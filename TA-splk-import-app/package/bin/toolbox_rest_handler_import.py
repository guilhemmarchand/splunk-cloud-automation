from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "toolbox_rest_handler_import.py"
__author__ = "Guilhem Marchand"

import logging
import os, sys
import shutil
import splunk
import splunk.entity
import splunk.Intersplunk
import json
import logging
import requests
import tarfile
import base64
import time
import re
import subprocess
import glob
from urllib.parse import urlencode
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
logger = logging.getLogger(__name__)
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/toolbox_rest_api.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append libs
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-splk-import-app', 'lib'))

# import rest handler
import toolbox_rest_handler

# import toolbox libs
from libs_toolbox import cd

# import SDK client
import splunklib.client as client

class ToolboxImport_v1(toolbox_rest_handler.RESTHandler):


    def __init__(self, command_line, command_arg):
        super(ToolboxImport_v1, self).__init__(command_line, command_arg, logger)


    def get_test_endpoint(self, request_info, **kwargs):

        response = {
            'resource_endpoint': 'test_endpoint',
            'resource_response': 'Welcome. Good to see you.', 
        }

        return {
            "payload": response,
            'status': 200
        }
    
    def post_test_sc_connectivity(self, request_info, **kwargs):

        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args['payload']))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict['describe']
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
                account = resp_dict['account']
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:

            response = {
                'describe': 'This endpoint performs a connectivity check for a Splunk remote account, it requires a POST call with the following options:',
                "resource_desc": "Run connectivity checks for a Splunk remote account, this validates the configuration, network connectivity and authentication",
                'options': [{
                    'account': 'The account configuration identifier',
                }]
            }
            return {
                "payload": response,
                'status': 200
            }

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                            namespace='TA-splk-import-app', sessionKey=request_info.session_key, owner='-')
        splunkd_port = entity['mgmtHostPort']

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-splk-import-app",
            port=splunkd_port,
            token=request_info.session_key
        )

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_splk_import_app_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # global configuration
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
        proxy_username = None
        for stanza in confs:
            if stanza.name == "proxy":
                for key, value in stanza.content.items():
                    if key == "proxy_enabled":
                        proxy_enabled = value
                    if key == "proxy_port":
                        proxy_port = value
                    if key == "proxy_type":
                        proxy_type = value
                    if key == "proxy_url":
                        proxy_url = value
                    if key == "proxy_username":
                        proxy_username = value

        if proxy_enabled == "1":

            # get proxy password
            if proxy_username:
                proxy_password = None

                # get proxy password, if any
                credential_realm = '__REST_CREDENTIAL__#TA-splk-import-app#configs/conf-ta_splk_import_app_settings'
                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm) \
                        and credential.content.get('clear_password').find('proxy_password') > 0:
                        proxy_password = json.loads(credential.content.get('clear_password')).get('proxy_password')
                        break

                if proxy_type == 'http':
                    proxy_dict= {
                        "http" : "http://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : "https://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }
                else:
                    proxy_dict= {
                        "http" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }

            else:
                proxy_dict= {
                    "http" : proxy_url + ":" + proxy_port,
                    "https" : proxy_url + ":" + proxy_port
                    }

        # Splunk credentials store
        storage_passwords = service.storage_passwords
            
        # account configuration
        isfound = False
        splunk_url = None
        app_namespace = None

        conf_file = "ta_splk_import_app_account"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == str(account):
                isfound = True
                for key, value in stanza.content.items():
                    if key == "splunk_url":
                        splunk_url = value
                    if key == "app_namespace":
                        app_namespace = value

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if not isfound:

            response = {
                'action': 'failure',
                'response': 'The account=\"{}\" specified does not exist in this system.'.format(account), 
            }

            return {
                "payload": response,
                'status': 500
            }
        
        else:

            # enforce https
            if not splunk_url.startswith("https://"):
                splunk_url = "https://" + str(splunk_url)

            # remote trailing slash in the URL, if any
            if splunk_url.endswith('/'):
                splunk_url = splunk_url[:-1]

            # Splunk remote application namespace where searches are going to be executed, default to search if not defined
            if not app_namespace:
                app_namespace = "search"

            # else get the bearer token stored encrypted
            else:

                # realm
                credential_realm = '__REST_CREDENTIAL__#TA-splk-import-app#configs/conf-ta_splk_import_app_account'
                credential_name = str(credential_realm) + ":" + str(account) + "``"

                # extract as raw json
                bearer_token_rawvalue = ""

                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm) and credential.name.startswith(credential_name):
                        bearer_token_rawvalue = bearer_token_rawvalue + str(credential.content.clear_password)

                # extract a clean json object
                bearer_token_rawvalue_match = re.search('\{\"bearer_token\":\s*\"(.*)\"\}', bearer_token_rawvalue)
                if bearer_token_rawvalue_match:
                    bearer_token = bearer_token_rawvalue_match.group(1)
                else:
                    bearer_token = None

        if not bearer_token:

            response = {
                'action': 'failure',
                'message': 'the value of the bearer token for the Splunk remove account failed to retrieved',
                'account': account,
            }

            return {
                "payload": response,
                'status': 500
            }

        else:

            # Set the header
            header = 'Bearer ' + str(bearer_token)

            # use urlparse to extract relevant info from target
            parsed_url = urllib.parse.urlparse(splunk_url)

            # Establish the remote service
            logging.info("Establishing connection to host=\"{}\" on port=\"{}\" for Splunk remote account=\"{}\"".format(parsed_url.hostname, parsed_url.port, account))

            # set url
            url = str(splunk_url) + '/services/toolbox/v1/export/test_endpoint'

            try:

                response = requests.get(url, headers={'Authorization': header}, proxies=proxy_dict,
                                            verify=False, timeout=30)

                if response.status_code not in (200, 201, 204):

                    logging.error(
                        'request has failed!. url={}, HTTP Error={}, '
                        'content={}'.format(url, response.status_code, response.text))

                    response = {
                        'action': 'failure',
                        'message': 'request has failed!. url={}, HTTP Error={}, content={}'.format(url, response.status_code, response.text),
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': response.status_code
                    }

                else:

                    # load the response in a dict
                    response_json = json.loads(response.text)
                    logging.info("response=\"{}\"".format(json.dumps(response_json, indent=2)))

                    response = {
                        'action': 'success',
                        'response': response_json,
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 200
                    }

            except Exception as e:

                logging.error("failed to process the request, exception=\"{}\"".format(str(e)))

                response = {
                    'action': 'failure',
                    'message': 'failed to process the request',
                    'exception': str(e),
                    'account': account,
                    'url': splunk_url,
                }

                return {
                    "payload": response,
                    'status': 500
                }


    def post_import_app(self, request_info, **kwargs):

        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args['payload']))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict['describe']
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False

                # get account
                try:
                    account = resp_dict['account']
                except Exception as e:
                    response = {
                        'action': 'failure',
                        'response': 'The value for account is mandatory', 
                    }
                    return {
                        "payload": response,
                        'status': 500
                    }

                # get app
                try:
                    app = resp_dict['app']
                except Exception as e:
                    response = {
                        'action': 'failure',
                        'response': 'The value for app is mandatory', 
                    }
                    return {
                        "payload": response,
                        'status': 500
                    }
                
                # get run_build (optional)
                try:
                    run_build = resp_dict['run_build']
                except Exception as e:
                    run_build = True

                # promote permissions (optional)
                try:
                    promote_permissions = resp_dict['promote_permissions']
                except Exception as e:
                    promote_permissions = False

                # postexec_metadata (optional)
                try:
                    postexec_metadata = resp_dict['postexec_metadata']
                except Exception as e:
                    postexec_metadata = None

        else:
            # body is required
            describe = True

        # if describe is requested, show the usage
        if describe:

            response = {
                'describe': 'This endpoint performs a connectivity check for a Splunk remote account, it requires a POST call with the following options:',
                "resource_desc": "Run connectivity checks for a Splunk remote account, this validates the configuration, network connectivity and authentication",
                'options': [{
                    'account': 'The account configuration identifier',
                    'app': 'The application to be exported',
                    'run_build': 'Run the building package, which means merging local configuration using ksconf, valid options are: True | False',
                    'promote_permissions': 'If run_build=True, you can decide to promote or not the local permissions, default to False, valid options are: True | False',
                    'postexec_metadata': 'Metadata for the post execution script, this should be a JSON object',
                }]
            }
            return {
                "payload": response,
                'status': 200
            }

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                            namespace='TA-splk-import-app', sessionKey=request_info.session_key, owner='-')
        splunkd_port = entity['mgmtHostPort']

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-splk-import-app",
            port=splunkd_port,
            token=request_info.session_key
        )

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_splk_import_app_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # global configuration
        proxy_enabled = "0"
        proxy_url = None
        proxy_dict = None
        proxy_username = None
        for stanza in confs:
            if stanza.name == "proxy":
                for key, value in stanza.content.items():
                    if key == "proxy_enabled":
                        proxy_enabled = value
                    if key == "proxy_port":
                        proxy_port = value
                    if key == "proxy_type":
                        proxy_type = value
                    if key == "proxy_url":
                        proxy_url = value
                    if key == "proxy_username":
                        proxy_username = value

        if proxy_enabled == "1":

            # get proxy password
            if proxy_username:
                proxy_password = None

                # get proxy password, if any
                credential_realm = '__REST_CREDENTIAL__#TA-splk-import-app#configs/conf-ta_splk_import_app_settings'
                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm) \
                        and credential.content.get('clear_password').find('proxy_password') > 0:
                        proxy_password = json.loads(credential.content.get('clear_password')).get('proxy_password')
                        break

                if proxy_type == 'http':
                    proxy_dict= {
                        "http" : "http://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : "https://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }
                else:
                    proxy_dict= {
                        "http" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
                        "https" : str(proxy_type) + "://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
                        }

            else:
                proxy_dict= {
                    "http" : proxy_url + ":" + proxy_port,
                    "https" : proxy_url + ":" + proxy_port
                    }

        # get the target_path, ksconf
        target_path = None
        ksconf_bin = None
        postexec_bin = None
        for stanza in confs:
            if stanza.name == 'configuration':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "target_path":
                        target_path = stanzavalue
                    if stanzakey == "ksconf_bin":
                        ksconf_bin = stanzavalue
                    if stanzakey == "postexec_bin":
                        postexec_bin = stanzavalue

        # Set run_build boolean
        if run_build == 'True':
            run_build = True
        elif run_build == 'False':
            run_build = False
        else:
            run_build = True

        # Set promote_permissions boolean
        if promote_permissions == 'True':
            promote_permissions = True
        elif promote_permissions == 'False':
            promote_permissions = False
        else:
            promote_permissions = False

        # Splunk credentials store
        storage_passwords = service.storage_passwords
            
        # account configuration
        isfound = False
        splunk_url = None
        app_namespace = None

        conf_file = "ta_splk_import_app_account"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == str(account):
                isfound = True
                for key, value in stanza.content.items():
                    if key == "splunk_url":
                        splunk_url = value
                    if key == "app_namespace":
                        app_namespace = value

        # end of get configuration

        # Stop here if we cannot find the submitted account
        if not isfound:

            response = {
                'action': 'failure',
                'response': 'The account=\"{}\" specified does not exist in this system.'.format(account), 
            }

            return {
                "payload": response,
                'status': 500
            }
        
        else:

            # enforce https
            if not splunk_url.startswith("https://"):
                splunk_url = "https://" + str(splunk_url)

            # remote trailing slash in the URL, if any
            if splunk_url.endswith('/'):
                splunk_url = splunk_url[:-1]

            # Splunk remote application namespace where searches are going to be executed, default to search if not defined
            if not app_namespace:
                app_namespace = "search"

            # else get the bearer token stored encrypted
            else:

                # realm
                credential_realm = '__REST_CREDENTIAL__#TA-splk-import-app#configs/conf-ta_splk_import_app_account'
                credential_name = str(credential_realm) + ":" + str(account) + "``"

                # extract as raw json
                bearer_token_rawvalue = ""

                for credential in storage_passwords:
                    if credential.content.get('realm') == str(credential_realm) and credential.name.startswith(credential_name):
                        bearer_token_rawvalue = bearer_token_rawvalue + str(credential.content.clear_password)

                # extract a clean json object
                bearer_token_rawvalue_match = re.search('\{\"bearer_token\":\s*\"(.*)\"\}', bearer_token_rawvalue)
                if bearer_token_rawvalue_match:
                    bearer_token = bearer_token_rawvalue_match.group(1)
                else:
                    bearer_token = None

        if not bearer_token:

            response = {
                'action': 'failure',
                'message': 'the value of the bearer token for the Splunk remove account failed to retrieved',
                'account': account,
            }

            return {
                "payload": response,
                'status': 500
            }

        else:

            # Set the header
            header = 'Bearer ' + str(bearer_token)

            # use urlparse to extract relevant info from target
            parsed_url = urllib.parse.urlparse(splunk_url)

            # Establish the remote service
            logging.info("Establishing connection to host=\"{}\" on port=\"{}\" for Splunk remote account=\"{}\"".format(parsed_url.hostname, parsed_url.port, account))

            # set url
            url = str(splunk_url) + '/services/toolbox/v1/export/export_app'

            try:

                response = requests.post(url, headers={'Authorization': header}, data=json.dumps({'app': app}), proxies=proxy_dict,
                                            verify=False, timeout=30)

                if response.status_code not in (200, 201, 204):

                    logging.error(
                        'request has failed!. url={}, HTTP Error={}, '
                        'content={}'.format(url, response.status_code, response.text))

                    response = {
                        'action': 'failure',
                        'message': 'request has failed!. url={}, HTTP Error={}, content={}'.format(url, response.status_code, response.text),
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 500
                    }

                else:

                    # load the response in a dict
                    response_json = json.loads(response.text)

                    logging.info("request post was successful")
                    # don't log the whole giant response
                    logging.debug("response=\"{}\"".format(json.dumps(response_json, indent=2)))

            except Exception as e:

                logging.error("failed to process the request, exception=\"{}\"".format(str(e)))

                response = {
                    'action': 'failure',
                    'message': 'failed to process the request',
                    'exception': str(e),
                    'account': account,
                    'url': splunk_url,
                }

                return {
                    "payload": response,
                    'status': 500
                }

            #
            # Process
            #

            # load our items
            base64_bytesdata = response_json.get('base64')
            version_data = response_json.get('version')
            filename_data = response_json.get('filename')

            # get rid of pseudo bytes litteral, there should be a better way to do that
            base64_bytesdata = base64_bytesdata.replace('b\'', '')
            base64_bytesdata = base64_bytesdata[:-1]

            # decode base64
            base64_bytesdata = base64.b64decode(base64_bytesdata)

            # check target path
            if not os.path.isdir(target_path):
                logging.error("target_path=\"{}\" does not exist, invalid configuration, exception=\"{}\"".format(target_path, str(e)))

                response = {
                    'action': 'failure',
                    'message': 'target_path=\"{}\" does not exist, invalid configuration'.format(target_path),
                    'exception': str(e),
                    'account': account,
                    'url': splunk_url,
                }

                return {
                    "payload": response,
                    'status': 500
                }

            else:
                target_path = os.path.join(target_path, account)

                # create dir as needed
                if not os.path.isdir(target_path):
                    try:
                        os.mkdir(target_path)
                    except Exception as e:
                        response = {
                            'action': 'failure',
                            'message': 'target_path=\"{}\" could not be created, invalid configuration'.format(target_path),
                            'exception': str(e),
                            'account': account,
                            'url': splunk_url,
                        }

                        return {
                            "payload": response,
                            'status': 500
                        }                        

            with cd(target_path):

                # before generating, remove the file, if any
                if os.path.isfile(filename_data):
                    try:
                        os.remove(filename_data)
                    except Exception as e:
                        logging.error("failed to remove existing output archive=\"{}\", exception=\"{}\"".format(filename_data, str(e)))

                        response = {
                            'action': 'failure',
                            'message': 'failed to remove existing output archive=\"{}\"'.format(filename_data),
                            'exception': str(e),
                            'account': account,
                            'url': splunk_url,
                        }

                        return {
                            "payload": response,
                            'status': 500
                        }

                # Write the archive
                try:
                    with open(filename_data, 'wb') as f:
                        f.write(base64_bytesdata)
                        logging.info("successfully imported app=\"{}\", version=\"{}\" , tarfile=\"{}\"".format(app, version_data, filename_data))

                except Exception as e:
                    logging.error("failed to export app=\"{}\", version=\"{}\", tarfile=\"{}\", exception=\"{}\"".format(app, version_data, filename_data, str(e)))

                    response = {
                        'action': 'failure',
                        'message': 'failed to export app=\"{}\", version=\"{}\" , tarfile=\"{}\"'.format(app, version_data, filename_data),
                        'exception': str(e),
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 500
                    }

                # before extracting, purge the local directory, if any
                if os.path.isdir(app):
                    try:
                        shutil.rmtree(app)
                    except Exception as e:
                        logging.error("failed to remove existing output directory=\"{}\", exception=\"{}\"".format(app))

                        response = {
                            'action': 'failure',
                            'message': 'failed to remove existing output directory=\"{}\"'.format(app),
                            'exception': str(e),
                            'account': account,
                            'url': splunk_url,
                        }

                        return {
                            "payload": response,
                            'status': 500
                        }

                # extract the generated archive in the target directory
                try:
                    my_tar = tarfile.open(filename_data)
                    my_tar.extractall('./') # specify which folder to extract to
                    my_tar.close()
                    logging.info("successfully extracted compressed archive=\"{}\" into directory=\"{}\"".format(filename_data, app))

                except Exception as e:
                    logging.error("failed to extract the compressed archive, exception=\"{}\"".format(str(e)))

                    response = {
                        'action': 'failure',
                        'message': 'failed to extract the compressed archive',
                        'exception': str(e),
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 500
                    }

            #
            # merge and build
            #

            if run_build:

                with cd(target_path):

                    # manage local.metadata

                    if os.path.join(app, 'metadata', 'local.meta'):

                        if promote_permissions:

                        # process ksconf merge

                            # if we have both, we merge using ksconf
                            logging.info("running ksconf promote -b {} {}".format(os.path.join(app, "metadata", "local.meta"), os.path.join(app, "metadata")))

                            try:
                                result = subprocess.run([ksconf_bin, "promote", "-b", os.path.join(app, "metadata", "local.meta"), os.path.join(app, "metadata")], capture_output=True)
                                logging.info("ksconf results.stdout=\"{}\"".format(result.stdout))
                                logging.info("ksconf results.stderr=\"{}\"".format(result.stderr))

                            except Exception as e:
                                logging.error("error encountered while attempted to run ksconf, exception=\"{}\"".format(str(e)))

                                response = {
                                    'action': 'failure',
                                    'message': 'error encountered while attempted to run ksconf',
                                    'exception': str(e),
                                    'account': account,
                                    'url': splunk_url,
                                }

                                return {
                                    "payload": response,
                                    'status': 500
                                }

                            if result.stderr:
                                logging.error("ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(app, "metadata", 'local.meta')))

                                response = {
                                    'action': 'failure',
                                    'message': "ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(app, "metadata", 'local.meta')),
                                    'exception': result.stderr,
                                    'account': account,
                                    'url': splunk_url,
                                }

                                return {
                                    "payload": response,
                                    'status': 500
                                }

                        else:
                            logging.info("purging metadata/local.metadata")
                            try:
                                os.remove(os.path.join(app, 'metadata', 'local.meta'))
                            except Exception as e:

                                logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(os.path.join(app, 'metadata', 'local.meta'), str(e)))

                                response = {
                                    'action': 'failure',
                                    'message': 'failed to remove file=\"{}\" before packaging'.format(os.path.join(app, 'metadata', 'local.meta')),
                                    'exception': str(e),
                                    'account': account,
                                    'url': splunk_url,
                                }

                                return {
                                    "payload": response,
                                    'status': 500
                                }

                    else:
                        logging.info("purging metadata/local.metadata")
                        try:
                            os.remove(os.path.join(app, 'metadata', 'local.meta'))
                        except Exception as e:
                            logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(os.path.join(app, 'metadata', 'local.meta'), str(e)))

                            response = {
                                'action': 'failure',
                                'message': 'failed to remove file=\"{}\" before packaging'.format(os.path.join(app, 'metadata', 'local.meta')),
                                'exception': str(e),
                                'account': account,
                                'url': splunk_url,
                            }

                            return {
                                "payload": response,
                                'status': 500
                            }

                    #
                    # handle local
                    #

                    if not os.path.isdir(os.path.join(app, 'local')):
                        logging.info("there are no local objects to be promoted, the compressed file=\"{}\" is ready to be used".format(filename_data))

                    else:

                        #
                        # ksconf packaging - merge local objects and repackage
                        #

                        logging.info("discoverying local knowledge objects")

                        with cd(os.path.join(app, 'local')):
                            local_conf_files = []
                            for filename in glob.iglob(f'*.conf'):

                                # do not any allow any kind of config file
                                allowed_conf_files = [
                                    'props.conf',
                                    'transforms.conf',
                                    'eventtypes.conf',
                                    'tags.conf',
                                    'savedsearches.conf',
                                    'macros.conf',
                                    'collections.conf',
                                ]

                                if filename in allowed_conf_files:
                                    local_conf_files.append(filename)

                            logging.info("discovered local config files=\"{}\"".format(local_conf_files))

                        # process ksconf merge

                        for conf_file in local_conf_files:

                            # if we have both, we merge using ksconf
                            logging.info("running ksconf promote -b {} {}".format(os.path.join(app, "local", conf_file), os.path.join(app, "default", conf_file)))

                            try:
                                result = subprocess.run([ksconf_bin, "promote", "-b", os.path.join(app, "local", conf_file), os.path.join(app, "default", conf_file)], capture_output=True)
                                logging.info("ksconf results.stdout=\"{}\"".format(result.stdout))
                                logging.info("ksconf results.stderr=\"{}\"".format(result.stderr))

                            except Exception as e:
                                logging.error("error encountered while attempted to run ksconf, exception=\"{}\"".format(str(e)))

                                response = {
                                    'action': 'failure',
                                    'message': 'error encountered while attempted to run ksconf',
                                    'exception': str(e),
                                    'account': account,
                                    'url': splunk_url,
                                }

                                return {
                                    "payload": response,
                                    'status': 500
                                }

                            if result.stderr:
                                logging.error("ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(appID, "local", conf_file)))

                                response = {
                                    'action': 'failure',
                                    'message': "ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(app, "metadata", 'local.meta')),
                                    'exception': result.stderr,
                                    'account': account,
                                    'url': splunk_url,
                                }

                                return {
                                    "payload": response,
                                    'status': 500
                                }

                        #
                        # views packaging - merge local views
                        #

                        app_local_views = []

                        if os.path.isdir(os.path.join(app, 'local', 'data', 'ui', 'views')):
                            logging.info("discovering local views")

                            with cd(os.path.join(app, 'local', 'data', 'ui', 'views')):
                                for filename in glob.iglob(f'*.xml'):
                                    app_local_views.append(filename)

                            for local_view in app_local_views:
                                logging.info("processing promotion of local view=\"{}\"".format(local_view))

                                # if the view does not exist in default, then it is a simple copy (but we need create the structure first if needed)
                                # otherwise, this is an override

                                if not os.path.isdir(os.path.join(app, 'default', 'data', 'ui', 'views')):
                                    try:
                                        os.makedirs(os.path.join(app, 'default', 'data', 'ui', 'views'))
                                    except Exception as e:
                                        logging.error('failed to create target directory structure=\"{}\", exception=\"{}\"'.format(os.path.join(app, 'default', 'data', 'ui', 'views'), str(e)))

                                        response = {
                                            'action': 'failure',
                                            'message': 'failed to create target directory structure=\"{}\"'.format(os.path.join(app, 'default', 'data', 'ui', 'views')),
                                            'exception': str(e),
                                            'account': account,
                                            'url': splunk_url,
                                        }

                                        return {
                                            "payload": response,
                                            'status': 500
                                        }

                                if not os.path.isfile(os.path.join(app, 'default', 'data', 'ui', 'views', filename)):

                                    try:
                                        shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'views', filename), os.path.join(app, "default", 'data', 'ui', 'views', filename))
                                        logging.info("local view=\"{}\" has no default equivalent, promoting the view".format(filename))

                                    except Exception as e:
                                        logging.error('failed to promote local view=\"{}\" with exception=\"{}\"'.format(filename, str(e)))

                                        response = {
                                            'action': 'failure',
                                            'message': 'failed to promote local view=\"{}\"'.format(filename),
                                            'exception': str(e),
                                            'account': account,
                                            'url': splunk_url,
                                        }

                                        return {
                                            "payload": response,
                                            'status': 500
                                        }

                                else:

                                    try:
                                        shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'views', filename), os.path.join(app, "default", 'data', 'ui', 'views', filename))
                                        logging.info("local view=\"{}\" has a default equivalent, promoting the view".format(filename))

                                    except Exception as e:
                                        logging.error('failed to promote local view=\"{}\" with exception=\"{}\"'.format(filename, str(e)))

                                        response = {
                                            'action': 'failure',
                                            'message': 'failed to promote local view=\"{}\"'.format(filename),
                                            'exception': str(e),
                                            'account': account,
                                            'url': splunk_url,
                                        }

                                        return {
                                            "payload": response,
                                            'status': 500
                                        }

                        #
                        # nav packaging
                        #

                        if os.path.isfile(os.path.join(app, 'local', 'data', 'ui', 'nav', 'default.xml')):
                            logging.info("processing promotion of local nav default.xml file")

                            # if the view does not exist in default, then it is a simple copy (but we need create the structure first if needed)
                            # otherwise, this is an override

                            if not os.path.isdir(os.path.join(app, 'default', 'data', 'ui', 'nav')):
                                try:
                                    os.makedirs(os.path.join(app, 'default', 'data', 'ui', 'nav'))
                                except Exception as e:
                                    logging.error('failed to create target directory structure=\"{}\", exception=\"{}\"'.format(os.path.join(app, 'default', 'data', 'ui', 'nav'), str(e)))

                                    response = {
                                        'action': 'failure',
                                        'message': 'failed to create target directory structure=\"{}\"'.format(os.path.join(app, 'default', 'data', 'ui', 'nav')),
                                        'exception': str(e),
                                        'account': account,
                                        'url': splunk_url,
                                    }

                                    return {
                                        "payload": response,
                                        'status': 500
                                    }

                            if not os.path.isfile(os.path.join(app, 'default', 'data', 'ui', 'nav', 'default.xml')):

                                try:
                                    shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'nav', 'default.xml'), os.path.join(app, "default", 'data', 'ui', 'nav', 'default.xml'))
                                    logging.info("local nav=\"default.xml\" has no default, promoting the nav")

                                except Exception as e:
                                    logging.error('failed to promote local nav=\"default.xml\" with exception=\"{}\"'.format(str(e)))

                                    response = {
                                        'action': 'failure',
                                        'message': 'failed to promote local nav=\"default.xml\"',
                                        'exception': str(e),
                                        'account': account,
                                        'url': splunk_url,
                                    }

                                    return {
                                        "payload": response,
                                        'status': 500
                                    }

                            else:

                                try:
                                    shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'nav', 'default.xml'), os.path.join(app, "default", 'data', 'ui', 'nav', 'default.xml'))
                                    logging.info("local nav=\"default.xml\" has a default equivalent, promoting the nav")

                                except Exception as e:
                                    logging.error('failed to promote local nav=\"default.xml\" with exception=\"{}\"'.format(str(e)))

                                    response = {
                                        'action': 'failure',
                                        'message': 'failed to promote local nav=\"default.xml\"',
                                        'exception': str(e),
                                        'account': account,
                                        'url': splunk_url,
                                    }

                                    return {
                                        "payload": response,
                                        'status': 500
                                    }

                        # re-package
                        try:
                            shutil.rmtree(os.path.join(app, 'local'))
                            logging.info('successfully purged the local directory before packaging the app')

                        except Exception as e:
                            logging.error("failed to purge the local directory, exception=\"{}\"".format(str(e)))

                            response = {
                                'action': 'failure',
                                'message': "failed to purge the local directory",
                                'exception': str(e),
                                'account': account,
                                'url': splunk_url,
                            }

                            return {
                                "payload": response,
                                'status': 500
                            }

                        # purge the current achive
                        try:
                            os.remove(filename_data)

                        except Exception as e:
                            logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(filename_data, str(e)))

                            response = {
                                'action': 'failure',
                                'message': 'failed to remove file=\"{}\" before packaging'.format(filename_data),
                                'exception': str(e),
                                'account': account,
                                'url': splunk_url,
                            }

                            return {
                                "payload": response,
                                'status': 500
                            }

                        # package
                        logging.info("Creating compress tgz filename=\"{}\"".format(filename_data))
                        out = tarfile.open(filename_data, mode='w:gz')

                        try:
                            out.add(str(app))

                        except Exception as e:
                            logging.error("archive file=\"{}\" creation failed with exception=\"{}\"".format(filename_data, str(e)))

                            response = {
                                'action': 'failure',
                                'message': "archive file=\"{}\" creation failed".format(filename_data),
                                'exception': str(e),
                                'account': account,
                                'url': splunk_url,
                            }

                            return {
                                "payload": response,
                                'status': 500
                            }

                        finally:
                            logging.info('Achive tar file creation successful, archive_file=\"{}\"'.format(filename_data))
                            out.close()


            # prepare the response
            response = {
                'action': 'success',
                'response': response_json,
                'account': account,
                'url': splunk_url,
                'run_build': run_build,
                'promote_permissions': promote_permissions,
            }

            # postexec_bin
            if not postexec_bin or not os.path.isfile(postexec_bin) or not postexec_metadata:
                response['post_execution'] = False
            else:
                response['post_execution'] = True

            # post execution
            if postexec_bin and postexec_metadata:

                try:
                    logging.info("Attempting to execute post exec script=\"{}\"".format(postexec_bin))
                    result = subprocess.run([postexec_bin, "--file", os.path.join(target_path, filename_data), "--metadata", postexec_metadata], capture_output=True)
                    logging.info("post execution results.stdout=\"{}\"".format(result.stdout))
                    logging.info("post execution results.stderr=\"{}\"".format(result.stderr))

                except Exception as e:
                    logging.error("error encountered while attempted to run postexec_bin, exception=\"{}\"".format(str(e)))

                    response = {
                        'action': 'failure',
                        'message': 'error encountered while attempted to run post execution script',
                        'exception': str(e),
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 500
                    }

                if result.stderr:
                    logging.error("post execution script=\"{}\" has returned errors, stderr=\"{}\"".format(postexec_bin, result.stderr))

                    response = {
                        'action': 'failure',
                        'message': "post execution script=\"{}\" has returned errors".format(postexec_bin),
                        'exception': result.stderr,
                        'account': account,
                        'url': splunk_url,
                    }

                    return {
                        "payload": response,
                        'status': 500
                    }

                # Add to response                
                try:
                    # otherwise, add to the response
                    response['post_execution_stdout'] = str(result.stdout)
                    response['post_execution_stderr'] = str(result.stderr)
                    response['post_execution_metadata'] = postexec_metadata

                except Exception as e:
                    logging.error("failed to add post execution results to the response, exception=\"{}\"".format(str(e)))

            # unless in debug, do not show the base64, nor the original response
            if not loglevel == 'DEBUG':
                try:
                    del response_json['base64']
                    del response_json['result']
                except Exception as e:
                    logging.error("failed to remove base64 and result field from original response, exception=\"{}\"".format(str(e)))

            # render
            return {
                "payload": response,
                'status': 200
            }
