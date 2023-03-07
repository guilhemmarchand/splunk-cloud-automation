from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "get_app_from_sc.py"
__author__ = "Guilhem Marchand"

import logging
import os, sys
import shutil
import requests
from requests.auth import HTTPBasicAuth
import json
import coloredlogs, logging
import base64
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import tarfile
import glob
import subprocess
import time

# load libs
sys.path.append('libs')
from tools import cd, gen_build_number, login_appinspect, submit_appinspect, verify_appinspect,\
    download_htmlreport_appinspect, download_jsonreport_appinspect, \
    splunkacs_create_ephemeral_token, splunk_acs_deploy_app

# context manager
class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--target_url', dest='target_url')
parser.add_argument('--username', dest='username')
parser.add_argument('--password', dest='password')
parser.add_argument('--app', dest='app')
parser.add_argument('--ksconf_bin', dest='ksconf_bin')
parser.add_argument('--promote_permissions', dest='promote_permissions', action='store_true')

parser.add_argument('--submitappinspect', dest='submitappinspect', action='store_true')
parser.add_argument('--userappinspect', dest='userappinspect')
parser.add_argument('--passappinspect', dest='passappinspect')

parser.add_argument('--useproxy', dest='useproxy', action='store_true')
parser.add_argument('--proxy_url', dest='proxy_url')
parser.add_argument('--proxy_port', dest='proxy_port')
parser.add_argument('--proxy_username', dest='proxy_username')
parser.add_argument('--proxy_password', dest='proxy_password')

parser.set_defaults(debug=False)
parser.set_defaults(promote_permissions=False)
parser.set_defaults(submitappinspect=False)
args = parser.parse_args()

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

#
# main arguments
#

if args.username:
    username = args.username
else:
    username = False

if args.password:
    password = args.password
else:
    password = False

if args.target_url:
    target_url = args.target_url
else:
    target_url = False

if args.app:
    app = args.app
else:
    app = False    

# if you need to set the path to ksconf
# Set ksconf_bin
if args.ksconf_bin:
    ksconf_bin = args.ksconf_bin
else:
    ksconf_bin = 'ksconf'

# Set promote permissions boolean
if args.promote_permissions:
    promote_permissions = True
else:
    promote_permissions = False

# Set appinspect_vetting
if args.submitappinspect:
    submitappinspect = True
else:
    submitappinspect = False

# Set appinspect_username
if args.userappinspect:
    userappinspect = args.userappinspect
else:
    userappinspect = False

# Set appinspect_password
if args.passappinspect:
    passappinspect = args.passappinspect
else:
    passappinspect = False

# Set useproxy boolean
if args.useproxy:
    useproxy = True
else:
    useproxy = False

# proxy_url settings
if args.proxy_url:
    proxy_url = args.proxy_url
else:
    proxy_url = False

if args.proxy_port:
    proxy_port = args.proxy_port
else:
    proxy_port = False

if args.proxy_username:
    proxy_username = args.proxy_username
else:
    proxy_username = False

if args.proxy_password:
    proxy_password = args.proxy_password
else:
    proxy_password = False

# if set
if useproxy:

    if not proxy_url or not proxy_port:
        logging.error("useproxy is enabled, but proxy_url or proxy_port were not provided")
        sys.exit(1)

    if not proxy_username or not proxy_password:
        proxy_dict= {
            "http" : proxy_url + ":" + proxy_port,
            "https" : proxy_url + ":" + proxy_port
            }
    else:
        proxy_dict= {
            "http" : "http://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port,
            "https" : "https://" + proxy_username + ":" + proxy_password + "@" + proxy_url + ":" + proxy_port
            }
else:
    proxy_dict = {}

# set logging
root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

# coloredlogs
coloredlogs.install(isatty=True, level='INFO', logger=logging.getLogger())

if debug:
    root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
else:
    root.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)

# check args
if not username or not password or not target_url:
    logging.error('arguments username, password, target_url, app must be set')
    sys.exit(1)

# set url
url = str(target_url) + '/services/toolbox/v1/export/export_app'

# set record
record = {
    'app': app,
}

# run request
logging.info("attempting to retrieve app=\"{}\" from target_url=\"{}\"".format(app, target_url))

try:
    response = requests.post(url, auth = HTTPBasicAuth(username, password),  proxies=proxy_dict, data=json.dumps(record),
                            verify=False)
    if response.status_code not in (200, 201, 204):
        logging.error(
            'request has failed!. url={}, data={}, HTTP Error={}, '
            'content={}'.format(url, record, response.status_code, response.text))
    else:

        # load the response in a dict
        response_json = json.loads(response.text)
        logging.debug("response=\"{}\"".format(json.dumps(response_json, indent=2)))           

except Exception as e:
    logging.error("failed to process the request, exception=\"{}\"".format(str(e)))

# load our items
base64_bytesdata = response_json.get('base64')
version_data = response_json.get('version')
filename_data = response_json.get('filename')

# get rid of pseudo bytes litteral, there should be a better way to do that
base64_bytesdata = base64_bytesdata.replace('b\'', '')
base64_bytesdata = base64_bytesdata[:-1]

# dedcode base64
base64_bytesdata = base64.b64decode(base64_bytesdata)

# Write the archive
try:
    with open(filename_data, 'wb') as f:
        f.write(base64_bytesdata)
        logging.info("successfully imported app=\"{}\", version=\"{}\" , tarfile=\"{}\"".format(app, version_data, filename_data))

except Exception as e:
    logging.error("failed to export app=\"{}\", version=\"{}\" , tarfile=\"{}\"".format(app, version_data, filename_data, str(e)))
    sys.exit(1)

# before extracting, purge the local directory, if any
if os.path.isdir(app):
    try:
        shutil.rmtree(app)
    except Exception as e:
        logging.error("failed to remove existing output directory=\"{}\", exception=\"{}\"".format(app, str(e)))
        sys.exit(1)

# extract the generated archive in the current directory

try:
    my_tar = tarfile.open(filename_data)
    my_tar.extractall('./') # specify which folder to extract to
    my_tar.close()
    logging.info("successfully extracted compressed archive=\"{}\" into directory=\"{}\"".format(filename_data, app))

except Exception as e:
    logging.error("failed to extract the compressed archive, exception=\"{}\"".format(str(e)))

#
# build package
#

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

        if result.stderr:
            logging.error("ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(app, "metadata", 'local.meta')))
            sys.exit(1)

    else:
        logging.info("purging metadata/local.metadata")
        try:
            os.remove(os.path.join(app, 'metadata', 'local.meta'))
        except Exception as e:
            logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(os.path.join(app, 'metadata', 'local.meta'), str(e)))

else:
    logging.info("purging metadata/local.metadata")
    try:
        os.remove(os.path.join(app, 'metadata', 'local.meta'))
    except Exception as e:
        logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(os.path.join(app, 'metadata', 'local.meta'), str(e)))

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

        if result.stderr:
            logging.error("ksconf has encountered a configuration issue with the configuration file=\"{}\", please fix the errors, failing the job on purpose.".format(os.path.join(appID, "local", conf_file)))
            sys.exit(1)

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
                    logging.error('failed to create target directory structure=\"{}\"'.format(os.path.join(app, 'default', 'data', 'ui', 'views')))

            if not os.path.isfile(os.path.join(app, 'default', 'data', 'ui', 'views', filename)):
                try:
                    shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'views', filename), os.path.join(app, "default", 'data', 'ui', 'views', filename))
                    logging.info("local view=\"{}\" has no default equivalent, promoting the view".format(filename))
                except Exception as e:
                    logging.error('failed to promote local view=\"{}\" with exception=\"{}\"'.format(filename, str(e)))
            else:
                try:
                    shutil.copyfile(os.path.join(app, "local", 'data', 'ui', 'views', filename), os.path.join(app, "default", 'data', 'ui', 'views', filename))
                    logging.info("local view=\"{}\" has a default equivalent, promoting the view".format(filename))
                except Exception as e:
                    logging.error('failed to promote local view=\"{}\" with exception=\"{}\"'.format(filename, str(e)))

    # re-package
    try:
        shutil.rmtree(os.path.join(app, 'local'))
        logging.info('successfully purged the local directory before packaging the app')
    except Exception as e:
        logging.error("failed to purge the local directory, exception=\"{}\"".format(str(e)))
        raise ValueError("failed to purge the local directory, exception=\"{}\"".format(str(e)))

    # purge the current achive
    try:
        os.remove(filename_data)
    except Exception as e:
        logging.error('failed to remove file=\"{}\" before packaging, exception=\"{}\"'.format(filename_data, str(e)))

    # package
    logging.info("Creating compress tgz filename=\"{}\"".format(filename_data))
    out = tarfile.open(filename_data, mode='w:gz')
    try:
        out.add(str(app))
    except Exception as e:
        logging.error("archive file=\"{}\" creation failed with exception=\"{}\"".format(filename_data, str(e)))
        raise ValueError("archive file=\"{}\" creation failed with exception=\"{}\"".format(filename_data), str(e))
    finally:
        logging.info('Achive tar file creation successful, archive_file=\"{}\"'.format(filename_data))
        out.close()

#
# Appinspect
#

if submitappinspect and userappinspect and passappinspect:

    # login to Appinspect
    appinspect_token = login_appinspect(userappinspect, passappinspect, proxy_dict)

    if appinspect_token:
        logging.info("Appsinspect: successfully logged in Appinspect API")

        appinspect_requestids = []

        # submit to Appinspect
        if os.path.isfile(filename_data):
            logging.info('Submitting to Appinspect API=\"{}\"'.format(filename_data))

            # set None
            appinspect_response = None

            # submit
            appinspect_response = submit_appinspect(appinspect_token, filename_data, proxy_dict)

            # append to the list
            if appinspect_response:
                appinspect_requestids.append(json.loads(appinspect_response)['request_id'])

        # Wait for all Appinspect vettings to be processed
        logging.debug("Appinspect request_ids=\"{}\"".format(appinspect_requestids))

        # sleep 2 seconds
        time.sleep(2)

        for request_id in appinspect_requestids:
            vetting_status = None
            vetting_response = verify_appinspect(appinspect_token, request_id, proxy_dict)

            vetting_status = json.loads(vetting_response)['status']

            attempts_counter = 0

            # Allow up to 150 attempts
            while vetting_status == 'PROCESSING' and attempts_counter<150:
                attempts_counter+=1
                # sleep 2 seconds
                time.sleep(2)
                vetting_response = verify_appinspect(appinspect_token, request_id, proxy_dict)
                vetting_status = json.loads(vetting_response)['status']

            if vetting_status == 'SUCCESS':
                logging.info("Appinspect request_id=\"{}\" was successfully processed".format(request_id))
            elif vetting_status == 'FAILURE':
                logging.error("Appinspect request_id=\"{}\" reported failed, vetting was not accepted!".format(request_id))
            else:
                logging.error("Appinspect request_id=\"{}\" status is unknown or not expected, review the report if available".format(request_id))

            # Download the HTML report                
            appinspect_report = download_htmlreport_appinspect(appinspect_token, request_id, proxy_dict)

            if appinspect_report:
                f = open(os.path.join("report_appinspect.html"), "w")
                f.write(appinspect_report)
                f.close()
                logging.info("Appinspect written to report=\"{}\"".format(os.path.join("report_appinspect.html")))          

            # Download the JSON report                
            appinspect_report = download_jsonreport_appinspect(appinspect_token, request_id, proxy_dict)

            if appinspect_report:
                f = open(os.path.join("report_appinspect.json"), "w")
                f.write(json.dumps(json.loads(appinspect_report), indent=4))
                f.close()
                logging.info("Appinspect written to report=\"{}\"".format(os.path.join("report_appinspect.json")))

            # Load the json dict
            appinspect_report_dict = json.loads(appinspect_report)

            count_failure = int(appinspect_report_dict['summary']['failure'])
            count_error = int(appinspect_report_dict['summary']['failure'])

            if count_failure == 0 and count_error == 0:
                logging.info("Appinspect request_id=\"{}\" was successfully vetted, summary=\"{}\"".format(request_id, json.dumps(appinspect_report_dict['summary'], indent=4)))
            else:
                logging.error("Appinspect request_id=\"{}\" could not be vetted, review the report for more information, summary=\"{}\"".format(request_id, json.dumps(appinspect_report_dict['summary'], indent=4)))
                raise ValueError("Appinspect request_id=\"{}\" could not be vetted, review the report for more information, summary=\"{}\"".format(request_id, json.dumps(appinspect_report_dict['summary'], indent=4)))
