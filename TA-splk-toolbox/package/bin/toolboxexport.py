#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"

import os
import sys
import splunk
import splunk.entity
import requests
import json
import re
import time
import logging
from urllib.parse import urlencode
import urllib.parse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = logging.FileHandler(
    splunkhome + "/var/log/splunk/toolbox_export.log", "a"
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-splk-toolbox", "lib"))

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)
import splunklib.client as client


@Configuration(distributed=False)
class ToolboxExport(GeneratingCommand):

    account = Option(
        doc="""
        **Syntax:** **The account=****
        **Description:** Mandatory, the account""",
        require=True,
        default=None,
        validate=validators.Match("account", r".*"),
    )

    remote_account = Option(
        doc="""
        **Syntax:** **The remote_account=****
        **Description:** Mandatory for sc_test and live, the remote_account""",
        require=False,
        default=None,
        validate=validators.Match("account", r".*"),
    )

    mode = Option(
        doc="""
        **Syntax:** **The HTTP mode=****
        **Description:** Optional, valid options are test | live. test will verify the connectivity, live runs the actual REST call""",
        require=False,
        default="live",
        validate=validators.Match("mode", r"^(?:test|sc_test|live)$"),
    )

    app = Option(
        doc="""
        **Syntax:** **The app=****
        **Description:** Optional, the app value""",
        require=False,
        default=None,
        validate=validators.Match("app", r".*"),
    )

    run_build = Option(
        doc="""
        **Syntax:** **run_build=****
        **Description:** Optional, the run_build value""",
        require=False,
        default="True",
        validate=validators.Match("run_build", r"^(True|False)$"),
    )

    promote_permissions = Option(
        doc="""
        **Syntax:** **promote_permissions=****
        **Description:** Optional, the promote_permissions value""",
        require=False,
        default="False",
        validate=validators.Match("promote_permissions", r"^(True|False)$"),
    )

    postexec_metadata = Option(
        doc="""
        **Syntax:** **postexec_metadata=****
        **Description:** Optional, the postexec_metadata value""",
        require=False,
        default=None,
        validate=validators.Match("postexec_metadata", r".*"),
    )

    exclude_large_files = Option(
        doc="""
        **Syntax:** **exclude_large_files=****
        **Description:** Optional, True or False to exclude large files""",
        require=False,
        default="False",
        validate=validators.Match("exclude_large_files", r"^(True|False)$"),
    )

    large_file_size = Option(
        doc="""
        **Syntax:** **large_file_size=****
        **Description:** Optional, the size in MB from what a file is considered large""",
        require=False,
        default="100",
        validate=validators.Match("large_file_size", r"^\d+$"),
    )

    def generate(self, **kwargs):

        if self:

            # set loglevel
            loglevel = "INFO"
            conf_file = "ta_splk_toolbox_settings"
            confs = self.service.confs[str(conf_file)]
            for stanza in confs:
                if stanza.name == "logging":
                    for stanzakey, stanzavalue in stanza.content.items():
                        if stanzakey == "loglevel":
                            loglevel = stanzavalue
            logginglevel = logging.getLevelName(loglevel)
            log.setLevel(logginglevel)

            # Get the session key
            session_key = self._metadata.searchinfo.session_key

            # Get splunkd port
            entity = splunk.entity.getEntity(
                "/server",
                "settings",
                namespace="TA-splk-toolbox",
                sessionKey=session_key,
                owner="-",
            )
            splunkd_port = entity["mgmtHostPort"]

            # Get service
            service = client.connect(
                owner="nobody",
                app="TA-splk-toolbox",
                port=splunkd_port,
                token=session_key,
            )

            # Splunk credentials store
            storage_passwords = service.storage_passwords

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
                    credential_realm = "__REST_CREDENTIAL__#TA-splk-toolbox#configs/conf-ta_splk_toolbox_settings"
                    for credential in storage_passwords:
                        if (
                            credential.content.get("realm") == str(credential_realm)
                            and credential.content.get("clear_password").find(
                                "proxy_password"
                            )
                            > 0
                        ):
                            proxy_password = json.loads(
                                credential.content.get("clear_password")
                            ).get("proxy_password")
                            break

                    if proxy_type == "http":
                        proxy_dict = {
                            "http": "http://"
                            + proxy_username
                            + ":"
                            + proxy_password
                            + "@"
                            + proxy_url
                            + ":"
                            + proxy_port,
                            "https": "https://"
                            + proxy_username
                            + ":"
                            + proxy_password
                            + "@"
                            + proxy_url
                            + ":"
                            + proxy_port,
                        }
                    else:
                        proxy_dict = {
                            "http": str(proxy_type)
                            + "://"
                            + proxy_username
                            + ":"
                            + proxy_password
                            + "@"
                            + proxy_url
                            + ":"
                            + proxy_port,
                            "https": str(proxy_type)
                            + "://"
                            + proxy_username
                            + ":"
                            + proxy_password
                            + "@"
                            + proxy_url
                            + ":"
                            + proxy_port,
                        }

                else:
                    proxy_dict = {
                        "http": proxy_url + ":" + proxy_port,
                        "https": proxy_url + ":" + proxy_port,
                    }

            # account configuration
            isfound = False
            splunk_url = None
            app_namespace = None

            conf_file = "ta_splk_toolbox_account"
            confs = service.confs[str(conf_file)]
            for stanza in confs:
                if stanza.name == str(self.account):
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
                    "action": "failure",
                    "response": 'The account="{}" specified does not exist in this system.'.format(
                        self.account
                    ),
                }

                return {"payload": response, "status": 500}

            else:

                # enforce https
                if not splunk_url.startswith("https://"):
                    splunk_url = "https://" + str(splunk_url)

                # remote trailing slash in the URL, if any
                if splunk_url.endswith("/"):
                    splunk_url = splunk_url[:-1]

                # Splunk remote application namespace where searches are going to be executed, default to search if not defined
                if not app_namespace:
                    app_namespace = "search"

                # else get the bearer token stored encrypted
                else:

                    # realm
                    credential_realm = "__REST_CREDENTIAL__#TA-splk-toolbox#configs/conf-ta_splk_toolbox_account"
                    credential_name = (
                        str(credential_realm) + ":" + str(self.account) + "``"
                    )

                    # extract as raw json
                    bearer_token_rawvalue = ""

                    for credential in storage_passwords:
                        if credential.content.get("realm") == str(
                            credential_realm
                        ) and credential.name.startswith(credential_name):
                            bearer_token_rawvalue = bearer_token_rawvalue + str(
                                credential.content.clear_password
                            )

                    # extract a clean json object
                    bearer_token_rawvalue_match = re.search(
                        '\{"bearer_token":\s*"(.*)"\}', bearer_token_rawvalue
                    )
                    if bearer_token_rawvalue_match:
                        bearer_token = bearer_token_rawvalue_match.group(1)
                    else:
                        bearer_token = None

            if not bearer_token:

                response = {
                    "action": "failure",
                    "message": "the value of the bearer token for the Splunk remove account failed to retrieved",
                    "account": self.account,
                }

                data = {"_time": time.time(), "_raw": response}
                yield data

            else:

                # Set the header
                header = "Bearer " + str(bearer_token)

                # use urlparse to extract relevant info from target
                parsed_url = urllib.parse.urlparse(splunk_url)

                #
                # check args
                #

                if self.mode == "sc_test" or self.mode == "live":
                    if not self.remote_account or self.remote_account == "None":
                        raise ValueError(
                            "The value for remote_account must be provided"
                        )

                if self.mode == "live":
                    if not self.app or self.app == "None":
                        raise ValueError("The value for app must be provided")

                #
                # Proceed
                #

                if self.mode == "test":

                    #
                    # test endpoint
                    #

                    # Establish the remote service
                    logging.info(
                        'Establishing connection to host="{}" on port="{}" for Splunk remote account="{}"'.format(
                            parsed_url.hostname, parsed_url.port, self.account
                        )
                    )

                    # set url
                    url = str(splunk_url) + "/services/toolbox/v1/import/test_endpoint"

                    try:

                        response = requests.get(
                            url,
                            headers={"Authorization": header},
                            proxies=proxy_dict,
                            verify=False,
                            timeout=30,
                        )

                        if response.status_code not in (200, 201, 204):

                            logging.error(
                                "request has failed!. url={}, HTTP Error={}, "
                                "content={}".format(
                                    url, response.status_code, response.text
                                )
                            )

                            response = {
                                "action": "failure",
                                "message": "request has failed!. url={}, HTTP Error={}, content={}".format(
                                    url, response.status_code, response.text
                                ),
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                        else:

                            # load the response in a dict
                            response_json = json.loads(response.text)
                            logging.info(
                                'response="{}"'.format(
                                    json.dumps(response_json, indent=2)
                                )
                            )

                            response = {
                                "action": "success",
                                "response": response_json,
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                    except Exception as e:

                        logging.error(
                            'failed to process the request, exception="{}"'.format(
                                str(e)
                            )
                        )

                        response = {
                            "action": "failure",
                            "message": "failed to process the request",
                            "exception": str(e),
                            "account": self.account,
                            "url": splunk_url,
                        }

                        data = {"_time": time.time(), "_raw": response}
                        yield data

                #
                # This verifies the connectivity back to Splunk Cloud from the remote endpoint
                #

                elif self.mode == "sc_test":

                    #
                    # sc_test endpoint
                    #

                    # Establish the remote service
                    logging.info(
                        'Establishing connection to host="{}" on port="{}" for Splunk remote account="{}"'.format(
                            parsed_url.hostname, parsed_url.port, self.account
                        )
                    )

                    # set url
                    url = (
                        str(splunk_url)
                        + "/services/toolbox/v1/import/test_sc_connectivity"
                    )

                    try:

                        response = requests.post(
                            url,
                            headers={"Authorization": header},
                            data=json.dumps({"account": self.remote_account}),
                            proxies=proxy_dict,
                            verify=False,
                            timeout=30,
                        )

                        if response.status_code not in (200, 201, 204):

                            logging.error(
                                "request has failed!. url={}, HTTP Error={}, "
                                "content={}".format(
                                    url, response.status_code, response.text
                                )
                            )

                            response = {
                                "action": "failure",
                                "message": "request has failed!. url={}, HTTP Error={}, content={}".format(
                                    url, response.status_code, response.text
                                ),
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                        else:

                            # load the response in a dict
                            response_json = json.loads(response.text)
                            logging.info(
                                'response="{}"'.format(
                                    json.dumps(response_json, indent=2)
                                )
                            )

                            response = {
                                "action": "success",
                                "response": response_json,
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                    except Exception as e:

                        logging.error(
                            'failed to process the request, exception="{}"'.format(
                                str(e)
                            )
                        )

                        response = {
                            "action": "failure",
                            "message": "failed to process the request",
                            "exception": str(e),
                            "account": self.account,
                            "url": splunk_url,
                        }

                        data = {"_time": time.time(), "_raw": response}
                        yield data

                elif self.mode == "live":

                    #
                    # live endpoint
                    #

                    # Establish the remote service
                    logging.info(
                        'Establishing connection to host="{}" on port="{}" for Splunk remote account="{}"'.format(
                            parsed_url.hostname, parsed_url.port, self.account
                        )
                    )

                    # set url
                    url = str(splunk_url) + "/services/toolbox/v1/import/import_app"
                    post_data = {
                        "account": self.remote_account,
                        "app": self.app,
                        "run_build": self.run_build,
                        "promote_permissions": self.promote_permissions,
                        "exclude_large_files": self.exclude_large_files,
                        "large_file_size": self.large_file_size,
                    }

                    # Add metadata
                    if self.postexec_metadata and self.postexec_metadata != "None":
                        post_data["postexec_metadata"] = self.postexec_metadata

                    try:

                        response = requests.post(
                            url,
                            headers={"Authorization": header},
                            data=json.dumps(post_data),
                            proxies=proxy_dict,
                            verify=False,
                            timeout=30,
                        )

                        if response.status_code not in (200, 201, 204):

                            logging.error(
                                "request has failed!. url={}, HTTP Error={}, "
                                "content={}".format(
                                    url, response.status_code, response.text
                                )
                            )

                            response = {
                                "action": "failure",
                                "message": "request has failed!. url={}, HTTP Error={}, content={}".format(
                                    url, response.status_code, response.text
                                ),
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                        else:

                            # load the response in a dict
                            response_json = json.loads(response.text)
                            logging.info(
                                'response="{}"'.format(
                                    json.dumps(response_json, indent=2)
                                )
                            )

                            response = {
                                "action": "success",
                                "response": response_json,
                                "account": self.account,
                                "url": splunk_url,
                            }

                            # yield
                            data = {"_time": time.time(), "_raw": response}
                            yield data

                    except Exception as e:

                        logging.error(
                            'failed to process the request, exception="{}"'.format(
                                str(e)
                            )
                        )

                        response = {
                            "action": "failure",
                            "message": "failed to process the request",
                            "exception": str(e),
                            "account": self.account,
                            "url": splunk_url,
                        }

                        data = {"_time": time.time(), "_raw": response}
                        yield data


dispatch(ToolboxExport, sys.argv, sys.stdin, sys.stdout, __name__)
