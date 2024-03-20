#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"

import os
import random
import base64
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict


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


# gen a random build number, digit of 10 digits
def gen_build_number():
    return random.randint(0, 9999999999)


# login to Appinspect API and return the token
def login_appinspect(username, password, proxy_dict):

    login_url = "https://api.splunk.com/2.0/rest/login/splunk"

    try:
        response = requests.get(
            login_url,
            auth=HTTPBasicAuth(username, password),
            verify=True,
            proxies=proxy_dict,
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "Authentication to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(
                    login_url, response.status_code, response.text
                )
            )
        else:
            logging.debug(
                'Authentication to Splunk Appinspect API was successful, url="{}", token="{}"'.format(
                    login_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'Authentication to Splunk Appinspect API has failed, url="{}", exception="{}"'.format(
                login_url, e
            )
        )

    response_json = json.loads(response.text)
    appinspect_token = response_json["data"]["token"]

    return appinspect_token


# submit an app to Appinspect
def submit_appinspect(token, app, proxy_dict):

    appinspect_headers = {
        "Authorization": "bearer %s" % token,
    }

    files = {
        "app_package": open(app, "rb"),
        "included_tags": (None, "cloud"),
    }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/validate"

    # run

    session = requests.Session()

    try:
        response = session.post(
            validate_url,
            headers=appinspect_headers,
            files=files,
            verify=True,
            proxies=proxy_dict,
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "Submission to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(
                    validate_url, response.status_code, response.text
                )
            )
        else:
            logging.debug(
                'Submission to Splunk Appinspect API was successful, url="{}", response="{}"'.format(
                    validate_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'Submission to Splunk Appinspect API has failed, url="{}", exception="{}"'.format(
                validate_url, e
            )
        )

    return response.text


# verify an Appinspect vetting status
def verify_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
        "Authorization": "bearer %s" % token,
    }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/validate/status/" + str(
        request_id
    )

    # run
    try:
        response = requests.get(
            validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(
                    validate_url, response.status_code, response.text
                )
            )
        else:
            logging.debug(
                'Request verification to Splunk Appinspect API was successful, url="{}", response="{}"'.format(
                    validate_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'Request verification to Splunk Appinspect API has failed, url="{}", exception="{}"'.format(
                validate_url, e
            )
        )

    return response.text


# download an Appinspect vetting report
def download_htmlreport_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
        "Authorization": "bearer %s" % token,
        "Content-Type": "text/html",
    }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/report/" + str(request_id)

    # run
    try:
        response = requests.get(
            validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(
                    validate_url, response.status_code, response.text
                )
            )
        else:
            logging.debug(
                'Request verification to Splunk Appinspect API was successful, url="{}", response="{}"'.format(
                    validate_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'Request verification to Splunk Appinspect API has failed, url="{}", exception="{}"'.format(
                validate_url, e
            )
        )

    return response.text


# download an Appinspect vetting report
def download_jsonreport_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
        "Authorization": "bearer %s" % token,
        "Content-Type": "application/json",
    }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/report/" + str(request_id)

    # run
    try:
        response = requests.get(
            validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(
                    validate_url, response.status_code, response.text
                )
            )
        else:
            logging.debug(
                'Request verification to Splunk Appinspect API was successful, url="{}", response="{}"'.format(
                    validate_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'Request verification to Splunk Appinspect API has failed, url="{}", exception="{}"'.format(
                validate_url, e
            )
        )

    return response.text


# Create an ephemeral token for the authentication
def splunkacs_create_ephemeral_token(stack, username, password, audience, proxy_dict):

    headers = CaseInsensitiveDict()
    authorization = username + ":" + password
    b64_auth = base64.b64encode(authorization.encode()).decode()
    headers = {
        "Authorization": "Basic %s" % b64_auth,
        "Content-Type": "application/json",
    }

    data = {
        "user": username,
        "audience": audience,
        "type": "ephemeral",
    }

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/tokens" % stack

    # run
    session = requests.Session()

    try:
        response = session.post(
            submit_url,
            headers=headers,
            verify=True,
            data=json.dumps(data),
            proxies=proxy_dict,
        )
        if response.status_code not in (200, 201, 204):
            logging.error(
                "function=splunkacs_create_ephemeral_token, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(
                    submit_url, response.status_code, response.text
                )
            )
            raise Exception(
                'Splunk ACS call has failed, url="{}", response="{}"'.format(
                    submit_url, response.text
                )
            )
        else:
            logging.debug(
                'Splunk ACS call was successful, url="{}", response="{}"'.format(
                    submit_url, response.text
                )
            )

    except Exception as e:
        logging.error(
            'function=splunkacs_create_ephemeral_token, Splunk ACS call has failed, url="{}", exception="{}"'.format(
                submit_url, e
            )
        )
        raise Exception(
            'Splunk ACS call has failed, url="{}", exception="{}"'.format(submit_url, e)
        )

    return response.text


# Deploy to Splunk Cloud through ACS
def splunk_acs_deploy_app(tokenacs, tokenappinspect, app, stack, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["X-Splunk-Authorization"] = "%s" % tokenappinspect
    headers["Authorization"] = "Bearer %s" % tokenacs
    headers["ACS-Legal-Ack"] = "Y"

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/apps/victoria" % stack

    # run

    session = requests.Session()

    with open(app, "rb") as f:

        try:
            response = session.post(
                submit_url, headers=headers, data=f, verify=True, proxies=proxy_dict
            )
            if response.status_code not in (200, 201, 204):
                logging.error(
                    "Submission to Splunk ACS API has failed, url={},  HTTP Error={}, content={}".format(
                        submit_url, response.status_code, response.text
                    )
                )
            else:
                logging.debug(
                    'Submission to Splunk ACS API was successful, url="{}", response="{}"'.format(
                        submit_url, response.text
                    )
                )

        except Exception as e:
            logging.error(
                'Submission to Splunk ACS API has failed, url="{}", exception="{}"'.format(
                    submit_url, e
                )
            )

        return response.text


# Stream base64 encoded data to a file while decoding
def stream_base64_to_file(base64_data, output_path):
    with open(output_path, "wb") as f:
        f.write(base64.b64decode(base64_data))
