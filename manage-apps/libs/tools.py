#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__maintainer__ = "TBD"
__status__ = "PRODUCTION"

import os
import random
import fnmatch
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
        response = requests.get(login_url, auth = HTTPBasicAuth(username, password), verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("Authentication to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(login_url, response.status_code, response.text))
        else:
            logging.debug("Authentication to Splunk Appinspect API was successful, url=\"{}\", token=\"{}\"".format(login_url, response.text))

    except Exception as e:
        logging.error("Authentication to Splunk Appinspect API has failed, url=\"{}\", exception=\"{}\"".format(login_url, e))

    response_json = json.loads(response.text)
    appinspect_token = response_json['data']['token']

    return appinspect_token


# submit an app to Appinspect
def submit_appinspect(token, app, proxy_dict):

    appinspect_headers = {
            'Authorization': 'bearer %s' % token,
        }

    files = {
        'app_package': open(app, 'rb'),
        'included_tags': (None, 'cloud'),
    }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/validate"

    # run

    session = requests.Session()

    try:
        response = session.post(validate_url, headers=appinspect_headers, files=files, verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("Submission to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(validate_url, response.status_code, response.text))
        else:
            logging.debug("Submission to Splunk Appinspect API was successful, url=\"{}\", response=\"{}\"".format(validate_url, response.text))

    except Exception as e:
        logging.error("Submission to Splunk Appinspect API has failed, url=\"{}\", exception=\"{}\"".format(validate_url, e))

    return response.text


# verify an Appinspect vetting status
def verify_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
            'Authorization': 'bearer %s' % token,
        }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/validate/status/" + str(request_id)

    # run
    try:
        response = requests.get(validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(validate_url, response.status_code, response.text))
        else:
            logging.debug("Request verification to Splunk Appinspect API was successful, url=\"{}\", response=\"{}\"".format(validate_url, response.text))

    except Exception as e:
        logging.error("Request verification to Splunk Appinspect API has failed, url=\"{}\", exception=\"{}\"".format(validate_url, e))

    return response.text


# download an Appinspect vetting report
def download_htmlreport_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
            'Authorization': 'bearer %s' % token,
            'Content-Type': 'text/html',
        }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/report/" + str(request_id)

    # run
    try:
        response = requests.get(validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(validate_url, response.status_code, response.text))
        else:
            logging.debug("Request verification to Splunk Appinspect API was successful, url=\"{}\", response=\"{}\"".format(validate_url, response.text))

    except Exception as e:
        logging.error("Request verification to Splunk Appinspect API has failed, url=\"{}\", exception=\"{}\"".format(validate_url, e))

    return response.text


# download an Appinspect vetting report
def download_jsonreport_appinspect(token, request_id, proxy_dict):

    appinspect_headers = {
            'Authorization': 'bearer %s' % token,
            'Content-Type': 'application/json',
        }

    # submit
    validate_url = "https://appinspect.splunk.com/v1/app/report/" + str(request_id)

    # run
    try:
        response = requests.get(validate_url, headers=appinspect_headers, verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("Request verification to Splunk Appinspect API has failed, url={},  HTTP Error={}, content={}".format(validate_url, response.status_code, response.text))
        else:
            logging.debug("Request verification to Splunk Appinspect API was successful, url=\"{}\", response=\"{}\"".format(validate_url, response.text))

    except Exception as e:
        logging.error("Request verification to Splunk Appinspect API has failed, url=\"{}\", exception=\"{}\"".format(validate_url, e))

    return response.text

