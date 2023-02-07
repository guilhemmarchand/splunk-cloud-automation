#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Splunk"
__version__ = "0.1.0"
__maintainer__ = "Splunk"
__status__ = "PRODUCTION"

import base64
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict

# Create an ephemeral token for the authentication
def splunkacs_create_ephemeral_token(stack, username, password, audience, proxy_dict):

    headers = CaseInsensitiveDict()
    authorization = username + ':' + password
    b64_auth = base64.b64encode(authorization.encode()).decode()
    headers = {
        'Authorization': 'Basic %s' % b64_auth,
        'Content-Type': 'application/json',
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
        response = session.post(submit_url, headers=headers, verify=True, data=json.dumps(data), proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("function=splunkacs_create_ephemeral_token, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url=\"{}\", response=\"{}\"".format(submit_url, response.text))
        else:
            logging.debug("Splunk ACS call was successful, url=\"{}\", response=\"{}\"".format(submit_url, response.text))

    except Exception as e:
        logging.error("function=splunkacs_create_ephemeral_token, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))

    return response.text


# Get indexes through ACS
def splunkacs_getidx(stack, tokenacs, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes?count=0" % stack

    # run

    session = requests.Session()

    try:
        response = session.get(submit_url, headers=headers, verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 204):
            logging.error("function=splunkacs_getidx, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url=\"{}\", response=\"{}\"".format(submit_url, response.text))
        else:
            logging.debug("Splunk ACS call was successful, url=\"{}\", response=\"{}\"".format(submit_url, response.text))

    except Exception as e:
        logging.error("function=splunkacs_getidx, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))

    return response.text


# Get a specific index through ACS, returns True if exists, False otherwise
def splunkacs_check_index(stack, tokenacs, indexname, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes" % stack
    submit_url = submit_url + "/" + str(indexname)

    # run

    session = requests.Session()

    try:
        response = session.get(submit_url, headers=headers, verify=True, proxies=proxy_dict)

        if response.status_code not in (200, 201, 204):
            logging.debug("function=splunkacs_check_index, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            return False

        else:
            logging.debug("function=splunkacs_check_index, url=\"{}\", response=\"{}\"".format(submit_url, response.text))
            return True

    except Exception as e:
        logging.error("function=splunkacs_check_index, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))


# Get a specific index through ACS
def splunkacs_get_target_index(stack, tokenacs, indexname, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes" % stack
    submit_url = submit_url + "/" + str(indexname)

    # run

    session = requests.Session()

    try:
        response = session.get(submit_url, headers=headers, verify=True, proxies=proxy_dict)

        if response.status_code not in (200, 201, 204):
            logging.error("function=splunkacs_get_target_index, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, response.text))

        else:
            logging.debug("function=splunkacs_get_target_index, Splunk ACS call was successful, url=\"{}\", response=\"{}\"".format(submit_url, response.text))

    except Exception as e:
        logging.error("function=splunkacs_get_target_index, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))

    return response.text   

# Create an index through ACS
def splunkacs_postidx(stack, tokenacs, definition, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs
    headers["Content-Type"] = "application/json"

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes" % stack

    # run

    session = requests.Session()

    try:
        response = session.post(submit_url, headers=headers, data=json.dumps(definition), verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 202, 204):
            logging.error("function=splunkacs_postidx, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
        else:
            logging.info("function=splunkacs_postidx, Splunk ACS call was successful, index deployment has been requested, response=\"{}\"".format(json.dumps(response.text, indent=2)))
            return response.text

    except Exception as e:
        logging.error("function=splunkacs_postidx, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))

# Create an index through ACS
def splunkacs_postidx(stack, tokenacs, definition, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs
    headers["Content-Type"] = "application/json"

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes" % stack

    # run

    session = requests.Session()

    try:
        response = session.post(submit_url, headers=headers, data=json.dumps(definition), verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 202, 204):
            logging.error("function=splunkacs_postidx, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
        else:
            logging.info("function=splunkacs_postidx, Splunk ACS call was successful, index deployment has been requested, response=\"{}\"".format(json.dumps(response.text, indent=2)))
            return response.text

    except Exception as e:
        logging.error("function=splunkacs_postidx, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))

# Update an index through ACS
def splunkacs_updateidx(stack, tokenacs, indexname, definition, proxy_dict):

    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Bearer %s" % tokenacs
    headers["Content-Type"] = "application/json"

    # submit
    submit_url = "https://admin.splunk.com/%s/adminconfig/v2/indexes" % stack
    submit_url = submit_url + "/" + str(indexname)

    # run

    session = requests.Session()

    try:
        response = session.patch(submit_url, headers=headers, data=json.dumps(definition), verify=True, proxies=proxy_dict)
        if response.status_code not in (200, 201, 202, 204):
            logging.error("function=splunkacs_updateidx, Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
            raise Exception("Splunk ACS call has failed, url={},  HTTP Error={}, content={}".format(submit_url, response.status_code, response.text))
        else:
            logging.info("function=splunkacs_updateidx, Splunk ACS call was successful, index deployment has been requested, response=\"{}\"".format(json.dumps(response.text, indent=2)))
            return response.text

    except Exception as e:
        logging.error("function=splunkacs_updateidx, Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
        raise Exception("Splunk ACS call has failed, url=\"{}\", exception=\"{}\"".format(submit_url, e))
