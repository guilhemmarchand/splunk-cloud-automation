#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__maintainer__ = "TBD"
__status__ = "PRODUCTION"

import os
import random
import base64
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlencode
import xml.etree.ElementTree as ET


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


def login_splunkbase(username, password, proxy_dict):
    """
    Log in to Splunkbase and return the ID value from the XML response.

    Args:
        username (str): The username for Splunkbase.
        password (str): The password for Splunkbase.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The ID value from the XML response.

    Raises:
        Exception: If the login request to Splunkbase fails.
    """
    url = "https://splunkbase.splunk.com/api/account:login"
    data = {"username": username, "password": password}

    try:
        response = requests.post(url, data=data, proxies=proxy_dict)

        if response.status_code == 200:
            xml_response = response.text
            root = ET.fromstring(xml_response)

            id_element = root.find("{http://www.w3.org/2005/Atom}id")

            if id_element is not None:
                return id_element.text
            else:
                logging.error(
                    "Splunkbase login failed, ID element not found in the XML response"
                )
                raise Exception(
                    "Splunkbase login failed, ID element not found in the XML response"
                )
        else:
            logging.error(
                f"Splunkbase login request failed with status code {response.status_code}"
            )
            raise Exception(
                f"Splunkbase login request failed with status code {response.status_code}"
            )

    except Exception as e:
        logging.error(f"Splunkbase login failed: exception={e}")
        raise Exception("Splunkbase login failed") from e


# login to Appinspect API and return the token
def login_appinspect(username, password, proxy_dict):
    """
    Log in to the AppInspect API and return the token.

    Args:
        username (str): The username for the API.
        password (str): The password for the API.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The AppInspect API token.

    Raises:
        Exception: If the authentication to the AppInspect API fails.
    """
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
                f"Authentication to Splunk AppInspect API failed: "
                f"url={login_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception("Authentication to Splunk AppInspect API failed")

        response_json = response.json()
        appinspect_token = response_json["data"]["token"]
        logging.debug(
            f"Authentication to Splunk AppInspect API successful: "
            f"url={login_url}, token={appinspect_token}"
        )
        return appinspect_token

    except Exception as e:
        logging.error(
            f"Authentication to Splunk AppInspect API failed: "
            f"url={login_url}, exception={e}"
        )
        raise Exception("Authentication to Splunk AppInspect API failed")


def submit_appinspect(token, app, proxy_dict):
    """
    Submit an app to Splunk AppInspect for validation.

    Args:
        token (str): The authentication token for AppInspect.
        app (str): The path to the app package file.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text from the AppInspect API.

    Raises:
        Exception: If the submission to the AppInspect API fails.
    """
    appinspect_headers = {
        "Authorization": f"Bearer {token}",
    }

    files = {
        "app_package": open(app, "rb"),
        "included_tags": (None, "cloud"),
    }

    validate_url = "https://appinspect.splunk.com/v1/app/validate"
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
                f"Submission to Splunk AppInspect API failed, "
                f"url={validate_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception("Submission to Splunk AppInspect API failed")
        else:
            logging.debug(
                f"Submission to Splunk AppInspect API was successful, "
                f"url={validate_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Submission to Splunk AppInspect API failed, "
            f"url={validate_url}, "
            f"exception={e}"
        )
        raise Exception("Submission to Splunk AppInspect API failed") from e


def verify_appinspect(token, request_id, proxy_dict):
    """
    Verify the vetting status of an app in Splunk AppInspect.

    Args:
        token (str): The authentication token for AppInspect.
        request_id (str): The request ID for the submitted app.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text from the AppInspect API.

    Raises:
        Exception: If the verification request to the AppInspect API fails.
    """
    appinspect_headers = {
        "Authorization": f"Bearer {token}",
    }

    validate_url = f"https://appinspect.splunk.com/v1/app/validate/status/{request_id}"

    try:
        response = requests.get(
            validate_url,
            headers=appinspect_headers,
            verify=True,
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"Request verification to Splunk AppInspect API failed, "
                f"url={validate_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception("Request verification to Splunk AppInspect API failed")
        else:
            logging.debug(
                f"Request verification to Splunk AppInspect API was successful, "
                f"url={validate_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Request verification to Splunk AppInspect API failed, "
            f"url={validate_url}, "
            f"exception={e}"
        )
        raise Exception("Request verification to Splunk AppInspect API failed") from e


def download_htmlreport_appinspect(token, request_id, proxy_dict):
    """
    Download the HTML report of an app from Splunk AppInspect.

    Args:
        token (str): The authentication token for AppInspect.
        request_id (str): The request ID for the submitted app.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the HTML report.

    Raises:
        Exception: If the request to download the report fails.
    """
    appinspect_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "text/html",
    }

    validate_url = f"https://appinspect.splunk.com/v1/app/report/{request_id}"

    try:
        response = requests.get(
            validate_url,
            headers=appinspect_headers,
            verify=True,
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"Request to download AppInspect HTML report failed, "
                f"url={validate_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception("Request to download AppInspect HTML report failed")
        else:
            logging.debug(
                f"Request to download AppInspect HTML report was successful, "
                f"url={validate_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Request to download AppInspect HTML report failed, "
            f"url={validate_url}, "
            f"exception={e}"
        )
        raise Exception("Request to download AppInspect HTML report failed") from e


def download_jsonreport_appinspect(token, request_id, proxy_dict):
    """
    Download the JSON report of an app from Splunk AppInspect.

    Args:
        token (str): The authentication token for AppInspect.
        request_id (str): The request ID for the submitted app.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the JSON report.

    Raises:
        Exception: If the request to download the report fails.
    """
    appinspect_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    validate_url = f"https://appinspect.splunk.com/v1/app/report/{request_id}"

    try:
        response = requests.get(
            validate_url,
            headers=appinspect_headers,
            verify=True,
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"Request to download AppInspect JSON report failed, "
                f"url={validate_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception("Request to download AppInspect JSON report failed")
        else:
            logging.debug(
                f"Request to download AppInspect JSON report was successful, "
                f"url={validate_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Request to download AppInspect JSON report failed, "
            f"url={validate_url}, "
            f"exception={e}"
        )
        raise Exception("Request to download AppInspect JSON report failed") from e


def splunkacs_create_ephemeral_token(stack, username, password, audience, proxy_dict):
    """
    Create an ephemeral token for the authentication.

    Args:
        stack (str): The stack to use for the request.
        username (str): The username for the authentication.
        password (str): The password for the authentication.
        audience (str): The audience for the authentication.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the token.

    Raises:
        Exception: If the request to create the token fails.
    """
    b64_auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {b64_auth}",
        "Content-Type": "application/json",
    }

    data = {
        "user": username,
        "audience": audience,
        "type": "ephemeral",
    }

    submit_url = f"https://admin.splunk.com/{stack}/adminconfig/v2/tokens"

    try:
        response = requests.post(
            submit_url,
            headers=headers,
            verify=True,
            data=json.dumps(data),
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"function=splunkacs_create_ephemeral_token, "
                f"Splunk ACS call failed, "
                f"url={submit_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception(
                f"Splunk ACS call failed, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
        else:
            logging.debug(
                f"Splunk ACS call successful, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"function=splunkacs_create_ephemeral_token, "
            f"Splunk ACS call failed, "
            f"url={submit_url}, "
            f"exception={e}"
        )
        raise Exception(
            f"Splunk ACS call failed, " f"url={submit_url}, " f"exception={e}"
        ) from e


def splunk_acs_deploy_app(tokenacs, tokenappinspect, app, stack, proxy_dict):
    """
    Deploy to Splunk Cloud through ACS.

    Args:
        tokenacs (str): The ACS token for the authentication.
        tokenappinspect (str): The AppInspect token for the authentication.
        app (str): The path to the app file to deploy.
        stack (str): The stack to use for the request.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the deployment result.

    Raises:
        Exception: If the request to deploy the app fails.
    """
    headers = {
        "X-Splunk-Authorization": tokenappinspect,
        "Authorization": f"Bearer {tokenacs}",
        "ACS-Legal-Ack": "Y",
    }

    submit_url = f"https://admin.splunk.com/{stack}/adminconfig/v2/apps/victoria"

    with open(app, "rb") as f:
        try:
            response = requests.post(
                submit_url,
                headers=headers,
                data=f,
                verify=True,
                proxies=proxy_dict,
            )

            if response.status_code not in (200, 201, 204):
                logging.error(
                    f"Submission to Splunk ACS API failed, "
                    f"url={submit_url}, "
                    f"HTTP Error={response.status_code}, "
                    f"content={response.text}"
                )
                raise Exception(
                    f"Submission to Splunk ACS API failed, "
                    f"url={submit_url}, "
                    f"response={response.text}"
                )
            else:
                logging.debug(
                    f"Submission to Splunk ACS API successful, "
                    f"url={submit_url}, "
                    f"response={response.text}"
                )
                return response.text

        except Exception as e:
            logging.error(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"exception={e}"
            )
            raise Exception(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"exception={e}"
            ) from e


def splunk_acs_deploy_splunkbase_app(
    tokenacs, tokensplunkbase, appId, version, licenseAck, stack, proxy_dict
):
    """
    Deploy to Splunk Cloud through ACS for a SplunkBase app.

    Args:
        tokenacs (str): The ACS token for the authentication.
        tokensplunkbase (str): The SplunkBase token for the authentication.
        appId (str): The ID of the SplunkBase app to deploy.
        version (str): The version of the app to deploy.
        licenseAck (str): The license acknowledgement flag.
        stack (str): The stack to use for the request.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the deployment result.

    Raises:
        Exception: If the request to deploy the app fails.
    """
    headers = {
        "X-Splunkbase-Authorization": tokensplunkbase,
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Bearer {tokenacs}",
        "ACS-Legal-Ack": "Y",
        "ACS-Licensing-Ack": licenseAck,
    }

    submit_url = (
        f"https://admin.splunk.com/{stack}/adminconfig/v2/apps/victoria?splunkbase=true"
    )

    try:
        response = requests.post(
            submit_url,
            headers=headers,
            data={"splunkbaseID": appId, "version": version},
            verify=True,
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 202, 204):
            logging.error(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
        else:
            logging.debug(
                f"Submission to Splunk ACS API successful, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Submission to Splunk ACS API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        )
        raise Exception(
            f"Submission to Splunk ACS API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        ) from e


def splunk_acs_update_splunkbase_app(
    tokenacs, tokensplunkbase, appName, version, licenseAck, stack, proxy_dict
):
    """
    Update a SplunkBase app deployed to Splunk Cloud through ACS.

    Args:
        tokenacs (str): The ACS token for the authentication.
        tokensplunkbase (str): The SplunkBase token for the authentication.
        appName (str): The name of the SplunkBase app to update.
        version (str): The version of the app to update.
        licenseAck (str): The license acknowledgement flag.
        stack (str): The stack to use for the request.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        str: The response text containing the update result.

    Raises:
        Exception: If the request to update the app fails.
    """
    headers = {
        "X-Splunkbase-Authorization": tokensplunkbase,
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Bearer {tokenacs}",
        "ACS-Legal-Ack": "Y",
        "ACS-Licensing-Ack": licenseAck,
    }

    submit_url = f"https://admin.splunk.com/{stack}/adminconfig/v2/apps/victoria/{appName}?splunkbase=true"

    try:
        response = requests.patch(
            submit_url,
            headers=headers,
            data={"version": version},
            verify=True,
            proxies=proxy_dict,
        )

        if response.status_code not in (200, 201, 202, 204):
            logging.error(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception(
                f"Submission to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
        else:
            logging.debug(
                f"Submission to Splunk ACS API successful, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
            return response.text

    except Exception as e:
        logging.error(
            f"Submission to Splunk ACS API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        )
        raise Exception(
            f"Submission to Splunk ACS API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        ) from e


def get_apps_splunk_rest(auth_rest_mode, token, stack, proxy_dict):
    """
    Retrieve the list of installed applications and their full details from Splunk API.
    Splunk ACS currently lacks the build number.

    Args:
        auth_rest_mode (str): The authentication mode ('bearer_token' or 'splunk_token').
        token (str): The authentication token.
        stack (str): The stack to use for the request.
        proxy_dict (dict): Proxy settings to use for the request.

    Returns:
        list: A list of installed applications and their full details.

    Raises:
        Exception: If the request to Splunk API fails.
    """
    if auth_rest_mode == "bearer_token":
        splunk_headers = {"Authorization": f"Bearer {token}"}
    elif auth_rest_mode == "splunk_token":
        splunk_headers = {"Authorization": f"Splunk {token}"}

    validate_url = f"https://{stack}.splunkcloud.com:8089/services/apps/local?output_mode=json&count=0"

    try:
        response = requests.get(
            validate_url, headers=splunk_headers, verify=False, proxies=proxy_dict
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"Request verification to Splunk API failed, "
                f"url={validate_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception(
                f"Request verification to Splunk API failed, "
                f"url={validate_url}, "
                f"response={response.text}"
            )
        else:
            logging.debug(
                f"Request verification to Splunk API successful, "
                f"url={validate_url}, "
                f"response={response.text}"
            )

        return json.loads(response.text).get("entry")

    except Exception as e:
        logging.error(
            f"Request verification to Splunk API failed, "
            f"url={validate_url}, "
            f"exception={e}"
        )
        raise Exception(
            f"Request verification to Splunk API failed, "
            f"url={validate_url}, "
            f"exception={e}"
        ) from e


def get_apps_splunk_acs(tokenacs, stack, proxy_dict):
    """
    Retrieve the list of installed applications and their full details from Splunk ACS API.
    Splunk ACS currently lacks the build number.

    Returns:
        list: A list of installed applications and their full details.

    Raises:
        Exception: If the request to Splunk API fails.
    """
    headers = {
        "Authorization": f"Bearer {tokenacs}",
    }

    submit_url = f"https://admin.splunk.com/{stack}/adminconfig/v2/apps/victoria?splunkbase=true&count=0"

    try:
        response = requests.get(
            submit_url, headers=headers, verify=False, proxies=proxy_dict
        )

        if response.status_code not in (200, 201, 204):
            logging.error(
                f"Request verification to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"HTTP Error={response.status_code}, "
                f"content={response.text}"
            )
            raise Exception(
                f"Request verification to Splunk ACS API failed, "
                f"url={submit_url}, "
                f"response={response.text}"
            )
        else:
            logging.debug(
                f"Request verification to Splunk ACS API successful, "
                f"url={submit_url}, "
                f"response={response.text}"
            )

        return json.loads(response.text).get("apps")

    except Exception as e:
        logging.error(
            f"Request verification to Splunk API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        )
        raise Exception(
            f"Request verification to Splunk API failed, "
            f"url={submit_url}, "
            f"exception={e}"
        ) from e
