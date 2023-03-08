#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__maintainer__ = "TBD"
__status__ = "PRODUCTION"

import os, sys
import time
import shutil
import tarfile
import json
import coloredlogs,logging
import argparse
import glob
import subprocess
import configparser
import hashlib
import base64

# load libs
sys.path.append('libs')
from tools import cd, gen_build_number, login_appinspect, submit_appinspect, verify_appinspect,\
    download_htmlreport_appinspect, download_jsonreport_appinspect, \
    splunkacs_create_ephemeral_token, splunk_acs_deploy_app

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--appfile', dest='appfile')
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--userappinspect', dest='userappinspect')
parser.add_argument('--passappinspect', dest='passappinspect')
parser.add_argument('--create_token', dest='create_token', action='store_true')
parser.add_argument('--token_audience', dest='token_audience')
parser.add_argument('--username', dest='username')
parser.add_argument('--password', dest='password')
parser.add_argument('--tokenacs', dest='tokenacs')
parser.add_argument('--stack', dest='stack')

parser.add_argument('--useproxy', dest='useproxy', action='store_true')
parser.add_argument('--proxy_url', dest='proxy_url')
parser.add_argument('--proxy_port', dest='proxy_port')
parser.add_argument('--proxy_username', dest='proxy_username')
parser.add_argument('--proxy_password', dest='proxy_password')
parser.set_defaults(debug=False)
parser.set_defaults(keep=False)
parser.set_defaults(create_token=False)
args = parser.parse_args()

# Set appfile
if args.appfile:
    appfile = args.appfile
else:
    logging.error("appfile argument was not provided, this is mandatory")
    sys.exit(1)

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

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

# Set tokenacs
if args.tokenacs:
    tokenacs = args.tokenacs
else:
    tokenacs = False

# Set stack
if args.stack:
    stack = args.stack
else:
    stack = False

# user login and password (required if create_token is set)
if args.username:
    username = args.username
else:
    username = False

if args.password:
    password = args.password
else:
    password = False

if args.token_audience:
    token_audience = args.token_audience
else:
    token_audience = False

# Create token boolean
if args.create_token:
    create_token = True
    if not username or not password or not token_audience:
        logging.error("create_token is enabled, but username, password or token_audience were not provided")
        sys.exit(1)
else:
    create_token = False

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

# Splunk ACS
# user login and password (required if create_token is set)
if args.username:
    username = args.username
else:
    username = False

if args.password:
    password = args.password
else:
    password = False

if args.token_audience:
    token_audience = args.token_audience
else:
    token_audience = False

# Create token boolean
if args.create_token:
    create_token = True
    if not username or not password or not token_audience:
        logging.error("create_token is enabled, but username, password or token_audience were not provided")
        sys.exit(1)
else:
    create_token = False

# set logging
root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

if debug:
    root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    coloredlogs.install(isatty=True, level='DEBUG', logger=logging.getLogger())
else:
    root.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)
    coloredlogs.install(isatty=True, level='INFO', logger=logging.getLogger())

#
# Program start
#

submitappinspect = True
deployacs = True

# if deployment to ACS is requested, we need to have some additional information
if deployacs:
    if create_token and (not username or not password):
        logging.error("Deployment to ACS has been requested with ephemeral token creation, but username or password were not provided")
        sys.exit(1)
    elif not create_token and not tokenacs:
        logging.error("Deployment to ACS has been requested with a permanent token, but the token was not provided")
        sys.exit(1)

# if deploy ACS, we need a stack
if deployacs and not stack:
    logging.error("Deployment to ACS has been requested but the stack was not provided")
    sys.exit(1)

#
# Appinspect
#

if submitappinspect and userappinspect and passappinspect:

    # login to Appinspect
    appinspect_token = login_appinspect(userappinspect, passappinspect, proxy_dict)

    if appinspect_token:
        logging.info("Appsinspect: successfully logged in Appinspect API")

        appinspect_requestids = []

        if os.path.isfile(appfile):
            logging.info('Submitting to Appinspect API=\"{}\"'.format(appfile))

            # set None
            appinspect_response = None

            # submit
            appinspect_response = submit_appinspect(appinspect_token, appfile, proxy_dict)

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
        
# if requested, deploy to Splunk ACS
if deployacs:

    #
    # If create token is enabled, we first need to create an ephemeral token for to be used in the rest of the operations
    #

    if create_token:
        tokenacs = None
        try:    
            tokenacs_creation_response = splunkacs_create_ephemeral_token(stack, username, password, token_audience, proxy_dict)
            logging.info("Ephemeral token created successfully")
            tokenacs = json.loads(tokenacs_creation_response).get('token')
            tokenid = json.loads(tokenacs_creation_response).get('id')

        except Exception as e:
            logging.error("An exception was encountered while attempting to create an ephemeral token from Splunk ACS, exception=\"{}\"".format(str(e)))
            tokenacs = None
            raise Exception(str(e))        

    if not tokenacs:
        sys.exit(1)

    # Look through the apps and submit
    if os.path.isfile(appfile):
        logging.debug('Deploy to Splunk ACS API=\"{}\"'.format(appfile))

        # set None
        splunkacs_response = None

        # submit
        splunkacs_response = splunk_acs_deploy_app(tokenacs, appinspect_token, appfile, stack, proxy_dict)

        # check
        if splunkacs_response:
            
            try:
                splunkacs_response = json.loads(splunkacs_response)
                status_acs = splunkacs_response['status']

                if status_acs == 'installed':
                    logging.info("Splunk ACS deployment of app=\"{}\" was successful, summary=\"{}\"".format(splunkacs_response['appID'], json.dumps(splunkacs_response, indent=4)))
                else:
                    logging.error("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(appfile, json.dumps(splunkacs_response, indent=4)))
                    raise ValueError("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(appfile, json.dumps(splunkacs_response, indent=4)))

            except Exception as e:
                logging.error("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(appfile, str(e)))
                raise ValueError("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(appfile, str(e)))

sys.exit(0)
