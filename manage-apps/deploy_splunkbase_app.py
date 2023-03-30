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
from tools import login_appinspect, login_splunkrest, get_apps_splunk_rest, \
    splunkacs_create_ephemeral_token, splunk_acs_deploy_splunkbase_app, splunk_acs_update_splunkbase_app

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--apps_dict_json', dest='apps_dict_json')
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--mode', dest='mode')
parser.add_argument('--userappinspect', dest='userappinspect')
parser.add_argument('--passappinspect', dest='passappinspect')
parser.add_argument('--create_token', dest='create_token', action='store_true')
parser.add_argument('--token_audience', dest='token_audience')
parser.add_argument('--username', dest='username')
parser.add_argument('--password', dest='password')
parser.add_argument('--tokenacs', dest='tokenacs')
parser.add_argument('--stack', dest='stack')
parser.add_argument('--license_ack', dest='license_ack')
parser.add_argument('--useproxy', dest='useproxy', action='store_true')
parser.add_argument('--proxy_url', dest='proxy_url')
parser.add_argument('--proxy_port', dest='proxy_port')
parser.add_argument('--proxy_username', dest='proxy_username')
parser.add_argument('--proxy_password', dest='proxy_password')
parser.set_defaults(debug=False)
parser.set_defaults(keep=False)
parser.set_defaults(create_token=False)
parser.set_defaults(submitappinspect=False)
args = parser.parse_args()

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

# Set mode
if args.mode:
    mode = args.mode
    if not mode in ('live', 'simulation'):
        logging.error('invalid value mode=\"{}\", valid options are simulation to show what we would do, live to proceed with ACS deployments accordingly')
        sys.exit(1)
else:
    mode = "simulation"

# Set apps_dict_json
if args.apps_dict_json:
    apps_dict_json = args.apps_dict_json
else:
    apps_dict_json = False

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

# Set license_ack
if args.license_ack:
    license_ack = args.license_ack
else:
    license_ack = False

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

# check input
if not apps_dict_json or not os.path.isfile(apps_dict_json):
    logging.error("the apps_dict_json file must be provided as an argument")
    sys.exit(1)

else:
    try:
        f = open(apps_dict_json)
        apps_dict = json.load(f)
    except Exception as e:
        logging.error('failed to load the apps dict json file=\"{}\", exception=\"{}\"'.format(apps_dict_json, str(e)))

#
# Appinspect
#

if userappinspect and passappinspect:

    # login to Appinspect
    try:
        appinspect_token = login_appinspect(userappinspect, passappinspect, proxy_dict)

        if appinspect_token:
            logging.info("Appsinspect: successfully logged in Appinspect API")
        else:
            logging.error("Appinspect: login failed, response=\"{}\"".format(appinspect_token))

    except Exception as e:
        logging.error("Appinspect: login failed, exception=\"{}\"".format(str(e)))        


#
# ACS
#

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

#
# Get the list of remote applications, and build an array with apps and their version/build number
#     

try:

    # use either splunk token or bearer token depending on the provided args
    if create_token:
        rest_auth_mode = 'bearer_token'
        # run
        splunk_apps_dict = get_apps_splunk_rest(rest_auth_mode, tokenacs, stack, proxy_dict)
        
    else:
        rest_auth_mode = 'splunk_token'
        splunk_rest_token = login_splunkrest(username, password, stack, proxy_dict)
        # run
        splunk_apps_dict = get_apps_splunk_rest(rest_auth_mode, splunk_rest_token, stack, proxy_dict)

    # debug
    logging.debug(json.dumps(splunk_apps_dict, indent=2))

except Exception as e:
    logging.error("failed to request Splunk API, exception=\"{}\"".format(str(e)))
    raise Exception("failed to request Splunk API, exception=\"{}\"".format(str(e)))

# build the list of installed app
remote_apps_dict = {}
remote_apps_list = []

for appinfo in splunk_apps_dict:

    # appname
    appname = appinfo.get('name')
    appversion = None
    appbuild = None

    # get version
    try:
        appversion = appinfo['content']['version']
    except Exception as e:
        logging.debug("app=\"{}\" has no version information, will be ignored".format(appinfo.get('name')))

    # get build
    try:
        appbuild = appinfo['content']['build']
    except Exception as e:
        logging.debug("app=\"{}\" has no build information, will be ignored".format(appinfo.get('name')))

    # proceed
    if appversion and appbuild:

        remote_apps_dict[appname] = {
            'name': appname,
            'version': appversion,
            'build': appbuild,
        }

        remote_apps_list.append(appname)

        logging.debug({
            'name': appname,
            'version': appversion,
            'build': appbuild,
        })

    elif appversion:

        remote_apps_dict[appname] = {
            'name': appname,
            'version': appversion,
        }

        remote_apps_list.append(appname)

        logging.debug({
            'name': appname,
            'version': appversion,
        })

logging.debug("remote_apps_list=\"{}\"".format(json.dumps(remote_apps_dict, indent=2)))
logging.debug("remote_apps_list=\"{}\"".format(remote_apps_list))

# loop

for record in apps_dict:

    splunkbase_name = record.get('name')
    splunkbase_id = record.get('splunkbaseID')
    license_ack = record.get('licenseAck')

    # the requested version
    version = record.get('version')

    # if the app is already installed, get the version
    try:
        version_current = remote_apps_dict[splunkbase_name].get('version')
    except Exception as e:
        version_current = None

    # Look through the apps and submit
    logging.debug('Request deploy to Splunk ACS API, app=\"{}\", id=\"{}\"'.format(splunkbase_name, splunkbase_id))

    # set None
    splunkacs_response = None

    # submit
    if splunkbase_name in remote_apps_list:

        # app is to be updated
        if version_current == version:
            logging.info("app=\"{}\", appId=\"{}\", nothing to do, version=\"{}\" matches requested version=\"{}\"".format(splunkbase_name, splunkbase_id, version_current, version))
        else:
            logging.info("app=\"{}\", appId=\"{}\", requesting update, version=\"{}\" does not matches requested version=\"{}\"".format(splunkbase_name, splunkbase_id, version_current, version))
            if mode == 'live':
                splunkacs_response = splunk_acs_update_splunkbase_app(tokenacs, appinspect_token, splunkbase_name, version, license_ack, stack, proxy_dict)

    else:
        # app is to be installed
        if mode == 'live':
            splunkacs_response = splunk_acs_deploy_splunkbase_app(tokenacs, appinspect_token, splunkbase_id, license_ack, stack, proxy_dict)

    # check
    if mode == 'live':
        if splunkacs_response:
            
            try:
                splunkacs_response = json.loads(splunkacs_response)
                status_acs = splunkacs_response['status']

                if status_acs == 'installed':
                    logging.info("Splunk ACS deployment of app=\"{}\" was successful, summary=\"{}\"".format(splunkacs_response['appID'], json.dumps(splunkacs_response, indent=4)))
                else:
                    logging.error("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(splunkbase_id, json.dumps(splunkacs_response, indent=4)))
                    raise ValueError("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(splunkbase_id, json.dumps(splunkacs_response, indent=4)))

            except Exception as e:
                logging.error("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(splunkbase_id, e))
                raise ValueError("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(splunkbase_id, e))

sys.exit(0)