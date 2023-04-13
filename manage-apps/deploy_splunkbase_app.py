#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__maintainer__ = "TBD"
__status__ = "PRODUCTION"

import os, sys
import json
import coloredlogs,logging
import argparse

# load libs
sys.path.append('libs')
from tools import login_splunkbase, login_splunkrest, get_apps_splunk_rest, \
    splunkacs_create_ephemeral_token, splunk_acs_deploy_splunkbase_app, splunk_acs_update_splunkbase_app


def set_argument_value(args, arg_name, default_value=None):
    value = getattr(args, arg_name)
    return value if value is not None else default_value


def exit_with_error(message):
    logging.error(message)
    sys.exit(1)


def create_proxy_dict(args):
    if args.useproxy:
        if not args.proxy_url or not args.proxy_port:
            exit_with_error("useproxy is enabled, but proxy_url or proxy_port were not provided")

        if not args.proxy_username or not args.proxy_password:
            return {
                "http": f"{args.proxy_url}:{args.proxy_port}",
                "https": f"{args.proxy_url}:{args.proxy_port}",
            }
        else:
            return {
                "http": f"http://{args.proxy_username}:{args.proxy_password}@{args.proxy_url}:{args.proxy_port}",
                "https": f"https://{args.proxy_username}:{args.proxy_password}@{args.proxy_url}:{args.proxy_port}",
            }
    else:
        return {}


parser = argparse.ArgumentParser()
parser.add_argument('--apps_dict_json')
parser.add_argument('--debug', action='store_true')
parser.add_argument('--mode')
parser.add_argument('--usersplunkbase')
parser.add_argument('--passsplunkbase')
parser.add_argument('--create_token', action='store_true')
parser.add_argument('--token_audience')
parser.add_argument('--username')
parser.add_argument('--password')
parser.add_argument('--tokenacs')
parser.add_argument('--tokenrest')
parser.add_argument('--stack')
parser.add_argument('--useproxy', action='store_true')
parser.add_argument('--proxy_url')
parser.add_argument('--proxy_port')
parser.add_argument('--proxy_username')
parser.add_argument('--proxy_password')
args = parser.parse_args()

debug = args.debug
mode = set_argument_value(args, 'mode', 'simulation')
if mode not in ('live', 'simulation'):
    exit_with_error(f'Invalid value mode="{mode}", valid options are "simulation" to show what we would do, "live" to proceed with ACS deployments accordingly')

apps_dict_json = set_argument_value(args, 'apps_dict_json', False)
usersplunkbase = set_argument_value(args, 'usersplunkbase', False)
passsplunkbase = set_argument_value(args, 'passsplunkbase', False)
tokenacs = set_argument_value(args, 'tokenacs', False)
tokenrest = set_argument_value(args, 'tokenrest', False)
stack = set_argument_value(args, 'stack', False)
username = set_argument_value(args, 'username', False)
password = set_argument_value(args, 'password', False)
token_audience = set_argument_value(args, 'token_audience', False)
create_token = args.create_token

if create_token and (not username or not password or not token_audience):
    exit_with_error("create_token is enabled, but username, password, or token_audience were not provided")

proxy_dict = create_proxy_dict(args)

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
# SplunkBase
#

# login to SplunKBase
try:
    splunkbase_token = login_splunkbase(usersplunkbase, passsplunkbase, proxy_dict)

    if splunkbase_token:
        logging.info("SplunkBase: successfully logged in SplunkBase API")
    else:
        logging.error("SplunkBase: login failed, response=\"{}\"".format(splunkbase_token))

except Exception as e:
    logging.error("SplunkBase: login failed, exception=\"{}\"".format(str(e)))
    

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
    if tokenrest:
        logging.info("Authentication to Splunk API using bearer auth")
        rest_auth_mode = 'bearer_token'
        # run
        splunk_apps_dict = get_apps_splunk_rest(rest_auth_mode, tokenrest, stack, proxy_dict)
        
    else:
        logging.info("Authentication to Splunk API using basic auth")
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

    logging.info("inspecting app=\"{}\", id=\"{}\"".format(splunkbase_name, splunkbase_id))

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
                splunkacs_response = splunk_acs_update_splunkbase_app(tokenacs, splunkbase_token, splunkbase_name, version, license_ack, stack, proxy_dict)

    else:
        # app is to be installed
        if mode == 'live':
            splunkacs_response = splunk_acs_deploy_splunkbase_app(tokenacs, splunkbase_token, splunkbase_id, version, license_ack, stack, proxy_dict)
        else:
            logging.info("app=\"{}\", appId=\"{}\", this app is not installed yet, run with mode=live to proceed with its deployment".format(splunkbase_name, splunkbase_id))

    # check
    if mode == 'live':
        if splunkacs_response:
            
            try:
                splunkacs_response = json.loads(splunkacs_response)
                status_acs = splunkacs_response['status']

                if status_acs == 'installed' or status_acs =='processing':
                    logging.info("Splunk ACS deployment of app=\"{}\" was successful, summary=\"{}\"".format(splunkacs_response['appID'], json.dumps(splunkacs_response, indent=4)))
                else:
                    logging.error("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(splunkbase_id, json.dumps(splunkacs_response, indent=4)))
                    #raise ValueError("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(splunkbase_id, json.dumps(splunkacs_response, indent=4)))

            except Exception as e:
                logging.error("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(splunkbase_id, e))
                #raise ValueError("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(splunkbase_id, e))

sys.exit(0)