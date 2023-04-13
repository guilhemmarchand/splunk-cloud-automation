#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__maintainer__ = "TBD"
__status__ = "PRODUCTION"

import os, sys
import time
import json
import coloredlogs,logging
import argparse
import glob

# load libs
sys.path.append('libs')
from tools import cd, gen_build_number, login_appinspect, submit_appinspect, verify_appinspect,\
    download_htmlreport_appinspect, download_jsonreport_appinspect, \
    splunkacs_create_ephemeral_token, splunk_acs_deploy_app, login_splunkrest, get_apps_splunk_rest

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--appdir', dest='appdir')
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--keep', dest='keep', action='store_true')

parser.add_argument('--appfilter', dest='appfilter')

parser.add_argument('--mode', dest='mode')

parser.add_argument('--tokenrest', dest='tokenrest')

parser.add_argument('--userappinspect', dest='userappinspect')
parser.add_argument('--passappinspect', dest='passappinspect')

parser.add_argument('--deployacs', dest='deployacs')
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

# Set appdir
if args.appdir:
    appdir = args.appdir
else:
    logging.error("appdir argument was not provided, this is mandatory")
    sys.exit(1)

# Set appfilter (can be a comma separated list of values)
if args.appfilter:
    appfilter = args.appfilter
    if not isinstance(appfilter, list):
        appfilter = appfilter.split(",")
else:
    appfilter = []

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

# Set tokenacs
if args.tokenrest:
    tokenrest = args.tokenrest
else:
    tokenrest = False

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

# check we can authenticate against Splunk REST API
if not tokenrest and not (create_token and username and password):
    logging.error('tokenrest or createtoken with username and password must be provided to authenticate against Splunk REST API and retrieve the list of applications deployed')
    sys.exit(1)

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

if debug:
    root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
    coloredlogs.install(isatty=True, level='DEBUG', logger=logging.getLogger())
else:
    root.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)
    coloredlogs.install(isatty=True, level='INFO', logger=logging.getLogger())

#
# First authenticate to ACS & Appinspect
#

# ACS
if create_token:
    
    tokenacs = None
    try:    
        tokenacs_creation_response = splunkacs_create_ephemeral_token(stack, username, password, token_audience, proxy_dict)
        logging.info("Splunk ACS Ephemeral token created successfully")
        tokenacs = json.loads(tokenacs_creation_response).get('token')
        tokenid = json.loads(tokenacs_creation_response).get('id')

    except Exception as e:
        logging.error("An exception was encountered while attempting to create an ephemeral token from Splunk ACS, exception=\"{}\"".format(str(e)))
        tokenacs = None
        raise Exception(str(e))        

    if not tokenacs:
        sys.exit(1)

elif not tokenacs:
    logging.error('cannot request mode=live without the necessary information to connect to Splunk ACS')
    sys.exit(1)

# Appinspect
if userappinspect and passappinspect:

    try:
        appinspect_token = login_appinspect(userappinspect, passappinspect, proxy_dict)
    except Exception as e:
        logging.error('failed to login to Appinspect, cannot continue, exception=\"{}\"'.format(str(e)))
        sys.exit(1)

    if appinspect_token:
        logging.info("Appsinspect: successfully logged in Appinspect API")
    else:
        logging.error('failed to login to Appinspect, cannot continue.')
        sys.exit(1)

else:

    logging.error('appinspect username and password are required with mode=live')
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

# Start message
logging.info("********** starting program massdeploy.py with appdir=\"{}\", target_stack=\"{}\" **********".format(appdir, stack))

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

#
# build the list of local applications
#

apps_local_dict = {}
apps_local_list = []

with cd(appdir):

    localappdirs = glob.glob('*')
    for localappdir in localappdirs:
        if os.path.isdir(localappdir):

            if localappdir in appfilter or len(appfilter) == 0:

                logging.debug("handling local app=\"{}\"".format(localappdir))

                appname = localappdir
                appversion = None
                appbuild = None
                apparchive = None

                with cd(localappdir):
                    if os.path.isfile('version.txt'):
                        with open('version.txt') as f:
                            appversion = f.readline()
                            logging.debug("app=\"{}\", version=\"{}\"".format(appname, appversion))

                    if os.path.isfile('build.txt'):
                        with open('build.txt') as f:
                            appbuild = f.readline()
                            logging.debug("app=\"{}\", build=\"{}\"".format(appname, appbuild))

                    tgz = glob.glob(str(appname) + '*.tgz')
                    if os.path.isfile(tgz[0]):
                        apparchive = tgz[0]
                        logging.debug("app=\"{}\", apparchive=\"{}\"".format(appname, apparchive))

                # proceed
                if appversion and appbuild:

                    apps_local_dict[appname] = {
                        'name': appname,
                        'version': appversion,
                        'build': appbuild,
                        'archive': apparchive,
                    }

                    apps_local_list.append(appname)

                    logging.debug({
                        'name': appname,
                        'version': appversion,
                        'build': appbuild,
                        'archive': apparchive,
                    })

                elif appversion:

                    apps_local_dict[appname] = {
                        'name': appname,
                        'version': appversion,
                        'archive': apparchive,
                    }

                    apps_local_list.append(appname)

                    logging.debug({
                        'name': appname,
                        'version': appversion,
                        'archive': apparchive,
                    })

logging.debug("apps_local_list=\"{}\"".format(json.dumps(apps_local_dict, indent=2)))
logging.debug("apps_local_list=\"{}\"".format(apps_local_list))

if len(apps_local_list) == 0:
    logging.info("There are no applications to be deployed.")
    logging.info("********** ending program massdeploy.py target_stack=\"{}\" **********".format(stack))
    sys.exit(0)

#
# Loop, check and deploy as needed
#

for app in apps_local_list:

    logging.debug("handling local app=\"{}\", app_info=\"{}\"".format(app, json.dumps(apps_local_dict[app], indent=2)))

    try:
        target_appversion = apps_local_dict[app].get('version')
    except Exception as e:
        target_appversion = None
    
    try:
        target_appbuild = apps_local_dict[app].get('build')
    except Exception as e:
        target_appbuild = None

    try:
        target_apparchive = apps_local_dict[app].get('archive')
    except Exception as e:
        target_apparchive = None

    deployment_reason = None

    # uc1: app is not deployed yet
    if not app in remote_apps_list:

        logging.info("app=\"{}\" is not installed yet on the target stack=\"{}\", proceeding to its deployment now".format(app, stack))
        deployment_reason = 'not_installed'

    # uc2: app is deployed but out of date
    elif app in remote_apps_list:

        logging.debug("app=\"{}\" is installed on target stack=\"{}\", checking if it is up to date".format(app, stack))

        # set remote
        try:
            remote_appversion = remote_apps_dict[app].get('version')
        except Exception as e:
            remote_appversion = None

        try:    
            remote_appbuild = remote_apps_dict[app].get('build')
        except Exception as e:
            remote_appbuild = None

        # if we have both version and buid
        if target_appversion and target_appbuild:

            # check version and build
            if str(target_appversion) == str(remote_appversion) and int(target_appbuild) == int(remote_appbuild):
                logging.info("app=\"{}\", app is up to date, local_version=\"{}\", remote_version=\"{}\", local_build=\"{}\", remote_build=\"{}\", nothing to do.".format(app, target_appversion, remote_appversion, target_appbuild, remote_appbuild))

            else:
                logging.info("app=\"{}\", detected mistmatch, local_version=\"{}\", remote_version=\"{}\", local_build=\"{}\", remote_build=\"{}\", deployment will be requested.".format(app, target_appversion, remote_appversion, target_appbuild, remote_appbuild))
                deployment_reason = 'out_of_date'

        # if we only have a version
        elif target_appversion:

            # check version and build
            if str(target_appversion) == str(remote_appversion):
                logging.info("app=\"{}\", app is up to date, local_version=\"{}\", remote_version=\"{}\", nothing to do.".format(app, target_appversion, remote_appversion))

            else:
                logging.info("app=\"{}\", detected mistmatch, local_version=\"{}\", remote_version=\"{}\", deployment will be requested.".format(app, target_appversion, remote_appversion))
                deployment_reason = 'out_of_date'

    # deploy as needed

    if deployment_reason and mode == 'simulation':
        logging.info("simulation mode terminated, to proceed with deployment effectively, run this command with --mode=live")

    elif deployment_reason:
        logging.info("fasten your belt, Splunk ACS deployment starting now for app=\"{}\", deployemnt_reason=\"{}\"".format(app, deployment_reason))

        # get app info
        deploy_apparchive = apps_local_dict[app].get('archive')

        # set file_name
        file_name = os.path.join(appdir, app, deploy_apparchive)

        # we have to submit to Appinspect first
        appinspect_passed = False

        logging.info('Submitting to Appinspect API=\"{}\"'.format(file_name))

        # submit
        appinspect_response = submit_appinspect(appinspect_token, file_name, proxy_dict)
        request_id = json.loads(appinspect_response)['request_id']

        # sleep 2 seconds
        time.sleep(2)

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

        # Get JSON report                
        appinspect_report = download_jsonreport_appinspect(appinspect_token, request_id, proxy_dict)

        # Load the json dict
        appinspect_report_dict = json.loads(appinspect_report)

        count_failure = int(appinspect_report_dict['summary']['failure'])
        count_error = int(appinspect_report_dict['summary']['failure'])

        if count_failure == 0 and count_error == 0:
            logging.info("Appinspect request_id=\"{}\" was successfully vetted, summary=\"{}\"".format(request_id, json.dumps(appinspect_report_dict['summary'], indent=4)))
            appinspect_passed = True
        else:
            logging.error("Appinspect request_id=\"{}\" could not be vetted, review the report for more information, summary=\"{}\"".format(request_id, json.dumps(appinspect_report_dict['summary'], indent=4)))
            appinspect_passed = False

        # if passed, submit to ACS for deployment
        if appinspect_passed:

            # submit
            splunkacs_response = splunk_acs_deploy_app(tokenacs, appinspect_token, file_name, stack, proxy_dict)

            # check
            if splunkacs_response:
                
                try:
                    splunkacs_response = json.loads(splunkacs_response)
                    status_acs = splunkacs_response['status']

                    if status_acs in ('installed', 'uploaded'):
                        logging.info("Splunk ACS deployment of app=\"{}\" was successful, summary=\"{}\"".format(splunkacs_response['appID'], json.dumps(splunkacs_response, indent=4)))
                    else:
                        logging.error("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(file_name, json.dumps(splunkacs_response, indent=4)))
                        raise ValueError("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(file_name, json.dumps(splunkacs_response, indent=4)))

                except Exception as e:
                    logging.error("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(file_name, e))
                    raise ValueError("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(file_name, e))

#
# end message
#
logging.info("********** ending program massdeploy.py target_stack=\"{}\" **********".format(stack))
