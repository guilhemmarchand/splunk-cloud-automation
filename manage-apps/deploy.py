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
import logging
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
parser.add_argument('--appdir', dest='appdir')
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--keep', dest='keep', action='store_true')
parser.add_argument('--submitappinspect', dest='submitappinspect', action='store_true')
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
parser.set_defaults(submitappinspect=False)
args = parser.parse_args()

# Set appdir
if args.appdir:
    appdir = args.appdir
else:
    logging.error("appdir agrument was not provided, this is mandatory")
    sys.exit(1)

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

# Set keep boolean
if args.keep:
    keep = True
else:
    keep = False

# Set deployacs boolean
if args.deployacs:
    deployacs = args.deployacs
    if deployacs == 'True':
        deployacs = True
    else:
        deployacs = False
else:
    deployacs = False

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
else:
    root.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)

# deployConfig.json
deployconf = "DeployConfig.json"

# appConfig file
appconf = "AppConfig.json"

# output_dir
output_dir = "output"

#
# Program start
#

if not os.path.isfile(deployconf):
    logging.error("Could not find expected DeployConfig.json")
    sys.exit(1)
else:
    f = open(deployconf)
    deployconf = json.load(f)
    logging.info("Successfully loaded the default list of authorized Splunk config files, DeployConfFilesList=\"{}\"".format(json.dumps(deployconf.get('DeployConfFilesList'), indent=2)))

# check appdir
if not os.path.isdir(appdir):
    logging.error("Could not find non existing appdir=\"{}\"".format(appdir))
    sys.exit(1)

else:
    # enter appdir and start
    with cd(appdir):    

        if os.path.isfile(appconf):
            f = open(appconf)
            appconf = json.load(f)
        else:
            logging.error("failed to open non existing AppConfig.json")
            sys.exit(1)

        # if deployment to ACS is requested, we need to have some additional information
        if deployacs:
            if create_token and not username or not password:
                logging.error("Deployment to ACS has been requested with ephemeral token creation, but username or password were not provided")
                sys.exit(1)
            elif not create_token and not tokenacs:
                logging.error("Deployment to ACS has been requested with a permanent token, but the token was not provided")
                sys.exit(1)

        # get and set
        buildNumber = gen_build_number()
        appAuthor = appconf.get("appAuthor")
        appID = appconf.get('appID')
        appLabel = appconf.get('appLabel')
        appDecription = appconf.get('appDecription')
        appMerge = appconf.get('appMerge')
        appSource = appconf.get('appSource')
        appVersion = appconf.get('appVersion')

        # log
        logging.info("Starting build buildNumber=\"{}\", appconf=\"{}\"".format(buildNumber, json.dumps(appconf, indent=2)))

        # create output dir
        if not os.path.isdir(output_dir):
            try:
                os.mkdir(output_dir)
            except Exception as e:
                logging.error("Failed to create the output_directory=\"{}\", exception=\"{}\"".format(output_dir, str(e)))
                sys.exit(1)

        # Package
        with cd(output_dir):

            # check if directory exists already
            if os.path.isdir(appID):
                try:
                    shutil.rmtree(appID)
                except Exception as e:
                    logging.error("failed to remove existing output directory=\"{}\", exception=\"{}\"".format(appID, str(e)))
                    sys.exit(1)
            # create
            try:
                os.mkdir(appID)
            except Exception as e:
                logging.error("failed to create output directory=\"{}\"".format(os.join(output_dir, appID), str(e)))
                sys.exit(1)

            # Purge any existing tgz in the output directory
            files = glob.glob(os.path.join('*.tgz'))
            for file_name in files:
                logging.debug('Attempting to remove existing tgz archive=\"{}\"'.format(file_name))
                if os.path.isfile(file_name):
                    try:
                        os.remove(file_name)
                        logging.debug('Archive=\"{}\" was deleted successfully'.format(file_name))
                    except Exception as e:
                        logging.error('Archive=\"{}\" could not be deleted, exception=\"{}\"'.format(file_name, e))

            # Purge Appinspect previous reports
            files = glob.glob(os.path.join('report_*.html'))
            for file_name in files:
                logging.debug('Attempting to remove report=\"{}\"'.format(file_name))
                if os.path.isfile(file_name):
                    try:
                        os.remove(file_name)
                        logging.debug('Report=\"{}\" was deleted successfully'.format(file_name))
                    except Exception as e:
                        logging.error('Report=\"{}\" could not be deleted, exception=\"{}\"'.format(file_name, e))

            files = glob.glob(os.path.join('report_*.json'))
            for file_name in files:
                logging.debug('Attempting to remove report=\"{}\"'.format(file_name))
                if os.path.isfile(file_name):
                    try:
                        os.remove(file_name)
                        logging.debug('Report=\"{}\" was deleted successfully'.format(file_name))
                    except Exception as e:
                        logging.error('Report=\"{}\" could not be deleted, exception=\"{}\"'.format(file_name, e))

            # create the basic structure
            os.mkdir(os.path.join(appID, "default"))
            os.mkdir(os.path.join(appID, "metadata"))
            os.mkdir(os.path.join(appID, "lookups"))

            # copy source metadata
            try:
                shutil.copyfile(os.path.join("../", appSource, "metadata", "default.meta"), os.path.join(appID, "metadata", "default.meta"))
            except Exception as e:
                logging.error("failed to copy metadata, exception=\"{}\"".format(str(e)))
            

        # generate the app.conf in default
        with cd(os.path.join(output_dir, appID, "default")):

            config_file = configparser.ConfigParser()

            config_file["install"]={
                    "is_configured": "0",
                    "build": buildNumber,
                }    

            config_file["package"]={
                    "id": appID,
                    "build": buildNumber,
                }    

            config_file["ui"]={
                    "is_visible": "0",
                    "label": appLabel,
                }    

            config_file["launcher"]={
                    "author": appAuthor,
                    "description": appDecription,
                    "version": appVersion,
                }    

            # save
            try:
                with open("app.conf","w") as file_object:
                    config_file.write(file_object)
            except Exception as e:
                logging.error("Failed to generate the app.conf, exception=\"{}\"".format(str(e)))

        # if app merging is requested
        if appMerge == 'True':
            logging.info("appMerge was requested, starting the merge process using ksconf for configuration files")

            # check the source exists
            if not os.path.isdir(appSource):
                logging.error("Could not find the request source app folder=\"{}\"".format(appSource))
                sys.exit(1)

            else:

                #
                # handle conf files
                #

                default_conf_files = deployconf.get('DeployConfFilesList')

                try:
                    local_conf_files = appconf.get('DeployConfFilesList')
                    logging.info("Successfully loaded a local list of authorized Splunk config files, this will override default allowed config files, DeployConfFilesList=\"{}\"".format(json.dumps(appconf.get('DeployConfFilesList'), indent=2)))
                except Exception as e:
                    local_conf_files = default_conf_files

                if local_conf_files:
                    conf_files = local_conf_files
                else:
                    conf_files = default_conf_files

                for conf_file in conf_files:
                    # if we have a file to be merged
                    if os.path.exists(os.path.join(appID, "local", conf_file)):
                        logging.info("Processing to stanza merging of local {} to target default".format(conf_file))

                        # check if there is a default in the appSource to be merged
                        has_default = False
                        if os.path.exists(os.path.join(appSource, "default", conf_file)):
                            has_default = True

                        if has_default:
                            shutil.copyfile(os.path.join(appSource, "default", conf_file), os.path.join(output_dir, appID, "default", conf_file))

                            #
                            # ksconf merge
                            #

                            # if we have both, we merge using ksconf
                            logging.info("running ksconf promote -k -b {} {}".format(os.path.join(appID, "local", conf_file), os.path.join(output_dir, appID, "default", conf_file)))

                            try:
                                result = subprocess.run(["ksconf", "promote", "-k", "-b", os.path.join(appID, "local", conf_file), os.path.join(output_dir, appID, "default", conf_file)], capture_output=True)
                                logging.info("ksconf results.stdout=\"{}\"".format(result.stdout))
                                logging.info("ksconf results.stderr=\"{}\"".format(result.stderr))


                            except Exception as e:
                                logging.error("error encountered while attempted to run ksconf, exception=\"{}\"".format(str(e)))

                        # there is no default, simply copy
                        else:
                            shutil.copyfile(os.path.join(appID, "local", conf_file), os.path.join(output_dir, appID, "default", conf_file))

                #
                # handle lookups
                #

                if os.path.isdir(os.path.join(appSource, "lookups")):

                    logging.info("Inspecting lookups now")

                    with cd(os.path.join(appSource, "lookups")):

                        for filename in glob.iglob(f'*.csv'):

                            logging.info("Inspecting lookup file=\"{}\"".format(filename))

                            # check if we have a local version
                            if os.path.isfile(os.path.join("../../", appID, "lookups", filename)):

                                logging.info("A local copy of the lookup was found with {}/lookups/{}".format(appID, filename))
                                # copy this version
                                try:
                                    shutil.copyfile(os.path.join("../../", appID, "lookups", filename), os.path.join("../../", output_dir, appID, "lookups", filename))
                                except Exception as e:
                                    logging.error("failed to copy the local lookup file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)

                            else:
                                logging.info("There is no local version of this lookup file, copying the vendor version")
                                # copy the vendor version
                                try:
                                    shutil.copyfile(os.path.join("../../", appSource, "lookups", filename), os.path.join("../../", output_dir, appID, "lookups", filename))
                                except Exception as e:
                                    logging.error("failed to copy the vendor lookup file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)

        else:

            # no merging

            # process .conf
            with cd(os.path.join(appID, "local")):
                for filename in glob.iglob(f'*.conf'):
                    logging.info("Copying source conf file {} to target".format(filename))
            
            # process lookups
            if os.path.isdir(os.path.join(appID, "lookups")):
                with cd(os.path.join(appID, "lookups")):
                    for filename in glob.iglob(f'*.csv'):
                        logging.info("Copying source csv file {} to target".format(filename))

        #
        # time to build
        #

        with cd(output_dir):

            tar_file = str(appID) + "_v" + str(appVersion.replace(".", "")) + "_" + str(buildNumber) + ".tgz"
            logging.info("Creating compress tgz, output_directory=\"{}\", filename=\"{}\"".format(output_dir, tar_file))

            out = tarfile.open(tar_file, mode='w:gz')

            try:
                out.add(str(appID))
            except Exception as e:
                logging.error("appID=\"{}\", archive file=\"{}\" creation failed with exception=\"{}\"".format(appID, tar_file, e))
                raise ValueError("appID=\"{}\", archive file=\"{}\" creation failed with exception=\"{}\"".format(appID, tar_file, e))
            finally:
                logging.info('"appID=\"{}\", Achive tar file creation, archive_file=\"{}\"'.format(appID, tar_file))
                out.close()

            # Remove build directories
            if not keep:
                if os.path.isdir(appID):
                    logging.debug("appID=\"{}\", purging existing directory app_root=\"{}\"".format(appID, appID))
                    try:
                        shutil.rmtree(appID)
                    except Exception as e:
                        logging.error("appID=\"{}\", failed to purge the build directory=\"{}\" with exception=\"{}\"".format(appID, appID, e))
                        raise ValueError("appID=\"{}\", failed to purge the build directory=\"{}\" with exception=\"{}\"".format(appID, appID, e))

        #
        # Appinspect
        #

        if submitappinspect and userappinspect and passappinspect:

            # login to Appinspect
            appinspect_token = login_appinspect(userappinspect, passappinspect, proxy_dict)

            if appinspect_token:
                logging.info("Appsinspect: successfully logged in Appinspect API")

                # loop
                with cd(output_dir):

                    appinspect_requestids = []

                    # Purge any existing tgz in the output directory
                    files = glob.glob(os.path.join(appID + '*.tgz'))
                    for file_name in files:
                        if os.path.isfile(file_name):
                            logging.info('Submitting to Appinspect API=\"{}\"'.format(file_name))

                            # set None
                            appinspect_response = None

                            # submit
                            appinspect_response = submit_appinspect(appinspect_token, file_name, proxy_dict)

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

            # loop
            with cd(output_dir):

                # Look through the apps and submit
                files = glob.glob(os.path.join(appID + '*.tgz'))
                for file_name in files:
                    if os.path.isfile(file_name):
                        logging.debug('Deploy to Splunk ACS API=\"{}\"'.format(file_name))

                        # set None
                        splunkacs_response = None

                        # submit
                        splunkacs_response = splunk_acs_deploy_app(tokenacs, appinspect_token, file_name, stack, proxy_dict)

                        # check
                        if splunkacs_response:
                            
                            try:
                                splunkacs_response = json.loads(splunkacs_response)
                                status_acs = splunkacs_response['status']

                                if status_acs == 'installed':
                                    logging.info("Splunk ACS deployment of app=\"{}\" was successful, summary=\"{}\"".format(splunkacs_response['appID'], json.dumps(splunkacs_response, indent=4)))
                                else:
                                    logging.error("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(file_name, json.dumps(splunkacs_response, indent=4)))
                                    raise ValueError("Splunk ACS deployment of app=\"{}\" has failed, summary=\"{}\"".format(file_name, json.dumps(splunkacs_response, indent=4)))

                            except Exception as e:
                                logging.error("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(file_name, e))
                                raise ValueError("Splunk ACS deployment of app=\"{}\", an expection was encountered, exception=\"{}\"".format(file_name, e))

sys.exit(0)
