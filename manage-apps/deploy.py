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

parser.add_argument('--deploy_onprem_standalone', dest='deploy_onprem_standalone')
parser.add_argument('--deploy_onprem_user', dest='deploy_onprem_user')
parser.add_argument('--deploy_onprem_target', dest='deploy_onprem_target')


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
    logging.error("appdir argument was not provided, this is mandatory")
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

# Set deploy_onprem_standalone boolean
if args.deploy_onprem_standalone:
    deploy_onprem_standalone = args.deploy_onprem_standalone
    if deploy_onprem_standalone == 'True':
        deploy_onprem_standalone = True
    else:
        deploy_onprem_standalone = False
else:
    deploy_onprem_standalone = False

# Set deploy_onprem_user
if args.deploy_onprem_user:
    deploy_onprem_user = args.deploy_onprem_user
else:
    deploy_onprem_user = False

# Set deploy_onprem_target
if args.deploy_onprem_target:
    deploy_onprem_target = args.deploy_onprem_target
else:
    deploy_onprem_target = False

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

# appConfig file
appconf = "AppConfig.json"

# output_dir
output_dir = "output"

#
# Program start
#

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
        appDescription = appconf.get('appDescription')
        appMerge = appconf.get('appMerge')

        # Applies to merging use cases only
        try:
            appSource = appconf.get('appSource')
        except Exception as e:
            appSource = None
        appVersion = appconf.get('appVersion')

        # optionally restrict which configuration files are allowed
        try:
            configFilesAuthorized = appconf.get("configFilesAuthorized")
        except Exception as e:
            configFilesAuthorized = None

        # optionally forbid specific configuration files, for instances inputs.conf
        try:
            configFilesDenied = appconf.get("configFilesDenied")
        except Exception as e:
            configFilesDenied = None

        # optionally allow or disallow incoporating views
        try:
            configAllowViews = appconf.get("configAllowViews")
            if configAllowViews == 'True':
                configAllowViews = True
            else:
                configAllowViews = False
        except Exception as e:
            configAllowViews = None

        # optionally allow or disallow incoporating alerts
        try:
            configAllowAlerts = appconf.get("configAllowAlerts")
            if configAllowAlerts == 'True':
                configAllowAlerts = True
            else:
                configAllowAlerts = False
        except Exception as e:
            configAllowAlerts = False

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

            # Purge version.txt
            files = glob.glob(os.path.join('version.txt'))
            for file_name in files:
                logging.debug('Attempting to remove file=\"{}\"'.format(file_name))
                if os.path.isfile(file_name):
                    try:
                        os.remove(file_name)
                        logging.debug('file=\"{}\" was deleted successfully'.format(file_name))
                    except Exception as e:
                        logging.error('file=\"{}\" could not be deleted, exception=\"{}\"'.format(file_name, e))

            # Purge build.txt
            files = glob.glob(os.path.join('build.txt'))
            for file_name in files:
                logging.debug('Attempting to remove file=\"{}\"'.format(file_name))
                if os.path.isfile(file_name):
                    try:
                        os.remove(file_name)
                        logging.debug('file=\"{}\" was deleted successfully'.format(file_name))
                    except Exception as e:
                        logging.error('file=\"{}\" could not be deleted, exception=\"{}\"'.format(file_name, e))

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
                    "description": appDescription,
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

                ########### conf files ###########
                #
                # handle conf files
                #
                ##################################

                # set an empty list
                source_conf_files = []
                with cd(os.path.join(appSource, "default")):
                    for filename in glob.iglob(f'*.conf'):

                        # if not restricted, takes all *.conf
                        if not configFilesAuthorized:

                            # unless forbidden
                            if configFilesDenied:
                                if filename not in configFilesDenied:
                                    source_conf_files.append(filename)
                            else:
                                source_conf_files.append(filename)

                        # if restricted, this should be in the allowed list of configuration files
                        elif configFilesAuthorized:
                            if filename in configFilesAuthorized:

                                # unless forbidden
                                if configFilesAuthorized:
                                    if filename not in configFilesDenied:
                                        source_conf_files.append(filename)
                                else:
                                    source_conf_files.append(filename)

                # remove app.conf
                if "app.conf" in source_conf_files:
                    source_conf_files.remove("app.conf")

                # wmi.conf is always rejected
                if "wmi.conf" in source_conf_files:
                    source_conf_files.remove("wmi.conf")

                for conf_file in source_conf_files:
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

                    # there is no local, simply copy
                    else:
                        shutil.copyfile(os.path.join(appSource, "default", conf_file), os.path.join(output_dir, appID, "default", conf_file))

                ########### lookup files ###########
                #
                # handle lookup files
                #
                ####################################

                logging.info("Inspecting lookups now")

                # store source lookups in a list
                source_lookups = []
                if os.path.isdir(os.path.join(appSource, "lookups")):
                    with cd(os.path.join(appSource, "lookups")):
                        for filename in glob.iglob(f'*.csv'):
                            source_lookups.append(filename)
                logging.debug("lookups in source=\"{}\"".format(source_lookups))

                # store local lookups in a list
                local_lookups = []
                if os.path.isdir(os.path.join(appID, "lookups")):
                    with cd(os.path.join(appID, "lookups")):
                        for filename in glob.iglob(f'*.csv'):
                            local_lookups.append(filename)
                logging.debug("lookups in source=\"{}\"".format(local_lookups))

                # for each local lookups which would not exist in default, get a copy
                if local_lookups:
                    for filename in local_lookups:
                        if not filename in source_lookups:
                            # copy this version
                            try:
                                shutil.copyfile(os.path.join(appID, "lookups", filename), os.path.join(output_dir, appID, "lookups", filename))
                                logging.info("the lookup filename=\"{}\" only exists in the local application, copying.".format(filename))
                            except Exception as e:
                                logging.error("failed to copy the local lookup file, exception=\"{}\"".format(str(e)))
                                sys.exit(1)

                # manage conflicting lookups
                if source_lookups and local_lookups:

                    for filename in source_lookups:

                        logging.info("Inspecting lookup file=\"{}\"".format(filename))

                        # check if we have a local version
                        if filename in local_lookups:

                            logging.info("A local copy of the lookup was found with {}/lookups/{}".format(appID, filename))
                            # copy this version
                            try:
                                shutil.copyfile(os.path.join(appID, "lookups", filename), os.path.join(output_dir, appID, "lookups", filename))
                            except Exception as e:
                                logging.error("failed to copy the local lookup file, exception=\"{}\"".format(str(e)))
                                sys.exit(1)

                        else:
                            logging.info("There is no local version of this lookup file, copying the vendor version")
                            # copy the vendor version
                            try:
                                shutil.copyfile(os.path.join(appSource, "lookups", filename), os.path.join(output_dir, appID, "lookups", filename))
                            except Exception as e:
                                logging.error("failed to copy the vendor lookup file, exception=\"{}\"".format(str(e)))
                                sys.exit(1)

                ########### views ##############################
                #
                # handle views
                #
                #################################################

                if configAllowViews:

                    viewsList = []
                    if os.path.isdir(os.path.join(appSource, "default", "data", "views")):
                        with cd(os.path.join(appSource, "default", "data", "views")):
                            for filename in glob.iglob(f'*.xml'):
                                viewsList.append(filename)                   

                    # create structure
                    if not os.path.isdir(os.path.join(output_dir, appID, "default", "data")):
                        os.mkdir(os.path.join(output_dir, appID, "default", "data")) 
                    os.mkdir(os.path.join(output_dir, appID, "default", "data", "views"))        

                    # take local, if any
                    if os.path.isdir(os.path.join(appID, "local", "data", "views")):
                        for filename in viewsList:
                            if os.path.isfile(os.path.join(appID, "local", "data", "views", filename)):
                                # copy this version
                                try:
                                    shutil.copyfile(os.path.join(appID, "local", "data", "views", filename), os.path.join(output_dir, appID, "default", "data", "views", filename))
                                except Exception as e:
                                    logging.error("failed to copy the local view file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)
                            else:
                                # copy vendor version
                                try:
                                    shutil.copyfile(os.path.join(appSource, "default", "data", "views", filename), os.path.join(output_dir, appID, "default", "data", "views", filename))
                                except Exception as e:
                                    logging.error("failed to copy the local view file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)

                    # handle nav finally
                    if os.path.isdir(os.path.join(appID, "local", "data", "nav", "default.xml")):
                        os.mkdir(os.path.join(output_dir, appID, "default", "data", "nav"))
                        # copy this version
                        try:
                            shutil.copyfile(os.path.join(appID, "local", "data", "nav", "default.xml"), os.path.join(output_dir, appID, "default", "data", "nav", "default.xml"))
                        except Exception as e:
                            logging.error("failed to copy the local view file, exception=\"{}\"".format(str(e)))
                            sys.exit(1)
                    elif os.path.isdir(os.path.join(appSource, "default", "data", "nav", "default.xml")):
                        os.mkdir(os.path.join(output_dir, appID, "default", "data", "nav"))
                        # copy vendor version
                        try:
                            shutil.copyfile(os.path.join(appSource, "default", "data", "nav", "default.xml"), os.path.join(output_dir, appID, "default", "data", "nav", "default.xml"))
                        except Exception as e:
                            logging.error("failed to copy the vendor view file, exception=\"{}\"".format(str(e)))
                            sys.exit(1)

                ########### alerts ##############################
                #
                # handle alerts
                #
                #################################################

                if configAllowAlerts:

                    viewsList = []
                    if os.path.isdir(os.path.join(appSource, "default", "data", "alerts")):
                        with cd(os.path.join(appSource, "default", "data", "alerts")):
                            for filename in glob.iglob(f'*.html'):
                                viewsList.append(filename)                   

                    # create structure
                    if not os.path.isdir(os.path.join(output_dir, appID, "default", "data")):
                        os.mkdir(os.path.join(output_dir, appID, "default", "data"))
                    os.mkdir(os.path.join(output_dir, appID, "default", "data", "alerts"))        

                    # take local, if any
                    if os.path.isdir(os.path.join(appID, "local", "data", "alerts")):
                        for filename in viewsList:
                            if os.path.isfile(os.path.join(appID, "local", "data", "alerts", filename)):
                                # copy this version
                                try:
                                    shutil.copyfile(os.path.join(appID, "local", "data", "alerts", filename), os.path.join(output_dir, appID, "default", "data", "alerts", filename))
                                except Exception as e:
                                    logging.error("failed to copy the local view file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)
                            else:
                                # copy vendor version
                                try:
                                    shutil.copyfile(os.path.join(appSource, "default", "data", "alerts", filename), os.path.join(output_dir, appID, "default", "data", "alerts", filename))
                                except Exception as e:
                                    logging.error("failed to copy the local view file, exception=\"{}\"".format(str(e)))
                                    sys.exit(1)

                ########### others ##############################
                #
                # handle other use cases (README, bin, appserver)
                #
                #################################################

                other_content = [
                    'bin',
                    'README',
                    'static',
                    'appserver',
                    'LICENSES',
                    'lib',
                ]

                for directory in other_content:
                    if os.path.isdir(os.path.join(appSource, directory)):

                        if directory in ('appserver') and not configAllowViews or configAllowAlerts:
                            logging.info("ignoring appserver as nor configAllowsViews or configAllowsAlerts is set to True")
                        else:
                            try:
                                shutil.copytree(os.path.join(appSource, directory), os.path.join(output_dir, appID, directory))
                            except Exception as e:
                                logging.error("Could not copy the directory, exception=\"{}\"".format(str(e)))

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

            # Store version and build into simple text files
            with open("version.txt", "a") as f:
                f.write(str(appVersion))

            with open("build.txt", "a") as f:
                f.write(str(buildNumber))

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

        # if requested, deploy to Splunk on-prem standalone
        if deploy_onprem_standalone and deploy_onprem_user and deploy_onprem_target:

            filename = str(appID) + "_v" + str(appVersion).replace(".", "") + "_" + str(buildNumber) + ".tgz"
            target = str(deploy_onprem_user) + "@" + str(deploy_onprem_target) + ":/tmp/"

            logging.info("Uploading the tgz build  filename=\"{}\" to the target machine using rsync".format(filename))
            try:
                result = subprocess.run(["rsync", "-a", "-v", os.path.join(output_dir, filename), target], capture_output=True)
                logging.info("ksconf results.stdout=\"{}\"".format(result.stdout))
                logging.info("ksconf results.stderr=\"{}\"".format(result.stderr))
            except Exception as e:
                logging.error("error encountered while attempted to run rsync, exception=\"{}\"".format(str(e)))

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
