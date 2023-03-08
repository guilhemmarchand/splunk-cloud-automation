#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Splunk"
__version__ = "0.1.0"
__maintainer__ = "Splunk"
__status__ = "PRODUCTION"

import os, sys
import json
import coloredlogs, logging
import argparse
import configparser

# load libs
sys.path.append('libs')
from tools import splunkacs_getidx, splunkacs_postidx, splunkacs_check_index, splunkacs_get_target_index, splunkacs_updateidx, \
    splunkacs_create_ephemeral_token

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--app_root', dest='app_root')
parser.add_argument('--app_dir', dest='app_dir')
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--show_idx_summary', dest='show_idx_summary')
parser.add_argument('--show_idx_full', dest='show_idx_full')
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
parser.set_defaults(submitappinspect=False)
args = parser.parse_args()

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

# Set show_idx_summary boolean
if args.show_idx_summary == 'True':
    show_idx_summary = True
else:
    show_idx_summary = False 

# Set show_idx_full boolean
if args.show_idx_full == 'True':
    show_idx_full = True
else:
    show_idx_full = False    

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

# Set app_root
if args.app_root:
    app_root = args.app_root
else:
    logging.error("--app_root <application_name> was not provided, this is mandatory.")
    sys.exit(1)

# Set app_dir
if args.app_dir:
    app_dir = args.app_dir
else:
    logging.error("--app_dir <directory_name> was not provided, this is mandatory.")
    sys.exit(1)

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

# init
stack_idx_list = []
local_idx_list = []
indexes_parsed = 0
error_count = 0
result_summary = []
indexes_creation_requested = []

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
# check requested file
#

if not os.path.isfile(os.path.join(app_root, app_dir, "indexes.conf")):
    raise Exception("Could not load not existing file=\"{}\"".format(os.path.join(app_root, app_dir, "indexes.conf")))

#
# Get indexes configuration from Splunk ACS
#

stack_dict_full = {}

try:
    stack_idx_dict = json.loads(splunkacs_getidx(stack, tokenacs, proxy_dict))

    # store the list of indexes as a list
    for record in stack_idx_dict:
        stack_idx_list.append(record.get('name'))

        stack_dict_full[record.get('name')] = {
            'maxDataSizeMB': record.get('maxDataSizeMB'),
            'searchableDays': record.get('searchableDays'),
        }

    logging.info("Splunk Cloud indexes configuration was successfully loaded")
    if show_idx_summary:
        logging.info("Splunk Cloud current indexes definition, stack_idx_list=\"{}\"".format(json.dumps(stack_idx_dict, indent=2)))
    if show_idx_full:
        logging.info("Splunk Cloud existing indexes with their parameters, stack_dict_full=\"{}\"".format(json.dumps(stack_dict_full, indent=2)))

except Exception as e:
    logging.error("An exception was encountered while attempting to retrieve indexes definition from Splunk ACS, exception=\"{}\"".format(str(e)))
    raise Exception(str(e))

#
# Read app indexes
#

# read app.conf to retrieve the current build
try:
    config = configparser.ConfigParser()
    config.read(os.path.join(app_root, app_dir, "indexes.conf"))

    # loop through the list of indexes
    for stanza in config:

        # Add the local index in the list, we will use this information a the further step
        local_idx_list.append(stanza)

        # Only allowed indexes
        if stanza not in ("DEFAULT", "default", "main", "summary", "history") and not stanza.startswith("_"):
            logging.info("checking index=\"{}\"".format(stanza))
            indexes_parsed+=1

            # Verify if the index is defined in Splunk Cloud
            idx_is_defined = False

            if stanza not in stack_idx_list:

                # Run a double verification
                try:
                    idx_is_defined = splunkacs_check_index(stack, tokenacs, stanza, proxy_dict)
                except Exception as e:
                    idx_is_defined = False

                # Request the index creation if necessary
                if not idx_is_defined:

                    logging.info("The index=\"{}\" is not currently defined in Splunk Cloud, it will be created now.".format(stanza))
                    indexes_creation_requested.append(stanza)

                    # set the definition

                    # datatype
                    try:
                        datatype = config[stanza]['datatype']
                    except Exception as e:
                        logging.info("datatype is not set, using default=event")
                        datatype = "event"

                    # searchableDays
                    try:
                        searchableDays = config[stanza]['searchableDays']
                    except Exception as e:
                        logging.info("searchableDays is not set, using default=90")
                        searchableDays = 90

                    # maxDataSizeMB
                    try:
                        maxDataSizeMB = config[stanza]['maxDataSizeMB']
                    except Exception as e:
                        logging.info("maxDataSizeMB is not set, using default=0")
                        maxDataSizeMB = 0

                    index_definition = {
                        "name": stanza,
                        "datatype": "event",
                        "maxDataSizeMB": int(maxDataSizeMB),
                        "searchableDays": int(searchableDays),
                    }

                    #
                    # create
                    #

                    try:
                        index_query_result = splunkacs_postidx(stack, tokenacs, index_definition, proxy_dict)
                        result_summary.append({
                            'index_name': stanza,
                            'requested_properties': index_definition,
                            'action': 'success',
                        })

                    except Exception as e:
                        error_count+=1
                        result_summary.append({
                            'index_name': stanza,
                            'requested_properties': index_definition,
                            'action': 'failure',
                            'exception': str(e)
                        })

                else:
                    idx_is_defined = True
                    logging.info("The index=\"{}\" is already defined, nothing to do.".format(stanza))

            else:
                idx_is_defined = True
                logging.info("The index=\"{}\" is already defined, nothing to do.".format(stanza))                

            #
            # Check configuration
            #

            # If an index is already defined, compare the Splunk Cloud verification and our configuration
            # If maxDataSizeMB / searchableDays do not match, these will be updated automatically

            if idx_is_defined:
                logging.info("retrieving the index configuration for index=\"{}\"".format(stanza))

                try:

                    # try retrieving from the dict
                    try:
                        target_index_config = stack_dict_full[stanza]
                        logging.debug("index=\"{}\", definition=\"{}\"".format(stanza, json.dumps(target_index_config, indent=2)))

                    except Exception as e:
                        logging.warning("Splunk ACS did not return the index with the global index endpoint, will have to retrieve its definition.")
                        target_index_config = None

                    # unless this failed
                    if not target_index_config:
                        target_index_config = json.loads(splunkacs_get_target_index(stack, tokenacs, stanza, proxy_dict))
                        logging.debug("index=\"{}\", definition=\"{}\"".format(stanza, json.dumps(target_index_config, indent=2)))

                    #
                    # local references
                    #

                    # searchableDays
                    try:
                        reference_searchableDays = config[stanza]['searchableDays']
                        logging.debug("reference searchableDays=\"{}\"".format(reference_searchableDays))
                    except Exception as e:
                        logging.debug("reference searchableDays is not set, using default=90")
                        reference_searchableDays = 90

                    # maxDataSizeMB
                    try:
                        reference_maxDataSizeMB = config[stanza]['maxDataSizeMB']
                        logging.debug("reference maxDataSizeMB=\"{}\"".format(reference_maxDataSizeMB))
                    except Exception as e:
                        logging.debug("reference maxDataSizeMB is not set, using default=0")
                        reference_maxDataSizeMB = 0

                    #
                    # remote references
                    #

                    # searchableDays
                    try:
                        remote_searchableDays = target_index_config['searchableDays']
                        logging.debug("remote searchableDays=\"{}\"".format(remote_searchableDays))
                    except Exception as e:
                        logging.debug("remote searchableDays is not set, using default=90")
                        remote_searchableDays = 90

                    # maxDataSizeMB
                    try:
                        remote_maxDataSizeMB = target_index_config['maxDataSizeMB']
                        logging.debug("reference maxDataSizeMB=\"{}\"".format(remote_maxDataSizeMB))
                    except Exception as e:
                        logging.debug("remote maxDataSizeMB is not set, using default=0")
                        remote_maxDataSizeMB = 0

                    # verify

                    # searchableDays
                    if int(reference_searchableDays) != int(remote_searchableDays):
                        logging.warning("index=\"{}\", reference_searchableDays=\"{}\" does not match remote_searchableDays=\"{}\", Splunk Cloud deployment will be updated".format(stanza, reference_searchableDays, remote_searchableDays))

                    # searchableDays
                    if int(reference_maxDataSizeMB) != int(remote_maxDataSizeMB):
                        logging.warning("index=\"{}\", reference_maxDataSizeMB=\"{}\" does not match remote_maxDataSizeMB=\"{}\", Splunk Cloud deployment will be updated".format(stanza, reference_maxDataSizeMB, remote_maxDataSizeMB))

                    # Update
                    if ( int(reference_searchableDays) != int(remote_searchableDays) ) or ( int(reference_maxDataSizeMB) != int(remote_maxDataSizeMB) ):

                        index_definition = {
                            "searchableDays": int(reference_searchableDays),
                            "maxDataSizeMB": int(reference_maxDataSizeMB),
                        }

                        try:
                            update_index_result = splunkacs_updateidx(stack, tokenacs, stanza, index_definition, proxy_dict)
                            logging.info("index=\"{}\" was successfully updated with definition=\"{}\"".format(stanza, json.dumps(index_definition, indent=2)))
                            result_summary.append({
                                'index_name': stanza,
                                'requested_properties': index_definition,
                                'action': 'success',
                                'change': 'update',
                            })
                        except Exception as e:
                            error_count+=1
                            result_summary.append({
                                'index_name': stanza,
                                'requested_properties': index_definition,
                                'action': 'failure',
                                'change': 'update',
                                'exception': str(e)
                            })

                except Exception as e:
                    error_count+=1
                    logging.error("Failed to retrieve the configuration for this index, exception=\"{}\"".format(str(e)))

    # Verify if we have indexes defined on the remote stack which are defined on the local indexes.conf
    # Shall this be the case, generate an error message (but do not fail the job)
    for remote_idx in stack_idx_list:
        if not remote_idx in local_idx_list and remote_idx not in ("DEFAULT", "default", "main", "summary", "history", "splunklogger", "audit_summary", "cim_modactions", "endpoint_summary", "gia_summary", "ioc", "lastchanceindex", "notable", "notable_summary", "risk", "sequenced_events", "threat_activity", "ubaroute", "ueba", "whois") and not stanza.startswith("_"):
            logging.error("The index=\"{}\" is defined on the Splunk Cloud stack but defined in the local indexes.conf configuration file, add this index in indexes.conf to suppress this message.".format(remote_idx))

    #
    # end
    #

    # if we had error encountered
    if error_count>0:
        logging.info("Splunk Cloud deployment is now terminated, number of indexes parsed=\"{}\", number of indexes creation requested=\"{}\", errors were encountered and this job will marked in failure, result_summary=\"{}\"".format(indexes_parsed, len(indexes_creation_requested), json.dumps(result_summary, indent=2)))
        sys.exit(1)
    else:
        logging.info("Splunk Cloud deployment is now terminated, number of indexes parsed=\"{}\", number of indexes creation requested=\"{}\", no errors were reported, result_summary=\"{}\"".format(indexes_parsed, len(indexes_creation_requested), json.dumps(result_summary, indent=2)))

except Exception as e:
    logging.error("Deployment has failed, exception=\"{}\"".format(str(e)))
    sys.exit(1)
