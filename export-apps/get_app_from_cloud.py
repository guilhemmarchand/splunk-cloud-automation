from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "get_app_from_sc.py"
__author__ = "Guilhem Marchand"

import logging
import os, sys
import requests
from requests.auth import HTTPBasicAuth
import json
import coloredlogs, logging
import base64
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Args
parser = argparse.ArgumentParser()
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--target_url', dest='target_url')
parser.add_argument('--username', dest='username')
parser.add_argument('--password', dest='password')
parser.add_argument('--app', dest='app')

parser.set_defaults(debug=False)
parser.set_defaults(keep=False)
parser.set_defaults(submitappinspect=False)
args = parser.parse_args()

# Set debug boolean
if args.debug:
    debug = True
else:
    debug = False

#
# main arguments
#

if args.username:
    username = args.username
else:
    username = False

if args.password:
    password = args.password
else:
    password = False

if args.target_url:
    target_url = args.target_url
else:
    target_url = False

if args.app:
    app = args.app
else:
    app = False    

# set logging
root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

# coloredlogs
coloredlogs.install(isatty=True, level='INFO', logger=logging.getLogger())

if debug:
    root.setLevel(logging.DEBUG)
    handler.setLevel(logging.DEBUG)
else:
    root.setLevel(logging.INFO)
    handler.setLevel(logging.INFO)

# check args
if not username or not password or not target_url:
    logging.error('arguments username, password, target_url, app must be set')
    sys.exit(1)

# set url
url = str(target_url) + '/services/toolbox/v1/export/export_app'

# set record
record = {
    'app': app,
}

# run request
logging.info("attempting to retrieve app=\"{}\" from target_url=\"{}\"".format(app, target_url))

try:
    response = requests.post(url, auth = HTTPBasicAuth(username, password), data=json.dumps(record),
                            verify=False)
    if response.status_code not in (200, 201, 204):
        logging.error(
            'request has failed!. url={}, data={}, HTTP Error={}, '
            'content={}'.format(url, record, response.status_code, response.text))
    else:

        # load the response in a dict
        response_json = json.loads(response.text)
        logging.debug("response=\"{}\"".format(json.dumps(response_json, indent=2)))           

except Exception as e:
    logging.error("failed to process the request, exception=\"{}\"".format(str(e)))

# load our items
base64_bytesdata = response_json.get('base64')
version_data = response_json.get('version')
filename_data = response_json.get('filename')

# get rid of pseudo bytes litteral, there should be a better way to do that
base64_bytesdata = base64_bytesdata.replace('b\'', '')
base64_bytesdata = base64_bytesdata[:-1]

# dedcode base64
base64_bytesdata = base64.b64decode(base64_bytesdata)

# finally, attempt to write
try:
    with open(filename_data, 'wb') as f:
        f.write(base64_bytesdata)
        logging.info("successfully imported app=\"{}\", version=\"{}\" , tarfile=\"{}\"".format(app, version_data, filename_data))
    sys.exit(1)

except Exception as e:
    logging.error("failed to export app=\"{}\", version=\"{}\" , tarfile=\"{}\"".format(app, version_data, filename_data, str(e)))
    sys.exit(1)
