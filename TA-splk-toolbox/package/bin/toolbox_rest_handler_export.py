from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "toolbox_rest_handler_export.py"
__author__ = "Guilhem Marchand"

import logging
import os, sys
import splunk
import splunk.entity
import splunk.Intersplunk
import json
import logging
import tarfile
import base64

splunkhome = os.environ['SPLUNK_HOME']

# set logging
logger = logging.getLogger(__name__)
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/toolbox_rest_api.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append libs
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-splk-toolbox', 'lib'))

# import rest handler
import toolbox_rest_handler

# import toolbox libs
from libs_toolbox import cd

# import SDK client
import splunklib.client as client

class ToolboxExport_v1(toolbox_rest_handler.RESTHandler):


    def __init__(self, command_line, command_arg):
        super(ToolboxExport_v1, self).__init__(command_line, command_arg, logger)


    def get_test_endpoint(self, request_info, **kwargs):

        response = {
            'resource_endpoint': 'test_endpoint',
            'resource_response': 'Welcome. Good to see you.', 
        }

        return {
            "payload": response,
            'status': 200
        }
    
    def post_export_app(self, request_info, **kwargs):

        # init
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args['payload']))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict['describe']
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
            if not describe:
                try:
                    app_target = resp_dict['app']
                except Exception as e:
                    msg = 'app argument is mandatory'
                    logging.error(msg)
                    return {
                        "payload": {
                            'action': 'failure',
                            'response': msg,
                        },
                        'status': 500
                    }

        else:
            # body is required in this endpoint, if not submitted describe the usage
            describe = True

        if describe:

            response = {
                "describe": "This endpoint exports the content of a Splunk application and returns the compressed tgz binary",
                "options" : [ {
                    "app": "The application to be exported",
                    } ] 
                }

            return {
                "payload": response,
                'status': 200
            }

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                            namespace='TA-splk-toolbox', sessionKey=request_info.session_key, owner='-')
        splunkd_port = entity['mgmtHostPort']

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-splk-toolbox",
            port=splunkd_port,
            token=request_info.session_key
        )

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_splk_toolbox_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        #
        # Program start
        #

        output_dir = os.path.join(splunkhome, 'etc', 'apps', 'TA-splk-toolbox')
        if not os.path.isdir(output_dir):
            try:
                os.mkdir(output_dir)
            except Exception as e:
                logging.error('failed to create output_dir=\"{}\", exception=\"{}\"'.format(output_dir, str(e)))
                return {
                    "payload": {
                        'action': 'failure',
                        'response': 'failed to create output_dir=\"{}\", exception=\"{}\"'.format(output_dir, str(e)),
                    },
                    'status': 200
                }
            
        # Retrieve the list apps, get version and create a dict for later usage
        apps = []
        apps_dict = {}
        for app in service.apps:
            apps.append(app.name)
            try:
                app_version = app.version
                logging.debug("app.name=\"{}\", app.version=\"{}\"".format(app.name, app.version))
            except Exception as e:
                app_version = "1.0.0"
            apps_dict[app.name] = {'version': app_version}
        logging.debug("apps_dict=\"{}\"".format(json.dumps(apps_dict, indent=2)))

        # Check that the requested app is available
        if not app_target in apps:
            return {
                "payload": {
                    'action': 'failure',
                    'response': 'The requested app=\"{}\" is not available'.format(app_target),
                    'available_apps': apps,
                },
                'status': 500
            }

        # set the version_short reference
        app_target_versionshort = apps_dict[app_target].get('version').replace(".", "")

        # set the tar file name
        tar_name = str(app_target) + '_v' + str(app_target_versionshort) + '.tgz'

        # create the tar file
        tar_file = os.path.join(output_dir, tar_name)
        logging.info("Creating compress tgz, filename=\"{}\"".format(tar_file))

        out = tarfile.open(tar_file, mode='w:gz')

        with cd(os.path.join(splunkhome, 'etc', 'apps')):
            try:
                out.add(str(app_target))
            except Exception as e:
                logging.error("appID=\"{}\", archive file=\"{}\" creation failed".format(app_target, tar_file))
                return {
                    "payload": {
                        'action': 'failure',
                        'response': 'The requested app=\"{}\" is not available'.format(app_target),
                        'exception': str(e),
                    },
                    'status': 500
                }

            finally:
                logging.info('"appID=\"{}\", Achive tar file creation, archive_file=\"{}\"'.format(app_target, tar_file))
                out.close()

        # load the tgz
        with open(tar_file,"rb") as f:
            data = f.read()

        # convert to base64
        data = base64.b64encode(data)

        # the package is not needed anymore
        if os.path.isfile(tar_file):
            try:
                os.remove(tar_file)
            except Exception as e:
                logging.error("Could not remove the generated file=\"{}\", exception=\"{}\"".format(tar_file, str(e)))

        # render the response
        response = {
            'base64': str(data),
            'app': app_target,
            'version': apps_dict[app_target].get('version'),
            'filename': tar_name,
            'result': 'The package is now ready in base64.', 
        }

        return {
            "payload": response,
            'status': 200
        }
