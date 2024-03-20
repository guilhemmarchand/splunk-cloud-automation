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
from logging.handlers import RotatingFileHandler
import base64

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
logger = logging.getLogger(__name__)
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/toolbox_rest_api.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append libs
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-splk-toolbox", "lib"))

# import rest handler
import toolbox_rest_handler

# import toolbox libs
from libs_toolbox import cd, create_tarfile_excluding_large_files

# import SDK client
import splunklib.client as client


class ToolboxExport_v1(toolbox_rest_handler.RESTHandler):

    def __init__(self, command_line, command_arg):
        super(ToolboxExport_v1, self).__init__(command_line, command_arg, logger)

    def get_test_endpoint(self, request_info, **kwargs):

        response = {
            "resource_endpoint": "test_endpoint",
            "resource_response": "Welcome. Good to see you.",
        }

        return {"payload": response, "status": 200}

    def post_export_app(self, request_info, **kwargs):

        # init
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if str(describe).lower() in ("true", "t"):
                    describe = True
            except Exception as e:
                describe = False
            if not describe:

                # app
                try:
                    app_target = resp_dict["app"]
                except Exception as e:
                    msg = "app argument is mandatory"
                    logging.error(msg)
                    return {
                        "payload": {
                            "action": "failure",
                            "response": msg,
                        },
                        "status": 500,
                    }

                # exclude_large_files, if not provided, defaults to True
                try:
                    exclude_large_files = resp_dict["exclude_large_files"]
                    if str(exclude_large_files).lower() in ("true", "t"):
                        exclude_large_files = True
                    else:
                        exclude_large_files = False
                except Exception as e:
                    exclude_large_files = True

                # large_file_size, if not provided, defaults to 100MB
                try:
                    large_file_size = int(resp_dict["large_file_size"])
                except Exception as e:
                    large_file_size = 100

        else:
            # body is required in this endpoint, if not submitted describe the usage
            describe = True

        if describe:

            response = {
                "describe": "This endpoint exports the content of a Splunk application and returns the compressed tgz binary",
                "options": [
                    {
                        "app": "The application to be exported",
                        "exclude_large_files": "Exclude large files from the export, True or False. Defaults to True",
                        "large_file_size": "The size in MB to consider a file as large. Defaults to 100MB",
                    }
                ],
            }

            return {"payload": response, "status": 200}

        # Get splunkd port
        entity = splunk.entity.getEntity(
            "/server",
            "settings",
            namespace="TA-splk-toolbox",
            sessionKey=request_info.session_key,
            owner="-",
        )
        splunkd_port = entity["mgmtHostPort"]

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-splk-toolbox",
            port=splunkd_port,
            token=request_info.session_key,
        )

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_splk_toolbox_settings"
        confs = service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        #
        # Program start
        #

        output_dir = os.path.join(splunkhome, "etc", "apps", "TA-splk-toolbox")
        if not os.path.isdir(output_dir):
            try:
                os.mkdir(output_dir)
            except Exception as e:
                logging.error(
                    'failed to create output_dir="{}", exception="{}"'.format(
                        output_dir, str(e)
                    )
                )
                return {
                    "payload": {
                        "action": "failure",
                        "response": 'failed to create output_dir="{}", exception="{}"'.format(
                            output_dir, str(e)
                        ),
                    },
                    "status": 200,
                }

        # Retrieve the list apps, get version and create a dict for later usage
        apps = []
        apps_dict = {}
        for app in service.apps:
            apps.append(app.name)
            try:
                app_version = app.version
                logging.debug(
                    'app.name="{}", app.version="{}"'.format(app.name, app.version)
                )
            except Exception as e:
                app_version = "1.0.0"
            apps_dict[app.name] = {"version": app_version}
        logging.debug('apps_dict="{}"'.format(json.dumps(apps_dict, indent=2)))

        # Check that the requested app is available
        if not app_target in apps:
            return {
                "payload": {
                    "action": "failure",
                    "response": 'The requested app="{}" is not available'.format(
                        app_target
                    ),
                    "available_apps": apps,
                },
                "status": 500,
            }

        # set the version_short reference
        app_target_versionshort = apps_dict[app_target].get("version").replace(".", "")

        # set the tar file name
        tar_name = f"{app_target}_v{app_target_versionshort}.tgz"

        # create the tar file
        tar_file = os.path.join(output_dir, tar_name)
        app_directory = os.path.join(splunkhome, "etc", "apps", app_target)

        try:
            excluded_files = create_tarfile_excluding_large_files(
                app_directory=app_directory,
                tar_file=tar_file,
                exclude_large_files=True,
                large_file_size_mb=large_file_size,
            )
        except Exception as e:
            logging.error(
                'failed to create tar_file="{}", exception="{}"'.format(
                    tar_file, str(e)
                )
            )
            return {
                "payload": {
                    "action": "failure",
                    "response": 'failed to create tar_file="{}", exception="{}"'.format(
                        tar_file, str(e)
                    ),
                },
                "status": 500,
            }

        # load the tgz
        with open(tar_file, "rb") as f:
            data = f.read()

        # convert to base64
        data = base64.b64encode(data)

        # Ensure the base64-encoded data is decoded to a UTF-8 string properly for JSON serialization
        base64_string = data.decode("utf-8")

        # the package is not needed anymore
        if os.path.isfile(tar_file):
            try:
                os.remove(tar_file)
            except Exception as e:
                logging.error(
                    f'Could not remove the generated file="{tar_file}", exception="{e}"'
                )

        # render the response
        response = {
            "base64": base64_string,
            "app": app_target,
            "version": apps_dict[app_target].get("version"),
            "filename": tar_name,
            "excluded_files": excluded_files,
            "result": "The package is now ready in base64.",
        }

        return {"payload": response, "status": 200}
