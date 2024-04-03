#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "Guilhem Marchand"
__version__ = "0.1.0"
__status__ = "PRODUCTION"

import os
import sys
import splunk
import splunk.entity
import json
import logging
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = logging.FileHandler(
    splunkhome + "/var/log/splunk/toolbox_prettyjson.log", "a"
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-splk-toolbox", "lib"))

# import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)


@Configuration()
class PrettyJson(StreamingCommand):

    fields = Option(
        doc="""
        **Syntax:** **fields=****
        **Description:** Comma Separated list of fields to pretty print.""",
        require=False,
        default="None",
        validate=validators.Match("fields", r"^.*$"),
    )

    # status will be statically defined as imported

    def stream(self, records):

        # set loglevel
        loglevel = "INFO"
        conf_file = "ta_splk_toolbox_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == "logging":
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # convert the fields into a list
        fields_list = self.fields.split(",")

        # Loop in the results
        for record in records:

            yield_record = {}

            # loop through the fields, add to the dict record
            for k in record:

                if k in fields_list:
                    try:
                        yield_record[k] = json.dumps(json.loads(record[k]), indent=4)
                    except Exception as e:
                        logging.error(
                            'Failed to load and render the json object in field="{}"'.format(
                                k
                            )
                        )
                        yield_record[k] = record[k]

                else:
                    yield_record[k] = record[k]

            yield yield_record


dispatch(PrettyJson, sys.argv, sys.stdin, sys.stdout, __name__)
