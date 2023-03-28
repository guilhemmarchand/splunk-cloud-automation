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
import re
import time
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome + "/var/log/splunk/massexecutor4csvgen.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s')
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'TA-splk-toolbox', 'lib'))

# import Splunk libs
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import splunklib.client as client
import splunklib.results as results

@Configuration(distributed=False)

class MassExector4CsvGen(GeneratingCommand):

    '''
    This generating command takes a savedsearch in input, we expect a field called spl which contains one or more searches to be executed
    '''

    savedsearch_name = Option(
        doc='''
        **Syntax:** **savedsearch_name=****
        **Description:** value for savedsearch_name.''',
        require=True, default=None, validate=validators.Match("savedsearch_name", r"^.*"))

    simulate = Option(
        doc='''
        **Syntax:** **simulate=****
        **Description:** value for simulate.''',
       require=False, default=False, validate=validators.Match("simulate", r"^.*"))

    earliest = Option(
        doc='''
        **Syntax:** **earliest=****
        **Description:** value for earliest.''',
       require=False, default="@d", validate=validators.Match("earliest", r"^.*"))

    latest = Option(
        doc='''
        **Syntax:** **latest=****
        **Description:** value for latest.''',
       require=False, default="now", validate=validators.Match("latest", r"^.*"))

    def generate(self, **kwargs):

        # set loglevel
        loglevel = 'INFO'
        conf_file = "ta_splk_toolbox_settings"
        confs = self.service.confs[str(conf_file)]
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)

        # Get the session key
        session_key = self._metadata.searchinfo.session_key

        # Get splunkd port
        entity = splunk.entity.getEntity('/server', 'settings',
                                            namespace='TA-splk-toolbox', sessionKey=session_key, owner='-')
        splunkd_port = entity['mgmtHostPort']
    
        # local service
        service = client.connect(
            token=str(session_key),
            owner="nobody",
            app="TA-splk-toolbox",
            host="localhost",
            port=splunkd_port
        )

        # Define the query
        search = "| savedsearch \"" + str(self.savedsearch_name) + "\""

        kwargs_oneshot = {
                            "earliest_time": self.earliest,
                            "latest_time": self.latest,
                            "output_mode": "json",
                        }

        logging.debug("search=\"{}\"".format(search))

        # An empty list to contain the list of SPL statement to be executed
        massexec_list = []

        # run the main report, every result is a Splunk search to be executed on its own thread        
        try:

            oneshotsearch_results = service.jobs.oneshot(search, **kwargs_oneshot)
            reader = results.JSONResultsReader(oneshotsearch_results)

            for item in reader:

                if isinstance(item, dict):

                    try:

                        entity_dict = {
                            'index': item.get("index"),
                            'sourcetype': item.get("sourcetype"),
                            'source': item.get("source"),
                            'csv_app': item.get("csv_app"),
                            'csv_lookup_file': item.get("csv_lookup_file"),
                            'spl': item.get('spl'),
                        }

                        massexec_list.append(entity_dict)
                        logging.info("Adding a new SPL statement for execution, entity=\"{}\"".format(json.dumps(massexec_list, indent=2)))

                    except Exception as e:
                        logging.error("An exception was encountered, exception=\"{}\"".format(str(e)))

        except Exception as e:
            logging.error("failed to call the custom command with exception=\"{}\"".format(str(e)))
            raise ValueError("failed to call the custom command with exception=\"{}\"".format(str(e)))

        # Act
        if massexec_list:

            # log
            logging.info("massexec_list=\"{}\"".format(massexec_list, indent=2))

            # Mass loop and execute
            for massexec_entity in massexec_list:

                # perf tracker
                run_start = float(time.time())

                # get the spl
                spl_statement = massexec_entity.get('spl')

                # searches need to explicitely start with search
                if not re.search(r'\|\s?tstats', spl_statement) and not spl_statement.startswith('search'):            
                    spl_statement = "search " + str(spl_statement)
                    massexec_entity['spl'] = spl_statement

                # if run
                if not self.simulate == 'True':

                    logging.info("Attempting to execute query=\"{}\"".format(spl_statement))

                    # run
                    try:

                        oneshotsearch_results = service.jobs.oneshot(spl_statement, **kwargs_oneshot)
                        reader = results.JSONResultsReader(oneshotsearch_results)

                        for item in reader:

                            if isinstance(item, dict):

                                # add results to our entity
                                massexec_entity['results'] = item

                                # runtime
                                massexec_entity['runtime'] = round(float(time.time()) - float(run_start), 3)

                                # earliest and latest
                                massexec_entity['earliest'] = self.earliest
                                massexec_entity['latest'] = self.latest

                                yield {
                                    '_time': time.time(),
                                    '_raw': massexec_entity,
                                }

                    except Exception as e:
                        logging.error("failed to call the custom command with exception=\"{}\"".format(str(e)))
                        raise ValueError("failed to call the custom command with exception=\"{}\"".format(str(e)))

                else:

                    # simulation
                    massexec_entity['simulation'] = self.simulate

                    logging.info("simuation mode is enabled, yield entity=\"{}\"".format(json.dumps(massexec_entity, indent=2)))

                    yield {
                        '_time': time.time(),
                        '_raw': massexec_entity,
                    }

        else:

            yield {
                '_time': time.time(),
                '_raw': {
                    'result': 'success',
                    'response': 'the upstream report did not return any results, likely nothing to do right now.',
                    'report': self.savedsearch_name,
                    'earliest': self.earliest,
                    'latest': self.latest,
                },
            }

dispatch(MassExector4CsvGen, sys.argv, sys.stdin, sys.stdout, __name__)
