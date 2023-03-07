# Splunk Cloud Export/Import Application and its content via REST API

## Introduction

The purpose of this solution is to allow exporting a whole Splunk application, including default and local knowledge objects (dashboards, props...), lookups and anything that is actually composing the Splunk Cloud app.

**For this, we rely on a Splunk Application which is hosted in the following repository:**

- https://github.com/guilhemmarchand/TA-splk-toolbox

**The concept can be described in the main big steps:**

_From the API perspective_:

- The TA-splk-toolbox is deployed to the Splunk Cloud stack using self cloud services (the app obviously passed Appinspect)
- Once deployed, the application exposes a REST API endpoint through splunkd, this means on a the requester side (from where you are going to call this endpoint), you need access to splunkd API (checkout your allowlist IPs in Splunk Cloud)
- When called, the API endpoint will package the Splunk application into a compressed tarball archived in a local directory of the application name space, and it will encode it in a base64 litteral, as well as additional Metadata (the expected file name, the exact version as it is running on the Search Head)
- Finally, the API endpoint returns a JSON payload which the base64 encoded data representing the content of the Splunk Application stored in a compressed tar ball

_From the requester perspective:_

- Now the requester, this is basically where you can going to call the REST API endpoint, a Linux/Mac based instance which likely would be part of your CI/CD environment
- We will leverage Python as well as additional tooling (ksconf)
- Python will use the requests module to call the API endpoint, retrieve the JSON payload and decode the base64 bytes litteral
- At this stage, the compressed tar ball is ready and at the exact image of the Splunk Cloud Search Head
- It is extracted locally, and optionally we will call ksconf to promote knowledge objects and views (as well as permissions if you wish to do so), and finally we repackage this into a brand new compressed tarball archive
- Last but not least, you can optionally submit this new package to Appinspect in Python to get the app vetting statement

## Requirements

The Python backend requires the following Python modules

- coloredlogs
- ksconf

You can easily install these using pip:

```shell
python3 -m pip install coloredlogs
python3 -m pip install ksconf
```

ksconf may require you to source your profile before the ksconf command is available, check:

```shell
which ksconf
```

If this doesn't return the command, exit your terminal and reconnect.
