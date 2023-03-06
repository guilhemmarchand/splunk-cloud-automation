# Purpose

The purpose of this tool is to build and manage Splunk applications for Splunk Cloud deployment, with the following concepts:

- Maintaining local configuration for third party public applications (such as Splunk Base Addons)
- Maintaining fully custom private apps

This Python tool allows to:

- merge configuration using ksconf, such as merging local knowledge objects into a final package that can be vetted and published to Splunk Cloud
- Authenticating and submit for Appinspect vetting, downloading results artifacts (Splunk Appinspect reports)
- Deploying to Splunk Cloud using Splunk ACS API in a Pythonic fashion with error handling

## Third party application merging

The concept is the following:

- A main directory represents the Git repository, for instance "Splunk_TA_windows"
- Within this directory, we will find this structure:

```shell
Splunk_TA_windows/<app content>
org_Splunk_TA_windows/
                      local/
                            props.conf
                            transforms.conf
                            ...
AppConfig.json
```

### AppConfig.json

The file AppConfig.json will be used to define the operations as needed, the following can be implemented:

```json
{
  "appAuthor": "My Company",
  "appID": "org_Splunk_TA_windows",
  "appLabel": "Splunk Add-on for Microsoft Windows",
  "appDescription": "Splunk Add-on for Microsoft Windows",
  "appMerge": "True",
  "appSource": "Splunk_TA_windows",
  "appVersion": "8.6.0"
}
```

- appAuthor: appears as the author of the application in Splunk
- appID: the application ID to be generated, it should differ from appSource and represents the final package the Python tool will create
- appLabel: the label for the Splunk app
- appDescription: the application description
- appMerge: expects True | False, in the concept of merging, this should be defined to True and will instruct that we actually want to merge the AppSource content with the third party content and produce a final application to be deployed
- appVersion: the version of the application to be created

#### Additional options

There are additional options that can be set in AppConfig.json:

- configFilesAuthorized: An optional array listing the Splunk configuration files that are allowed to be merged and generated, example:

```json
  "configFilesAuthorized": ["props.conf", "transforms.conf"],
```

In this case, the Python backend will only consider these config files, anything else will be excluded.

- configFilesDenied: An optional array listing Splunk configuration files which should be ignored, example:

```json
  "configFilesDenied": ["inputs.conf"],
```

On the opposite, you can specific a list of configuration files that will never be considered. (for instance inputs.conf, wmi.conf, eventgen.conf, and so forth)

- configAllowViews: True | False - this allows or prevents Splunk views (dashboards, etc) to be generated as part of the final package, in the use case of pure parsing TAs for instance, it may make sense to exclude any kind of views as there aren't generally of a great value in the end:

```json
  "configAllowViews": "True",
```

- configAllowAlerts: True | False - this allows or prevents Splunk alert actions, if any, to be part of the final package:

```json
  "configAllowAlerts": "True",
```
