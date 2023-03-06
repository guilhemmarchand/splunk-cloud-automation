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
