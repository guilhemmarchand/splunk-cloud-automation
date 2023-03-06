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

### Example of build

Using the following AppConfig.json and for the example of the Splunk_TA_windows:

```json
{
  "appAuthor": "My Company",
  "appID": "org_Splunk_TA_windows",
  "appLabel": "Splunk Add-on for Microsoft Windows",
  "appDescription": "Splunk Add-on for Microsoft Windows",
  "appMerge": "True",
  "appSource": "Splunk_TA_windows",
  "appVersion": "8.6.0",
  "configFilesDenied": ["inputs.conf", "wmi.conf", "eventgen.conf"],
  "configAllowViews": "True",
  "configAllowAlerts": "True"
}
```

You can generate the build calling:

```shell
deploy.py --appdir Splunk_TA_windows
```

The backend will parse the package and the options, to finally generate the release and its artifacts in the output directory:

```shell
output/
        build.txt
        org_Splunk_TA_windows_v<version_number>_<build_number>.tgz
        version.txt
```

You can use the '--keep' option if you want to keep the extracted directory in the output directory:

```shell
deploy.py --appdir Splunk_TA_windows --keep
```

In such a case, we will have:

```shell
output/
        build.txt
        org_Splunk_TA_windows_v<version_number>_<build_number>
        org_Splunk_TA_windows_v<version_number>_<build_number>.tgz
        version.txt
```

Should we want to submit the application release for Appinspect vetting for the purposes of Splunk Cloud, you would:

```shell
python3 deploy.py --appdir Splunk_TA_windows --submitappinspect --userappinspect 'my_user' --passappinspect 'my_password'
```

If the App vetting is passed, the backend outputs the results, downloads the artifacts as well as exit with a 0 exit code.
If the App vetting fails for some reasons, it will exist with exit code 1.

```shell
2023-03-06 12:06:43 xxxxxxxxxx root[41121] INFO "appID="org_Splunk_TA_windows", Achive tar file creation, archive_file="org_Splunk_TA_windows_v860_3797097781.tgz"
2023-03-06 12:06:45 xxxxxxxxxx root[41121] INFO Appsinspect: successfully logged in Appinspect API
2023-03-06 12:06:45 xxxxxxxxxx root[41121] INFO Submitting to Appinspect API="org_Splunk_TA_windows_v860_3797097781.tgz"
2023-03-06 12:06:57 xxxxxxxxxx root[41121] INFO Appinspect request_id="13d333b0-94e8-49f4-b542-774f0344e14e" was successfully processed
2023-03-06 12:06:58 xxxxxxxxxx root[41121] INFO Appinspect written to report="report_appinspect.html"
2023-03-06 12:06:59 xxxxxxxxxx root[41121] INFO Appinspect written to report="report_appinspect.json"
2023-03-06 12:06:59 xxxxxxxxxx root[41121] INFO Appinspect request_id="13d333b0-94e8-49f4-b542-774f0344e14e" was successfully vetted, summary="{
    "error": 0,
    "failure": 0,
    "skipped": 0,
    "manual_check": 1,
    "not_applicable": 90,
    "warning": 5,
    "success": 127
}"
```

Appinspect artifacts:

```shell
output/
        report_appinspect.html
        report_appinspect.json
```

## Private application management

Similarly, the tool can be used to package, vet and deploy fully private Splunk applications.

Example, we have the following private app:

```shell
TA-org-customapp
                /local/
                        props.conf
                        xxx.conf
                /metadata
```

With the following AppConfig.json:

```json
{
  "appAuthor": "My Company",
  "appID": "TA-org-customapp",
  "appLabel": "Splunk Add-on of mine",
  "appDescription": "Splunk Add-on of mine",
  "appMerge": "False",
  "appSource": "TA-org-customapp",
  "appVersion": "1.0.0"
}
```

In this case, the proces is simplier as we do not need to merge configuration from a third part app, however we would still merge configuration if we have both a default and local directory with conflicting configuration files.

To build and submit to Appinspect

```shell
python3 deploy.py --appdir TA-org-customapp --submitappinspect --userappinspect 'my_user' --passappinspect 'my_password'
```
