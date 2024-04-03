# Purpose

The purpose of this tool is to build and manage Splunk applications for Splunk Cloud deployment, with the following concepts:

- Maintaining local configuration for third party public applications (such as Splunk Base Addons)
- Maintaining fully custom private apps

This Python tool allows to:

- merge configuration using ksconf, such as merging local knowledge objects into a final package that can be vetted and published to Splunk Cloud
- Authenticating and submit for Appinspect vetting, downloading results artifacts (Splunk Appinspect reports)
- Deploying to Splunk Cloud using Splunk ACS API in a Pythonic fashion with error handling

# Requirements

The Python backend requires the following packages which can be installed using pip:

- ksconf
- coloredlogs

## Maintaining Splunk Base applications in your Splunk Cloud stack

When it comes to Splunk Base applications, Splunk Cloud allows you to install and update through Splunk Web, or via Splunk ACS API.

While it can be convenient for quick wins, using Splunk Web is far from being flexible, shows outdated information regarding the releases available, and is really tedious to deal with at scale.

Instead, using the ACS API is really a much better, much safer and reliable way of maintaining Splunk Base application in your Splunk Cloud stack!

The concept is the following:

- You maintain a list of Splunk applications in a JSON reference file, with basic information such as the Splunk Base ID and the requested version.
- When calling the backend, it will verify for each application if it is already deployed and the version that is currently deployed.
- Depending on the use cases, it will either upgrade or ensure to maintain the request version by upgrading or downgrading, if necessary.

JSON Content (splunkbase_apps_dict.json):

```json
[
  {
    "name": "trackme",
    "splunkbaseID": 4621,
    "licenseAck": "https://docs.trackme-solutions.com/license.html",
    "version": "2.0.87"
  },
  {
    "name": "Splunk_SA_CIM",
    "splunkbaseID": 1621,
    "licenseAck": "https://www.splunk.com/en_us/legal/splunk-general-terms.html",
    "version": "5.3.1"
  }
]
```

Then, your CI/CD (or yourself manually) can run the logic in a single command:

```shell

export stack="your_stack"
export tokenacs="your_acs_token"
export usersplunkbase="your_splunk_base_login"
export passsplunkbase="your_splunk_base_password"

python deploy_splunkbase_app.py --apps_dict_json splunkbase_apps_dict.json --mode live --usersplunkbase $usersplunkbase --passsplunkbase $passsplunkbase --stack $stack --tokenacs $tokenacs

```

Note: you can run in mode="simulation" to review what the backend will do.

Result execution example:

```shell
2024-04-03 12:07:52 Guilhems-Mac.local root[58606] INFO SplunkBase: successfully logged in SplunkBase API
2024-04-03 12:07:52 Guilhems-Mac.local root[58606] INFO Authentication to Splunk API using bearer auth
2024-04-03 12:07:54 Guilhems-Mac.local root[58606] INFO inspecting app="trackme", id="4621"
2024-04-03 12:07:54 Guilhems-Mac.local root[58606] INFO app="trackme", appId="4621", nothing to do, version="2.0.87" matches requested version="2.0.87"
2024-04-03 12:07:54 Guilhems-Mac.local root[58606] INFO inspecting app="Splunk_SA_CIM", id="1621"
2024-04-03 12:07:54 Guilhems-Mac.local root[58606] INFO app="Splunk_SA_CIM", appId="1621", nothing to do, version="5.3.1" matches requested version="5.3.1"
```

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

## Deploying to Splunk Cloud using Splunk ACS API

You can request the deployment to your Splunk Cloud stack by submitting with the following options:

```shell
--deployacs True --stack <Splunk Cloud stack>
```

In addition, you can choose between a username/password authentication and the creation of Ephemeral tokens, or specify a static bearrer token, both approaches are possible, the ephemeral token approach is likely safer and has some advantages.

To use ephemeral tokens:

```shell
--deployacs True --stack $stack --create_token --username '<myuser>' --password '<mypassword>' --token_audience "ACS"
```

To use a static bearrer token:

```shell
--deployacs True --stack $stack --create_token --tokenacs <bearrer token>
```
