# Splunk Cloud Export/Import Application and its content via REST API

## Introduction

The purpose of this solution is to allow exporting a whole Splunk application, including default and local knowledge objects (dashboards, props...), lookups and anything that is actually composing the Splunk Cloud app.

**For this, we rely on a Splunk Application which is hosted in the following repository:**

- https://github.com/guilhemmarchand/splunk-cloud-automation/tree/main/TA-splk-toolbox

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

## debug

_To operate in debug mode, add:_

```shell
--debug
```

## proxy

_To operate with a proxy, set:_

```shell
--useproxy --proxy_url <myproxy> --proxy_port 8080
```

_If the proxy requires authentication:_

```shell
--useproxy --proxy_url <myproxy> --proxy_port 8080 --proxy_username <my_proxy_user> --proxy_password <my_proxy_password>
```

### Run time

Let's export some variables to make our life easier, we will export:

- stack: the name of your Splunk Cloud stack
- userappinspect: your splunk.com username, for the purposes of Appinspect vetting
- passappinspect: the password associated with your account
- token: the bearer token value if you wish to connect to the splunkd API using a bearrer token
- username and password if wish to authenticate against splunkd API using basic authentication instead

```shell
export stack='mystack'
export userappinspect='myuser'
export passappinspect='mypass'
```

Then either:

```shell
export token='my_bearrer_token'
```

Or:

```shell
export username='my_splunk_username'
export password='mypass'
```

Let's test the connectivity first:

_basic authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode basic --username $username --password $password --target_url "https://$stack.splunkcloud.com:8089" --test
```

_bearrer authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode token --token $token --target_url "https://$stack.splunkcloud.com:8089" --test
```

_In both cases, you expect the following answer:_

```shell
2023-03-08 09:36:07 xxxxxx root[80736] INFO response="{
  "resource_endpoint": "test_endpoint",
  "resource_response": "Welcome. Good to see you."
}"
```

#### Exporting an application

Now, let's export an application, we are going to use the argument run_build = False for a first execution, this means we that want to extract the application from the Splunk Cloud stack, unarchive locally and stop.

In this case, we are not going to use ksconf to merge local objects to default for now:

_basic authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode basic --username $username --password $password --target_url "https://$stack.splunkcloud.com:8089" --app TA-org-customapp --run_build False
```

_bearrer authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode token --token $token --target_url "https://$stack.splunkcloud.com:8089" --app TA-org-customapp --run_build False
```

If there are no local objects, and if the application exists, you will get an answer like:

```shell
2023-03-08 09:56:16 xxxxxxxxxx root[82481] INFO attempting to retrieve app="TA-org-customapp" from target_url="https://scde-dda6bndfb28rkta02.splunkcloud.com:8089"
2023-03-08 09:56:17 xxxxxxxxxx root[82481] INFO successfully imported app="TA-org-customapp", version="1.0.0" , tarfile="TA-org-customapp_v100.tgz"
2023-03-08 09:56:17 xxxxxxxxxx root[82481] INFO successfully extracted compressed archive="TA-org-customapp_v100.tgz" into directory="TA-org-customapp"
2023-03-08 09:56:17 xxxxxxxxxx root[82481] INFO purging metadata/local.metadata
2023-03-08 09:56:17 xxxxxxxxxx root[82481] INFO there are no local objects to be promoted, the compressed file="TA-org-customapp_v100.tgz" is ready to be used
```

If there are local objects, and the application exists, you will get the following answer:

```shell
2023-03-08 09:58:47 xxxxxxxxxx root[82724] INFO attempting to retrieve app="TA-org-customapp" from target_url="https://scde-dda6bndfb28rkta02.splunkcloud.com:8089"
2023-03-08 09:58:47 xxxxxxxxxx root[82724] INFO successfully imported app="TA-org-customapp", version="1.0.0" , tarfile="TA-org-customapp_v100.tgz"
2023-03-08 09:58:47 xxxxxxxxxx root[82724] INFO successfully extracted compressed archive="TA-org-customapp_v100.tgz" into directory="TA-org-customapp"
```

If the app does not exist, you will get:

```shell
2023-03-08 10:00:33 xxxxxxxxxx root[82890] INFO attempting to retrieve app="TA-org-custombad" from target_url="https://scde-dda6bndfb28rkta02.splunkcloud.com:8089"
2023-03-08 10:00:34 xxxxxxxxxx root[82890] ERROR request has failed!. url=https://scde-dda6bndfb28rkta02.splunkcloud.com:8089/services/toolbox/v1/export/export_app, data={'app': 'TA-org-custombad'}, HTTP Error=500, content={"action":"failure","response":"The requested app=\"TA-org-custombad\" is not available","available_apps":["000-self-service","075-cloudworks","100-cloudworks-wlm","100-whisper","100-whisper-common","100-whisper-searchhead","alert_logevent","alert_webhook","appsbrowser","cloud-app-readiness","cloud_administration","data_manager","dmc","dynamic-data-self-storage-app","introspection_generator_addon","journald_input","launcher","learned","legacy","org_Splunk_TA_windows","prometheus","python_upgrade_readiness_app","sample_app","search","search_artifacts_helper","semicircle_donut","splunk-dashboard-studio","splunk_gdi","splunk_httpinput","splunk_instance_monitoring","splunk_instrumentation","splunk_internal_metrics","splunk_metrics_workspace","Splunk_ML_Toolkit","splunk_product_guidance","splunk_rapid_diag","Splunk_SA_CIM","Splunk_SA_Scientific_Python_linux_x86_64","splunk_secure_gateway","Splunk_TA_apache","Splunk_TA_juniper","Splunk_TA_linux","Splunk_TA_nginx","Splunk_TA_windows","splunkclouduf","TA-config-scde","TA-ms-teams-alert-action","TA-org-customapp","TA-splk-toolbox","TA_MS_Teams","timeline_app","tos","trackme"]}
```

After this step, we have a local tgz archive which is the exact Application content as it is on the Splunk Cloud search head, as well as an extracted directory of it.

If we have any local objects in the app context, these will be available in the local directory.

**Exporting, merging local objects and re-packaging:**

Now, let's export the app and repackage it, this means:

- local knowledge objects are merged into default using ksconf promote
- permissions can be merged too using the argument --promote_permissions - if it is unset, the default behaviour is not to merge permissions
- local views will be placed in default

_basic authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode basic --username $username --password $password --target_url "https://$stack.splunkcloud.com:8089" --app TA-org-customapp --run_build True
```

_bearrer authentication:_

```shell
python3 get_app_from_cloud.py --auth_mode token --token $token --target_url "https://$stack.splunkcloud.com:8089" --app TA-org-customapp --run_build True
```

Expected answer:

```shell
2023-03-08 10:04:26 xxxxxxxxxx root[83200] INFO attempting to retrieve app="TA-org-customapp" from target_url="https://scde-dda6bndfb28rkta02.splunkcloud.com:8089"
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO successfully imported app="TA-org-customapp", version="1.0.0" , tarfile="TA-org-customapp_v100.tgz"
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO successfully extracted compressed archive="TA-org-customapp_v100.tgz" into directory="TA-org-customapp"
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO purging metadata/local.metadata
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO discoverying local knowledge objects
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO discovered local config files="['props.conf']"
2023-03-08 10:04:27 xxxxxxxxxx root[83200] INFO running ksconf promote -b TA-org-customapp/local/props.conf TA-org-customapp/default/props.conf
2023-03-08 10:04:28 xxxxxxxxxx root[83200] INFO ksconf results.stdout="b''"
2023-03-08 10:04:28 xxxxxxxxxx root[83200] INFO ksconf results.stderr="b''"
2023-03-08 10:04:28 xxxxxxxxxx root[83200] INFO successfully purged the local directory before packaging the app
2023-03-08 10:04:28 xxxxxxxxxx root[83200] INFO Creating compress tgz filename="TA-org-customapp_v100.tgz"
2023-03-08 10:04:28 xxxxxxxxxx root[83200] INFO Achive tar file creation successful, archive_file="TA-org-customapp_v100.tgz"
```

This gives you a full packaged application, which would pass Appinspect, you can request an Appinspect verification straight away:

```shell
python3 get_app_from_cloud.py --auth_mode token --token $token --target_url "https://$stack.splunkcloud.com:8089" --app TA-org-customapp --run_build True --submitappinspect --userappinspect $userappinspect --passappinspect $passappinspect
```

Answer:

```shell
2023-03-08 10:05:37 xxxxxxxxxx root[83304] INFO attempting to retrieve app="TA-org-customapp" from target_url="https://scde-dda6bndfb28rkta02.splunkcloud.com:8089"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO successfully imported app="TA-org-customapp", version="1.0.0" , tarfile="TA-org-customapp_v100.tgz"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO successfully extracted compressed archive="TA-org-customapp_v100.tgz" into directory="TA-org-customapp"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO purging metadata/local.metadata
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO discoverying local knowledge objects
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO discovered local config files="['props.conf']"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO running ksconf promote -b TA-org-customapp/local/props.conf TA-org-customapp/default/props.conf
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO ksconf results.stdout="b''"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO ksconf results.stderr="b''"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO successfully purged the local directory before packaging the app
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO Creating compress tgz filename="TA-org-customapp_v100.tgz"
2023-03-08 10:05:38 xxxxxxxxxx root[83304] INFO Achive tar file creation successful, archive_file="TA-org-customapp_v100.tgz"
2023-03-08 10:05:39 xxxxxxxxxx root[83304] INFO Appsinspect: successfully logged in Appinspect API
2023-03-08 10:05:39 xxxxxxxxxx root[83304] INFO Submitting to Appinspect API="TA-org-customapp_v100.tgz"
2023-03-08 10:05:48 xxxxxxxxxx root[83304] INFO Appinspect request_id="833206a5-aab1-4603-87d3-e03a6204b74a" was successfully processed
2023-03-08 10:05:48 xxxxxxxxxx root[83304] INFO Appinspect written to report="report_appinspect.html"
2023-03-08 10:05:49 xxxxxxxxxx root[83304] INFO Appinspect written to report="report_appinspect.json"
2023-03-08 10:05:49 xxxxxxxxxx root[83304] INFO Appinspect request_id="833206a5-aab1-4603-87d3-e03a6204b74a" was successfully vetted, summary="{
    "error": 0,
    "failure": 0,
    "skipped": 0,
    "manual_check": 0,
    "not_applicable": 102,
    "warning": 4,
    "success": 117
}"
```

As I am saying often in that case, "Voila!".

#### Deploying

You can the Python script "deploy_to_cloud.py" to deploy to a new Splunk Cloud stack, it will:

- Run Appinspect
- Deploy to Splunk Cloud using Splunk ACS API

_To use an ACS token:_

```shell
export tokenacs='mytoken_acs'
```

_Then:_

```shell
python3 deploy_to_cloud.py --stack $stack --appfile TA-org-customapp_v100.tgz --userappinspect $userappinspect --passappinspect $passappinspect --tokenacs $tokenacs
```

_Answer:_

```shell
2023-03-08 11:17:10 xxxxxxxxxx root[89404] INFO Appsinspect: successfully logged in Appinspect API
2023-03-08 11:17:10 xxxxxxxxxx root[89404] INFO Submitting to Appinspect API="TA-org-customapp_v100.tgz"
2023-03-08 11:17:17 xxxxxxxxxx root[89404] INFO Appinspect request_id="1b45ba6f-25d3-4194-a57d-927c689a45c2" was successfully processed
2023-03-08 11:17:20 xxxxxxxxxx root[89404] INFO Appinspect written to report="report_appinspect.html"
2023-03-08 11:17:21 xxxxxxxxxx root[89404] INFO Appinspect written to report="report_appinspect.json"
2023-03-08 11:17:21 xxxxxxxxxx root[89404] INFO Appinspect request_id="1b45ba6f-25d3-4194-a57d-927c689a45c2" was successfully vetted, summary="{
    "error": 0,
    "failure": 0,
    "skipped": 0,
    "manual_check": 0,
    "not_applicable": 102,
    "warning": 4,
    "success": 117
}"
2023-03-08 11:17:24 xxxxxxxxxx root[89404] INFO Splunk ACS deployment of app="TA-org-customapp" was successful, summary="{
    "appID": "TA-org-customapp",
    "label": "Splunk Add-on of mine",
    "name": "TA-org-customapp",
    "status": "installed",
    "version": "1.0.0"
}"
```

_To use an epehmeral ACS token:_

```shell
export username='my_splunk_username'
export password='mypass'
```

_Then:_

```shell
python3 deploy_to_cloud.py --stack $stack --appfile TA-org-customapp_v100.tgz --userappinspect $userappinspect --passappinspect $passappinspect --create_token --username $username --password $password --token_audience "Splunk ACS"
```

_Answer:_

```shell
023-03-08 11:17:57 xxxxxxxxxx root[89515] INFO Appsinspect: successfully logged in Appinspect API
2023-03-08 11:17:57 xxxxxxxxxx root[89515] INFO Submitting to Appinspect API="TA-org-customapp_v100.tgz"
2023-03-08 11:18:06 xxxxxxxxxx root[89515] INFO Appinspect request_id="fb82291a-54ee-488e-9b29-a9f32844395c" was successfully processed
2023-03-08 11:18:07 xxxxxxxxxx root[89515] INFO Appinspect written to report="report_appinspect.html"
2023-03-08 11:18:08 xxxxxxxxxx root[89515] INFO Appinspect written to report="report_appinspect.json"
2023-03-08 11:18:08 xxxxxxxxxx root[89515] INFO Appinspect request_id="fb82291a-54ee-488e-9b29-a9f32844395c" was successfully vetted, summary="{
    "error": 0,
    "failure": 0,
    "skipped": 0,
    "manual_check": 0,
    "not_applicable": 102,
    "warning": 4,
    "success": 117
}"
2023-03-08 11:18:09 xxxxxxxxxx root[89515] INFO Ephemeral token created successfully
2023-03-08 11:18:12 xxxxxxxxxx root[89515] INFO Splunk ACS deployment of app="TA-org-customapp" was successful, summary="{
    "appID": "TA-org-customapp",
    "label": "Splunk Add-on of mine",
    "name": "TA-org-customapp",
    "status": "installed",
    "version": "1.0.0"
}"
```
