# TA-splk-toolbox - Toolbox application designed for Splunk Cloud operations

## Feature 1 - Exporting Splunk applications from Splunk Cloud

This application exposes a REST API for the purposes of exporting Splunk applications from a Splunk CLoud deployment.

### Concept

- An HTTP REST API interface exposes an endpoint that allows packaging and exporting a Splunk Application and all of its content
- Once packaged in the application working directory, the compressed tarball content is provided in a JSON payload over TLS encoded in base64
- The requester process process would read this base64 encoded JSON payload and decode the base64 using Python

### Requirements

- The only requirement is to have access to the Splunk Splunk Cloud Search Head Splunk API, which you can configure in Splunk Web
- Authentication is performed against Splunkd using valid credential you provide as part of the API requester arguments

#### Requirements for the couple TA-splk-toolbox / TA-splk-import-app

- The Splunk Cloud Search Head needs to be able to access to your Heavy Forwarder on Splunkd API 8089, for this you need to allow the outgoing traffic on ACS:

```shell
export stack="<my_stack>"
export token="<my_bearer_token>"

curl -X POST "https://admin.splunk.com/$stack/adminconfig/v2/access/outbound-ports" \
--header "Authorization: Bearer $token" \
--header 'Content-Type: application/json' \
--data-raw '{
   "outboundPorts": [{"subnets": ["<HF public IP>/32"], "port": 8089}],
   "reason": "external API splunkd"
}'
```

You can check your config as:

```shell
curl "https://admin.splunk.com/$token/adminconfig/v2/access/outbound-ports/8089" \
--header "Authorization: Bearer $token"
```

Of course, your HF needs to accept the incoming traffic from Splunk Cloud.

- Then, the Heavy Forwarder itself needs to be able to do the opposite, this means accessing Splunk Cloud Search Head API on 8089.

You can nowadays allow this traffic straight from the Splunk Cloud configuration UI.

#### Example

To export a Splunk Application and all its content in a gzip compressed tarball archived:

```shell
export login='myuser'
export pass='mypassword'
export stack='https://$mystack.splunkcloud.com:8089'
curl -k -u $muyser:"$mypassowrd" -X POST $stack/services/toolbox/v1/export/export_app -d '{"app": "Splunk_TA_juniper"}'
```

The response will be similar to:

```json
{
  "base64": "b'<encoded_base64>'",
  "app": "Splunk_TA_juniper",
  "version": "1.5.5rfb1b492",
  "filename": "Splunk_TA_juniper_v155rfb1b492.tgz",
  "result": "The package is now ready in base64."
}
```

**More details about the programmatic behaviour can be found here:**

- https://github.com/guilhemmarchand/splunk-cloud-automation/tree/main/export-apps

### Configuration parameters

#### Configuration

The App provides a configuration UI with a concept of accounts, in each account you will setup:

- An account ID
- The URL to your Splunk Heavy Forwarder API
- A bearer token for the authentication purposes

**This will target a Heavy Forwarder instance running the TA-splk-import-app which contains the mirrored API endpoint and will perform the import from Splunk Cloud:**

![screen001](img/screen001.png)

**The workflow is the following:**

- From Splunk Cloud, a custom command is called to trigger the import on the target Splunk instance (HF)

- This custom command performs a REST call to the HF hosting the TA-splk-import-app

- In turn, the HF triggers a REST call back to Splunk Cloud, exports the app and runs the requested logic (merging, packaging and post-execution)

##### TA-splk-import-app

On the HF, the TA-splk-import-app is deployed, this app hosts a REST API endpoint which receives incoming REST calls via splunkd and a bearer authentication mechanism.

The configuration is similar to the TA-splk-import-app, with several additional parameters:

**Account:**

![screen002](img/screen002.png)

In this case, you want to configure Splunk Cloud as the target:

- An account ID
- The URL to your Splunk Cloud Search Head API
- A bearer token for the authentication purposes

**Main parameters:**

In addition, we have 3 main parameters:

- **The local target path**, which defines the location on the file-system of the Heavy Forwarder (the target) where application will exported and packaged, this directory needs to exist and be owned by the Unix user running Splunk processes

- The **ksconf finary path**, on the HF you need to install ksconf as a Splunk Application, see: https://ksconf.readthedocs.io

- An optional **post execution script**, this script would optionally be called at part of the build process to run your CI/CD logic, we will come back on this in the further steps!
