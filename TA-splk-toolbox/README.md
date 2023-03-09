# TA-splk-toolbox - Toolbox application designed for Splunk Cloud operations

## Exporting Splunk applications from Splunk Cloud

This application exposes a REST API for the purposes of exporting Splunk applications from a Splunk CLoud deployment.

### Concept

- An HTTP REST API interface exposes an endpoint that allows packaging and exporting a Splunk Application and all of its content
- Once packaged in the application working directory, the compressed tarball content is provided in a JSON payload over TLS encoded in base64
- The requester process process would read this base64 encoded JSON payload and decode the base64 using Python

### Requirement

- The only requirement is to have access to the Splunk Splunk Cloud Search Head Splunk API, which you can configure in Splunk Web
- Authentication is performed against Splunkd using valid credential you provide as part of the API requester arguments

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
