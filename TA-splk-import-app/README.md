# TA-splk-import-app

**See the documentation here:**

- https://github.com/guilhemmarchand/splunk-cloud-automation/tree/main/TA-splk-toolbox

**Export env:**

```shell
export target="https://myhf.mydomain.com:8089"
export tokenhf="<my_bearer_token>
```

**Test endpoint:**

```shell
curl -k -H "Authorization: Bearer $tokenhf" -X GET $target/services/toolbox/v1/import/test_endpoint
```

**Test remote:**

```shell
curl -k -H "Authorization: Bearer $tokenhf" -X POST $target/services/toolbox/v1/import/test_sc_connectivity -d '{"account": "scde"}'
```

**Export an application:**

```shell
curl -k -H "Authorization: Bearer $tokenhf" -H "Content-Type: application/json" -X POST $target/services/toolbox/v1/import/import_app -d '{"account": "scde", "app": "TA-org-customapp"}'
```

**Export an application without packing:**

```shell
curl -k -H "Authorization: Bearer $tokenhf" -H "Content-Type: application/json" -X POST $target/services/toolbox/v1/import/import_app -d '{"account": "scde", "app": "TA-org-customapp", "run_build": "false"}'
```
