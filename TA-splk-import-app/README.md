# TA-splk-import-app

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

**Get app:**

```shell
curl -k -H "Authorization: Bearer $tokenhf" -H "Content-Type: application/json" -X POST $target/services/toolbox/v1/import/import_app -d '{"account": "scde", "app": "TA-org-customapp"}'
```