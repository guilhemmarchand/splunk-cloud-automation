# Manage Splunk Cloud indexes using a Splunk like application with an indexes.conf

## Usage

    export token="my bearer token"
    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token"

To use a proxy:

    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token" --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>

To use an ephemeral token:

    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --create_token --username <Splunk user> --password <Splunk password> --token_audience <Audience for the token> --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>

## behaviour

- maxDataSizeMB: max index size in MB
- searchableDays: max searcheable days

If there is a mismatch with any of these two parameters between this configuration file and the remote Splunk Cloud stack, Update will be requested to Splunk ACS.

If an index listed here does not exist remotely, its creation will be push to Splunk ACS.
