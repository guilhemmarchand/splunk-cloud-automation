# Manage Splunk Cloud indexes using a Splunk like application with an indexes.conf

## Usage

    export token="my bearer token"
    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token"

To use a proxy:

    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token" --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>

To use an ephemeral token:

    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --create_token --username <Splunk user> --password <Splunk password> --token_audience <Audience for the token> --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>
