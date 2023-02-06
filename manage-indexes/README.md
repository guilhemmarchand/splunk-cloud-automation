# Manage Splunk Cloud indexes using a Splunk like application with an indexes.conf

## Usage

::

    export token="my bearer token"
    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token"

To use a proxy:

::

    deploy.py --app_root gsoc_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token" --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>
