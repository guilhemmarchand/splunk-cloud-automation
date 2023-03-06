# Manage Splunk Cloud indexes using a Splunk like application with an indexes.conf

## Usage

    export token="my bearer token"
    deploy.py --app_root org_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token"

To use a proxy:

    deploy.py --app_root org_all_indexes --app_dir local  --stack '<stack_name>' --tokenacs "$token" --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>

To use an ephemeral token:

    deploy.py --app_root org_all_indexes --app_dir local  --stack '<stack_name>' --create_token --username <Splunk user> --password <Splunk password> --token_audience <Audience for the token> --useproxy --proxy_url <https://myproxy> --proxy_port <proxy_port>

## behaviour

The following options can be set on the local indexes.conf and will be maintained in Splunk Cloud:

- maxDataSizeMB: max index size in MB
- searchableDays: max searcheable days

If there is a mismatch with any of these two parameters between this configuration file and the remote Splunk Cloud stack, Update will be requested to Splunk ACS.

If an index listed here does not exist remotely, its creation will be push to Splunk ACS.

## Options

- --app_root: the directory name containing a default or local directory with your indexes.conf

- --app_dir: the app directory, can be default or local

- --debug: enables debug logging

- --show_idx_summary 'True|False;': defaults to False, if set True, this logs a summary list of all indexes available in the Splunk Cloud stack

- --show_idx_full 'True|False': defaults to False, if set True, this logs a full dictionnary of the all indexes and their parameters availanle in the Splunk Cloud stack

- --create_token: if set, we will create and use an ephemeral token, this requires the username, password and token_audience to be provided

- --token_audience: if using ephemeral tokens, defines the audience

- --username: if using ephemeral tokens, the Splunk user name used for the authentication and the token definition

- --password: if using ephemeral tokens, the Splunk user password

- --tokenacs: if using a bearer token, provide the token here

- --stack: the Splunk Cloud stack identifier

- --useproxy: If you need to use a proxy, enable the switch

- --proxy_url: The proxy URL, in the format https://proxyurl

- --proxy_port: The proxy port

- --proxy_username: Optional, the proxy username if required

- --proxy_password: Optional, the proxy password if required (mandatory is proxy_username is set)
