from keycloak import KeycloakOpenIDConnection, KeycloakAdmin, KeycloakOpenID
from kubernetes import client, config
import sys
import base64
import json

input_params = {
    'server_url': 'http://tks-console-dev.taco-cat.xyz/auth/',
    'target_realm_name': 'test3',
    'keycloak_credential_secret_name': 'keycloak',
    'keycloak_credential_secret_namespace': 'keycloak',
}

output_file_path = "/tmp/output.json"
output_params = {
    'users': [],  # List of Keycloak user objects
}

def get_kubernetes_api(local=False):
    if local:
        import os
        kubeconfig_path = os.path.expandvars("$HOME/.kube/config")
        # use kubeconfig in a directory& return kubernetes client
        config.load_kube_config(config_file=kubeconfig_path)
    else:
        # use service account & return kubernetes client
        config.load_incluster_config()
    return client.CoreV1Api()


def get_secret(k8s_client, secret_name, secret_namespace):
    secret_obj = k8s_client.read_namespaced_secret(name=secret_name, namespace=secret_namespace)
    encoded_data = secret_obj.data.get('admin-password')
    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
    return decoded_data


def input_validation(origin_input_params):
    if not origin_input_params['server_url'][-1] == '/':
        origin_input_params['server_url'] += '/'


input_validation(input_params)
k8s_client = get_kubernetes_api(local=False)

try:
    secret_name = input_params['keycloak_credential_secret_name']
    secret_namespace = input_params['keycloak_credential_secret_namespace']
    secret = get_secret(k8s_client, secret_name, secret_namespace)
    print(f'get secret "{secret_name}" in "{secret_namespace}" namespace')
except Exception as e:
    print(e)
    print(f'failed to get secret "{secret_name}" in "{secret_namespace}" namespace')
    sys.exit(1)

keycloak_connection = KeycloakOpenIDConnection(
    server_url=input_params['server_url'],
    client_id='admin-cli',
    realm_name=input_params['target_realm_name'],
    user_realm_name='master',
    username='admin',
    password=secret,
    verify=False,
)
keycloak_openid = KeycloakOpenID(
    server_url=input_params['server_url'],
    client_id='admin-cli',
    realm_name='master',
)
try:
    keycloak_admin = KeycloakAdmin(connection=keycloak_connection)
    print(f'login to {input_params["server_url"]} success')
except Exception as e:
    print(e)
    print(f'login to {input_params["server_url"]} failed')
    sys.exit(1)

try:
    users = keycloak_admin.get_users()
    print(f'get users success')

    name_list = []
    for user in users:
        name_list.append(user['username'])
    try:
        data = {
            'user_names': name_list
        }
        with open(output_file_path, "w") as f:
            json.dump(data, f)

        print(f"Users data saved to {output_file_path}")

    except Exception as e:
        print(e)
        print(f'failed to save users data')
        sys.exit(1)

    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])

except Exception as e:
    print(e)
    print(f'get users failed')
    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])
    sys.exit(1)
