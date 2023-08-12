from keycloak import KeycloakOpenID
import requests
from kubernetes import client, config
import sys
import base64

input_params = {
    'server_url': 'http://donggyu-keycloak.taco-cat.xyz/auth/',
    'target_realm_name': 'test3',
    'target_client_id': 'test-client2',
    'keycloak_credential_secret_name': 'keycloak',
    'keycloak_credential_secret_namespace': 'keycloak',
}


def get_kubernetes_api(local=False):
    if local:
        import os
        kubeconfig_path = os.path.expandvars("$HOME/donggyu_kubeconfig/kubeconfig_donggyu-test")
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


def create_client(url, realm_name, client_id, token):
    # if url end with '/', remove it
    if url[-1] == '/':
        url = url[:-1]
    path = f'/admin/realms/{realm_name}/clients'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token['access_token'],
    }
    data = {
        'clientId': client_id,
        'enabled': True,
        'publicClient': True,
        'protocol': 'openid-connect',
        'standardFlowEnabled': True,
        'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': True,
        'serviceAccountsEnabled': False,
        'authorizationServicesEnabled': False,
        'fullScopeAllowed': True,
    }
    response = requests.post(url + path, headers=headers, json=data)
    if response.status_code == 201:
        print(f'create client {client_id} success')
    elif response.status_code == 409:
        raise Exception(response.text)
    else:
        raise Exception(response.text)


k8s_client = get_kubernetes_api(local=True)

try:
    secret_name = input_params['keycloak_credential_secret_name']
    secret_namespace = input_params['keycloak_credential_secret_namespace']
    secret = get_secret(k8s_client, secret_name, secret_namespace)
    print(f'get secret "{secret_name}" in "{secret_namespace}" namespace')
except Exception as e:
    print(e)
    print(f'failed to get secret "{secret_name}" in "{secret_namespace}" namespace')
    sys.exit(1)

keycloak_openid = KeycloakOpenID(
    server_url=input_params['server_url'],
    client_id='admin-cli',
    realm_name='master',
)

token = keycloak_openid.token(
    grant_type='password',
    username='admin',
    password=secret,
)

try:
    create_client(input_params['server_url'], input_params['target_realm_name'], input_params['target_client_id'], token)
    print(f'create client "{input_params["target_client_id"]}" success')
    keycloak_openid.logout(token['refresh_token'])
except Exception as e:
    print(e)
    print('create client failed')
    keycloak_openid.logout(token['refresh_token'])
    sys.exit(1)

