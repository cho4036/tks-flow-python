from keycloak import KeycloakOpenID
import requests
from kubernetes import client, config
import sys
import base64
import json

input_params = {
    'server_url': 'http://donggyu-keycloak.taco-cat.xyz/auth/',
    'target_realm_name': 'test3',
    'target_client_id': 'k8s-oidc6',
    'keycloak_credential_secret_name': 'keycloak',
    'keycloak_credential_secret_namespace': 'keycloak',

    'mapper_name': 'test-mapper1',
    'claim_name': 'k8s-oidc',
    'add_to_access_token': False,
    'add_to_id_token': True,
    'add_to_userinfo': False,
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


def create_client_scope_mapper(url, realm_name, client_id, token, mapper_name):
    path = 'admin/realms/' + realm_name + '/clients/' + client_id + '/protocol-mappers/models'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token['access_token'],
    }
    data = {
        'name': mapper_name,
        'protocol': 'openid-connect',
        'protocolMapper': 'oidc-usermodel-attribute-mapper',
        'config': {
            'claim.name': input_params['claim_name'],
            'access.token.claim': input_params['add_to_access_token'],
            'id.token.claim': input_params['add_to_id_token'],
            'userinfo.token.claim': input_params['add_to_userinfo'],
            'multivalued': 'true',
            'jsonType.label': 'String',
        },
    }
    response = requests.post(url + path, headers=headers, json=data)
    if response.status_code == 201:
        print(f'create client scope mapper {client_id} success')
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
    client_id='k8s-oidc6',
    realm_name='test3',
)

token = keycloak_openid.token("user1", "user1")
#print token pretty
print(json.dumps(token, indent=4, sort_keys=True))
keycloak_openid.logout(token['refresh_token'])


