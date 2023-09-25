from keycloak import KeycloakOpenIDConnection, KeycloakAdmin, KeycloakOpenID
import requests
from kubernetes import client, config
import sys
import base64

input_params = {
    'server_url': 'http://tks-console-dev.taco-cat.xyz/auth/',
    'target_realm_name': 'test3',
    'target_client_id': 'k8s-oidc6',
    'keycloak_credential_secret_name': 'keycloak',
    'keycloak_credential_secret_namespace': 'keycloak',

    'mapper_name': 'k8s-role-mapper',
    'claim_name': 'groups',
    'add_to_access_token': False,
    'add_to_id_token': True,
    'add_to_userinfo': False,
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


def create_client_scope_mapper(url, realm_name, client_id, hashed_client_id, token, mapper_name):
    # if url end with '/', remove it
    if url[-1] == '/':
        url = url[:-1]
    path = f'/admin/realms/{realm_name}/clients/{hashed_client_id}/protocol-mappers/models'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token['access_token'],
    }
    data = {
        'name': mapper_name,
        'protocol': 'openid-connect',
        'protocolMapper': 'oidc-usermodel-client-role-mapper',
        'config': {
            'usermodel.clientRoleMapping.clientId': client_id,
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
    verify=True,
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
    try:
        hashed_client_id = keycloak_admin.get_client_id(client_id=input_params["target_client_id"])
        print(f'hashed_client_id of client id "{input_params["target_client_id"]}" is "{hashed_client_id}".')
    except Exception as inner_e:
        print(inner_e)
        raise Exception(f'get client id "{input_params["target_client_id"]} failed')

    try:
        create_client_scope_mapper(
            url=input_params['server_url'],
            realm_name=input_params['target_realm_name'],
            client_id=input_params['target_client_id'],
            hashed_client_id=hashed_client_id,
            token=keycloak_admin.connection.token,
            mapper_name=input_params['mapper_name'],
        )
        print(f'create client scope mapper "{input_params["mapper_name"]}" in client "{input_params["target_client_id"]} success')
    except Exception as inner_e:
        print(inner_e)
        raise Exception('create client role on keycloak failed')

    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])
except Exception as e:
    print(e)
    print(f'create client scope mapper "{input_params["mapper_name"]}" in client "{input_params["target_client_id"]} failed')
    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])
    sys.exit(1)
