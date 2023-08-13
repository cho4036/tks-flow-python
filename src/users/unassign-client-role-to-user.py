from keycloak import KeycloakOpenIDConnection, KeycloakAdmin, KeycloakOpenID
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

    'client_role_name': 'admin',
    'user_name': 'user1',
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
        print(f'hashed_client_id of client id "{input_params["target_client_id"]}" is "{hashed_client_id}"')
    except Exception as inner_e:
        print(inner_e)
        raise Exception(f'get client id "{input_params["target_client_id"]} failed')

    try:
        idOfClientRole = keycloak_admin.get_client_role_id(client_id=hashed_client_id,
                                                           role_name=input_params["client_role_name"])
        print(f'client role id in client id "{input_params["target_client_id"]}" is "{idOfClientRole}"')
    except Exception as inner_e:
        print(inner_e)
        raise Exception(f'get client role "{input_params["client_role_name"]}" failed')

    try:
        idOfUser = keycloak_admin.get_user_id(username=input_params["user_name"])
        print(f'id of user "{input_params["user_name"]}" is "{idOfUser}"')
    except Exception as inner_e:
        print(inner_e)
        raise Exception(f'get user "{input_params["user_name"]}" failed')

    try:
        keycloak_admin.delete_client_roles_of_user(client_id=hashed_client_id, user_id=idOfUser,
                                                   roles=[{'id': idOfClientRole, 'name': input_params["client_role_name"]}])
        print(f'un-assign client role "{input_params["client_role_name"]}" to user "{input_params["user_name"]}" success')
    except Exception as inner_e:
        print(inner_e)
        raise Exception('un-assign client role to user on keycloak failed')

    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])
except Exception as e:
    print(e)
    print(f'un-assign client role "{input_params["client_role_name"]}" to user "{input_params["user_name"]}" failed')
    keycloak_openid.logout(keycloak_admin.connection.token['refresh_token'])
    sys.exit(1)
