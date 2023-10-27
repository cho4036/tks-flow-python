import sys
from kubernetes import client, config
import yaml
import base64
import json

input_params = {
    'target_cluster_id': 'cj7e583yl',
    'is_self_target': 'true',
    'rolebinding_name': 'test',
    'role_name': 'admin',
    'group_list': '["cluster-admin", "cluster-view"]',
}


def get_kubernetes_api(local=False):
    if local:
        import os
        kubeconfig_path = os.path.expandvars("$HOME/.kube/config")
        api_config = client.Configuration()
        config.load_kube_config(config_file=kubeconfig_path, client_configuration=api_config)
    else:
        api_config = client.Configuration()
        config.load_incluster_config(client_configuration=api_config)
    return client.ApiClient(configuration=api_config)


def get_kubernetes_api_from_kubeconfig(kubeconfig_str):
    kubeconfig_dict = yaml.safe_load(kubeconfig_str)
    api_config = client.Configuration()
    config.load_kube_config_from_dict(kubeconfig_dict, client_configuration=api_config)
    return client.ApiClient(configuration=api_config)


def get_kubeconfig_secret(k8s_client, secret_name, secret_namespace):
    api_instance = client.CoreV1Api(k8s_client)
    secret_obj = api_instance.read_namespaced_secret(name=secret_name, namespace=secret_namespace)
    encoded_data = secret_obj.data.get('value')
    decoded_data = base64.b64decode(encoded_data).decode('utf-8')
    return decoded_data


def create_cluster_rolebinding(api_client, name, group_list, role):
    api_instance = client.RbacAuthorizationV1Api(api_client)
    body = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": name
        },
        "subjects": [
        ],
        "roleRef": {
            "kind": "ClusterRole",
            "name": role,
            "apiGroup": "rbac.authorization.k8s.io"
        }
    }
    for group in group_list:
        body['subjects'].append({
            "kind": "Group",
            "name": group,
            "apiGroup": "rbac.authorization.k8s.io"
        })
    try:
        return api_instance.create_cluster_role_binding(body)
    except client.ApiException as e:
        if e.status == 409:
            print(f'cluster rolebinding "{name}" already exists')
            return
        else:
            raise e


def input_validation(origin_input_params):
    if not origin_input_params['target_cluster_id'] or origin_input_params['target_cluster_id'] == '':
        raise Exception('target_cluster_id is required')
    if not origin_input_params['rolebinding_name'] or origin_input_params['rolebinding_name'] == '':
        raise Exception('rolebinding_name is required')
    if not origin_input_params['role_name'] or origin_input_params['role_name'] == '':
        raise Exception('role_name is required')
    if not origin_input_params['group_list'] or len(origin_input_params['group_list']) == 0:
        raise Exception('group_list is required')


input_validation(input_params)
input_params["group_list"] = json.loads(input_params["group_list"])

if input_params['is_self_target'] == 'true':
    target_k8s_client = k8s_client = get_kubernetes_api(local=False)

else:
    k8s_client = get_kubernetes_api(local=False)
    target_k8s_kubeconfig = get_kubeconfig_secret(k8s_client, input_params['target_cluster_id'] + "-tks-kubeconfig",
                                                  input_params['target_cluster_id'])
    target_k8s_client = get_kubernetes_api_from_kubeconfig(target_k8s_kubeconfig)

try:
    create_cluster_rolebinding(target_k8s_client, input_params['rolebinding_name'], input_params['group_list'], input_params['role_name'])
    print(f'create cluster rolebinding "{input_params["rolebinding_name"]}" success')
except Exception as e:
    print(e)
    sys.exit(1)

sys.exit(0)
