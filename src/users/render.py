import os
import yaml
import ast
import astunparse

# 현재 스크립트의 위치
current_script_path = os.path.dirname(os.path.abspath(__file__))
# 디렉토리 이름
current_script_dirname = os.path.basename(current_script_path)
# template 파일의 경로
template_dir_path = os.path.join(current_script_path, f'../../workflowtemplate/keycloak/{current_script_dirname}')
# 현재 스크립트의 위치를 기준으로 상대 경로로 base_template.yaml의 경로 지정
base_template_path = os.path.join(template_dir_path, 'base-template.yaml')

image_name = 'harbor-cicd.taco-cat.xyz/dev/python-keycloak-cli:v0.1.0'


class ReplaceInputParams(ast.NodeTransformer):
    def visit_Assign(self, node):
        if any(target.id == "input_params" for target in node.targets if isinstance(target, ast.Name)):
            if isinstance(node.value, ast.Dict):
                for i, key in enumerate(node.value.keys):
                    if isinstance(key, ast.Str):
                        param_name = key.s
                        node.value.values[i] = ast.Str(f'{{{{workflow.parameters.{param_name}}}}}')
        return node


def replace_input_params_with_ast(script_content):
    tree = ast.parse(script_content)
    transformer = ReplaceInputParams()
    modified_tree = transformer.visit(tree)
    return astunparse.unparse(modified_tree)


def str_presenter(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, str_presenter)


def extract_input_params(script_path):
    with open(script_path, "r") as f:
        tree = ast.parse(f.read())
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if target.id == "input_params":
                        if isinstance(node.value, ast.Dict):
                            keys = [k.s for k in node.value.keys]
                            values = [v.s for v in node.value.values]
                            # values = [f"{{{{workflow.parameters.{k.s}}}}}" for k in node.value.keys]
                            return dict(zip(keys, values))
        return {}


with open(base_template_path, "r") as template_file:
    base_template = yaml.safe_load(template_file)

base_template["spec"]["templates"] = []

# current_script_path에 있는 모든 파일을 순회하면서 .py 확장자를 가진 파일 검색
for filename in os.listdir(current_script_path):
    # 현재 실행 중인 스크립트는 제외
    if filename.endswith(".py") and filename != os.path.basename(__file__):
        # 확장자를 제거한 파일 이름
        template_name = os.path.splitext(filename)[0]

        # 파이썬 스크립트에서 input_params 가져오기
        script_path = os.path.join(current_script_path, filename)
        input_params = extract_input_params(script_path)

        with open(script_path, 'r') as f:
            script_content = f.read()

        # 파이썬 스크립트 내용에서 input_params를 workflow.parameters로 치환
        script_content = replace_input_params_with_ast(script_content)

        # Argo Workflow용 inputs.parameters 생성
        inputs_parameters = [{"name": k, "value": v} for k, v in input_params.items()]

        template_content = {
            "name": template_name,
            "inputs": {
                "parameters": inputs_parameters
            },
            "script": {
                "command": ['python3'],
                "image": image_name,
                "source": script_content
            },
            # ... (다른 필요한 템플릿 내용 추가)
        }
        base_template["spec"]["templates"].append(template_content)

# 결과를 새로운 YAML 파일로 출력
with open(f"{template_dir_path}/output_workflow_template.yaml", "w") as outfile:
    yaml.dump(base_template, outfile, sort_keys=False)
