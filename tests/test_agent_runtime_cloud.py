from backend.agent.security_agent import CloudNativeSecurityAgent
from backend.scanners.cloud_config_scanner import scan_cloud_config_text
from backend.scanners.runtime_edr import analyze_runtime_event
from backend.scanners.terraform_scanner import scan_terraform_text


def test_runtime_edr_detects_shell_and_token_access():
    shell_event = {
        "event_type": "execve",
        "namespace": "default",
        "pod": "bad",
        "container": "app",
        "process_name": "bash",
        "cmdline": "bash -i",
    }
    token_event = {
        "event_type": "open",
        "namespace": "default",
        "pod": "bad",
        "container": "app",
        "process_name": "cat",
        "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    }
    assert any(f["rule_id"] == "EDR001" for f in analyze_runtime_event(shell_event))
    assert any(f["rule_id"] == "EDR005" for f in analyze_runtime_event(token_event))


def test_cloud_config_detects_public_and_secret():
    text = '{"sg":{"cidr":"0.0.0.0/0"},"accessKey":"AKIA1234567890EXAMPLE","bucketAcl":"public-read","encrypted":false}'
    rule_ids = {f["rule_id"] for f in scan_cloud_config_text(text)}
    assert "CLOUD001" in rule_ids
    assert "CLOUD002" in rule_ids
    assert "CLOUD003" in rule_ids
    assert "CLOUD005" in rule_ids


def test_terraform_detects_public_sg_and_wildcard_iam():
    text = '''
    resource "aws_security_group" "bad" {
      ingress { from_port=22 to_port=22 protocol="tcp" cidr_blocks=["0.0.0.0/0"] }
    }
    resource "aws_iam_policy" "admin" { policy = "{\"Statement\":[{\"Action\":\"*\"}]}" }
    variable "secret_key" { default = "hardcoded" }
    '''
    rule_ids = {f["rule_id"] for f in scan_terraform_text(text)}
    assert "TF001" in rule_ids
    assert "TF003" in rule_ids


def test_agent_correlates_escape_path():
    k8s = '''
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
  volumes:
    - name: host
      hostPath:
        path: /
'''
    result = CloudNativeSecurityAgent().analyze({"k8s_yaml_text": k8s})
    assert result["summary"]["total"] > 0
    assert any(path["name"] == "容器逃逸高危链路" for path in result["attack_paths"])
