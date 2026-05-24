from backend.scanners.dockerfile_scanner import scan_dockerfile_text
from backend.scanners.k8s_yaml_scanner import scan_k8s_yaml_text


def test_dockerfile_detects_basic_risks():
    text = """
    FROM ubuntu:latest
    ENV API_KEY=AKIA1234567890EXAMPLE
    RUN apt-get update && apt-get install -y curl netcat
    ADD . /app
    CMD ["bash"]
    """
    findings = scan_dockerfile_text(text)
    rule_ids = {f["rule_id"] for f in findings}
    assert "DF001" in rule_ids
    assert "DF004" in rule_ids
    assert "DF010" in rule_ids


def test_k8s_detects_privileged_hostpath():
    text = """
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: bad
    spec:
      template:
        spec:
          hostNetwork: true
          containers:
            - name: app
              image: nginx:latest
              securityContext:
                privileged: true
                allowPrivilegeEscalation: true
          volumes:
            - name: host
              hostPath:
                path: /
    """
    findings = scan_k8s_yaml_text(text)
    rule_ids = {f["rule_id"] for f in findings}
    assert "K8S001" in rule_ids
    assert "K8S005" in rule_ids
    assert "K8S007" in rule_ids
