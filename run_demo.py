from __future__ import annotations

import json
from pathlib import Path

from backend.agent.security_agent import CloudNativeSecurityAgent
from backend.agents import SecuritySupervisorAgent
from backend.llm.remediation_generator import enrich_findings
from backend.models.database import create_task, finish_task, init_db, save_falco_event, save_findings, save_runtime_event
from backend.reports.generator import save_report
from backend.scanners.cloud_config_scanner import scan_cloud_config_path
from backend.scanners.common import summarize_findings
from backend.scanners.dockerfile_scanner import scan_dockerfile_path
from backend.scanners.falco_parser import parse_falco_event
from backend.scanners.k8s_yaml_scanner import scan_k8s_yaml_path
from backend.scanners.runtime_edr import analyze_runtime_event
from backend.scanners.terraform_scanner import scan_terraform_path
from backend.scanners.trivy_image import scan_image_with_trivy

ROOT = Path(__file__).resolve().parent


def save_task(task_type: str, target: str, findings):
    findings = enrich_findings(list(findings))
    task_id = create_task(task_type, target)
    save_findings(task_id, findings)
    summary = summarize_findings(findings)
    finish_task(task_id, "finished", summary)
    print(f"[+] {task_type} {target}: {summary}")


def main() -> None:
    init_db()
    dockerfile = ROOT / "examples" / "vulnerable-dockerfile" / "Dockerfile"
    k8s_yaml = ROOT / "examples" / "vulnerable-k8s-yaml" / "deployment.yaml"
    falco_event = ROOT / "examples" / "falco-event.json"
    runtime_events_path = ROOT / "examples" / "runtime" / "edr-events.json"
    cloud_config = ROOT / "examples" / "cloud" / "aws-risky-config.json"
    terraform = ROOT / "examples" / "terraform" / "main.tf"

    save_task("dockerfile_scan", str(dockerfile), scan_dockerfile_path(str(dockerfile)))
    save_task("k8s_yaml_scan", str(k8s_yaml), scan_k8s_yaml_path(str(k8s_yaml)))
    save_task("terraform_scan", str(terraform), scan_terraform_path(str(terraform)))
    save_task("cloud_config_scan", str(cloud_config), scan_cloud_config_path(str(cloud_config)))
    save_task("image_scan", "nginx:latest", scan_image_with_trivy("nginx:latest", timeout=60))

    event = json.loads(falco_event.read_text(encoding="utf-8"))
    finding = enrich_findings([parse_falco_event(event)])[0]
    save_falco_event(event, finding)
    print("[+] falco_event stored")

    runtime_events = json.loads(runtime_events_path.read_text(encoding="utf-8"))
    for runtime_event in runtime_events:
        findings = enrich_findings(analyze_runtime_event(runtime_event))
        save_runtime_event(runtime_event, findings)
    print(f"[+] runtime_edr_events stored: {len(runtime_events)}")

    agent = SecuritySupervisorAgent()
    agent_result = agent.analyze({
        "dockerfile_text": dockerfile.read_text(encoding="utf-8"),
        "dockerfile_target": "examples/vulnerable-dockerfile/Dockerfile",
        "k8s_yaml_text": k8s_yaml.read_text(encoding="utf-8"),
        "k8s_target": "examples/vulnerable-k8s-yaml/deployment.yaml",
        "terraform_text": terraform.read_text(encoding="utf-8"),
        "terraform_target": "examples/terraform/main.tf",
        "cloud_config_text": cloud_config.read_text(encoding="utf-8"),
        "cloud_config_target": "examples/cloud/aws-risky-config.json",
        "runtime_events": runtime_events,
    })
    print("[+] multi-agent supervisor executive summary:")
    print(agent_result["executive_summary"])
    print("[+] multi-agent attack paths:", len(agent_result["attack_paths"]))
    print("[+] a2a messages:", len(agent_result["a2a_transcript"]["messages"]))
    print("[+] mcp tools:", len(agent_result["mcp_tools"]))

    report_path = save_report()
    print(f"[+] report generated: {report_path}")


if __name__ == "__main__":
    main()
