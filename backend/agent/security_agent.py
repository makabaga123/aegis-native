from __future__ import annotations

import json
from typing import Any, Dict, List

from backend.llm.agent_brain import SecurityAgentBrain
from backend.llm.remediation_generator import enrich_findings
from backend.models.database import create_task, finish_task, save_findings
from backend.scanners.cloud_config_scanner import scan_cloud_config_text
from backend.scanners.common import summarize_findings
from backend.scanners.dockerfile_scanner import scan_dockerfile_text
from backend.scanners.k8s_yaml_scanner import scan_k8s_yaml_text
from backend.scanners.runtime_edr import analyze_runtime_events
from backend.scanners.terraform_scanner import scan_terraform_text
from backend.scanners.trivy_image import scan_image_with_trivy


class CloudNativeSecurityAgent:
    """Agent coordinator: Plan -> Scan -> Correlate -> Explain -> Report data."""

    def __init__(self, brain: SecurityAgentBrain | None = None) -> None:
        self.brain = brain or SecurityAgentBrain()

    def analyze(self, inputs: Dict[str, Any], *, persist: bool = False) -> Dict[str, Any]:
        plan = self.brain.plan(inputs)
        all_findings: List[Dict[str, Any]] = []
        task_ids: List[int] = []

        def run_task(task_type: str, target: str, scanner_result: List[Dict[str, Any]]) -> None:
            nonlocal all_findings, task_ids
            findings = enrich_findings(scanner_result)
            all_findings.extend(findings)
            if persist:
                task_id = create_task(task_type, target)
                save_findings(task_id, findings)
                finish_task(task_id, "finished", summarize_findings(findings))
                task_ids.append(task_id)

        if inputs.get("dockerfile_text"):
            run_task("agent_dockerfile_scan", inputs.get("dockerfile_target") or "Dockerfile", scan_dockerfile_text(inputs["dockerfile_text"], target=inputs.get("dockerfile_target") or "Dockerfile"))

        if inputs.get("k8s_yaml_text"):
            run_task("agent_k8s_yaml_scan", inputs.get("k8s_target") or "k8s-yaml", scan_k8s_yaml_text(inputs["k8s_yaml_text"], target=inputs.get("k8s_target") or "k8s-yaml"))

        if inputs.get("terraform_text"):
            run_task("agent_terraform_scan", inputs.get("terraform_target") or "terraform", scan_terraform_text(inputs["terraform_text"], target=inputs.get("terraform_target") or "terraform"))

        if inputs.get("cloud_config_text"):
            run_task("agent_cloud_config_scan", inputs.get("cloud_config_target") or "cloud-config", scan_cloud_config_text(inputs["cloud_config_text"], target=inputs.get("cloud_config_target") or "cloud-config"))

        runtime_events = inputs.get("runtime_events") or []
        if isinstance(runtime_events, str):
            try:
                runtime_events = json.loads(runtime_events)
            except json.JSONDecodeError:
                runtime_events = []
        if isinstance(runtime_events, dict):
            runtime_events = [runtime_events]
        if runtime_events:
            run_task("agent_runtime_edr_scan", "runtime-events", analyze_runtime_events(runtime_events))

        if inputs.get("image"):
            run_task("agent_image_scan", inputs["image"], scan_image_with_trivy(inputs["image"], timeout=int(inputs.get("trivy_timeout") or 120)))

        attack_paths = self.brain.correlate_attack_paths(all_findings)
        priority_actions = self.brain.prioritize(all_findings)
        for item in all_findings:
            item["agent_explanation"] = self.brain.explain_finding(item)

        return {
            "agent": {
                "name": "CloudNativeSecurityAgent",
                "mode": self.brain.mode,
                "workflow": ["plan", "scan", "correlate", "explain", "prioritize"],
            },
            "plan": plan,
            "summary": summarize_findings(all_findings),
            "executive_summary": self.brain.executive_summary(all_findings, attack_paths),
            "attack_paths": attack_paths,
            "priority_actions": priority_actions,
            "findings": all_findings,
            "task_ids": task_ids,
            "llm_prompt_preview": self.brain.as_json_prompt(all_findings, attack_paths),
        }
