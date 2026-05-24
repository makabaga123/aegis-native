from __future__ import annotations

import json
from typing import Any, Dict, List

from backend.llm.remediation_generator import enrich_findings
from backend.scanners.cloud_config_scanner import scan_cloud_config_text
from backend.scanners.dockerfile_scanner import scan_dockerfile_text
from backend.scanners.k8s_yaml_scanner import scan_k8s_yaml_text
from backend.scanners.kernel_event_normalizer import normalize_kernel_events
from backend.scanners.runtime_edr import analyze_runtime_events
from backend.scanners.terraform_scanner import scan_terraform_text
from backend.scanners.trivy_image import scan_image_with_trivy


class SecurityToolRegistry:
    """MCP-style tool registry.

    It exposes scanner capabilities through a stable tool interface. The
    Supervisor and specialist agents call tools through this registry instead of
    importing scanner functions directly.
    """

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "dockerfile.rule_scan",
                "description": "Rule-based Dockerfile security audit",
                "input_schema": {"type": "object", "properties": {"text": {"type": "string"}, "target": {"type": "string"}}, "required": ["text"]},
            },
            {
                "name": "k8s.rule_scan",
                "description": "Rule-based Kubernetes YAML, Pod Security, RBAC and exposure audit",
                "input_schema": {"type": "object", "properties": {"text": {"type": "string"}, "target": {"type": "string"}}, "required": ["text"]},
            },
            {
                "name": "terraform.rule_scan",
                "description": "Rule-based Terraform/IaC cloud misconfiguration audit",
                "input_schema": {"type": "object", "properties": {"text": {"type": "string"}, "target": {"type": "string"}}, "required": ["text"]},
            },
            {
                "name": "cloud.rule_scan",
                "description": "Rule-based cloud inventory audit for public exposure, IAM and encryption risks",
                "input_schema": {"type": "object", "properties": {"text": {"type": "string"}, "target": {"type": "string"}}, "required": ["text"]},
            },
            {
                "name": "runtime.behavior_scan",
                "description": "Runtime EDR behavior detection over normalized process/file/network events",
                "input_schema": {"type": "object", "properties": {"events": {"type": "array"}}, "required": ["events"]},
            },
            {
                "name": "kernel.normalize_events",
                "description": "Normalize Falco/eBPF/Tetragon/KubeArmor kernel-level events into platform runtime event schema",
                "input_schema": {"type": "object", "properties": {"events": {"type": "array"}}, "required": ["events"]},
            },
            {
                "name": "image.trivy_scan",
                "description": "Trivy image vulnerability scan. Requires trivy binary in PATH.",
                "input_schema": {"type": "object", "properties": {"image": {"type": "string"}, "timeout": {"type": "integer"}}, "required": ["image"]},
            },
        ]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name == "dockerfile.rule_scan":
            findings = scan_dockerfile_text(arguments["text"], target=arguments.get("target") or "Dockerfile")
            return {"findings": enrich_findings(findings)}
        if name == "k8s.rule_scan":
            findings = scan_k8s_yaml_text(arguments["text"], target=arguments.get("target") or "k8s-yaml")
            return {"findings": enrich_findings(findings)}
        if name == "terraform.rule_scan":
            findings = scan_terraform_text(arguments["text"], target=arguments.get("target") or "terraform")
            return {"findings": enrich_findings(findings)}
        if name == "cloud.rule_scan":
            findings = scan_cloud_config_text(arguments["text"], target=arguments.get("target") or "cloud-config")
            return {"findings": enrich_findings(findings)}
        if name == "runtime.behavior_scan":
            events = arguments.get("events") or []
            if isinstance(events, str):
                events = json.loads(events)
            if isinstance(events, dict):
                events = [events]
            return {"findings": enrich_findings(analyze_runtime_events(events))}
        if name == "kernel.normalize_events":
            events = arguments.get("events") or []
            if isinstance(events, str):
                events = json.loads(events)
            if isinstance(events, dict):
                events = [events]
            return {"events": normalize_kernel_events(events)}
        if name == "image.trivy_scan":
            findings = scan_image_with_trivy(arguments["image"], timeout=int(arguments.get("timeout") or 120))
            return {"findings": enrich_findings(findings)}
        raise ValueError(f"Unknown MCP tool: {name}")
