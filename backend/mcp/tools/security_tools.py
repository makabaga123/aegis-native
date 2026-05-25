"""Standard MCP tool registry — security scanning tools.

Each tool is defined with a standard MCP inputSchema (JSON Schema).
"""

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
    """Standard MCP tool registry.

    Each tool exposes a standard MCP inputSchema (JSON Schema) so that
    MCP-compatible clients (Claude Desktop, Continue, Cursor, etc.)
    can discover and call security scanning capabilities.
    """

    # ── Tool definitions ─────────────────────────────────────────────────

    TOOL_DEFINITIONS: List[Dict[str, Any]] = [
        {
            "name": "dockerfile.rule_scan",
            "description": "Rule-based Dockerfile security audit — detects latest tag, root user, ADD instead of COPY, hardcoded secrets, dangerous tools, curl-pipe-bash patterns, missing HEALTHCHECK, and more.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Dockerfile content to scan"},
                    "target": {"type": "string", "description": "File name or identifier for the scanned artifact"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "k8s.rule_scan",
            "description": "Rule-based Kubernetes security audit — detects privileged containers, hostPath mounts, hostNetwork/hostPID/hostIPC, SYS_ADMIN capability, missing runAsNonRoot/readOnlyRootFilesystem, RBAC wildcard permissions, Secret access, pods/exec privileges, and NodePort/LoadBalancer exposure.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Kubernetes YAML manifest content to scan"},
                    "target": {"type": "string", "description": "File name or resource identifier"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "terraform.rule_scan",
            "description": "Rule-based Terraform/IaC security audit — detects 0.0.0.0/0 security groups, public S3/OSS/COS buckets, IAM wildcard actions/resources, hardcoded credentials, unencrypted resources, and missing MFA.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Terraform HCL content to scan"},
                    "target": {"type": "string", "description": "File name or module identifier"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "cloud.rule_scan",
            "description": "Rule-based cloud configuration audit — detects public network exposure, public object storage, MFA absence, AccessKey leakage, IAM over-privilege, and unencrypted resources.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Cloud configuration JSON content to scan"},
                    "target": {"type": "string", "description": "Configuration name or resource identifier"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "runtime.behavior_scan",
            "description": "Runtime EDR behavior detection — analyzes normalized process/file/network events for shell spawning, reverse shells, crypto mining, sensitive file access, docker.sock access, ServiceAccount token theft, and anomalous outbound connections.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "description": "Array of normalized runtime event objects to analyze",
                        "items": {"type": "object"},
                    },
                },
                "required": ["events"],
            },
        },
        {
            "name": "kernel.normalize_events",
            "description": "Kernel event normalization — converts Falco/eBPF, Tetragon/eBPF, KubeArmor/LSM, and generic syscall events into the platform's unified runtime event schema.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "description": "Array of raw kernel-level events to normalize",
                        "items": {"type": "object"},
                    },
                },
                "required": ["events"],
            },
        },
        {
            "name": "image.trivy_scan",
            "description": "Trivy container image vulnerability scan — returns CVEs with severity (Critical/High/Medium/Low), affected package, current version, and fix version. Requires trivy binary in PATH.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Container image reference (e.g. 'nginx:latest', 'registry.example.com/app:v1')"},
                    "timeout": {"type": "integer", "description": "Scan timeout in seconds (default: 120)"},
                },
                "required": ["image"],
            },
        },
    ]

    # ── Public API ───────────────────────────────────────────────────────

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return all registered tools in standard MCP format."""
        return self.TOOL_DEFINITIONS

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a tool call by name and return the result."""
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
