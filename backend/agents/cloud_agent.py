from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class CloudSecurityAgent(BaseSecurityAgent):
    name = "cloud-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Reviews cloud inventory and Terraform/IaC for exposure, IAM, encryption and secret risks.",
            url="/a2a/cloud-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text", "file"],
            defaultOutputModes=["text", "json"],
            skills=[
                AgentSkill(
                    id="terraform_scan",
                    name="Terraform Security Audit",
                    description="Detects 0.0.0.0/0 security groups, public S3/OSS/COS buckets, IAM wildcard actions/resources, hardcoded credentials, unencrypted resources, missing MFA",
                    tags=["security", "terraform", "iac", "cloud"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
                AgentSkill(
                    id="cloud_config_scan",
                    name="Cloud Configuration Audit",
                    description="Detects public network exposure, public object storage, MFA absence, AccessKey leakage, IAM over-privilege, unencrypted resources",
                    tags=["security", "cloud", "aws", "azure", "gcp"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
            ],
            capabilities=["terraform_scan", "cloud_inventory_scan", "iam_review", "exposure_review"],
            input_types=["terraform_text", "cloud_config_text"],
            output_types=["findings", "cloud_risk_notes"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        findings = []
        notes = []
        llm_info = []
        if message.payload.get("terraform_text"):
            text = message.payload["terraform_text"]
            target = message.payload.get("terraform_target") or "terraform"
            findings += self.mcp.call_tool("terraform.rule_scan", {"text": text, "target": target}).get("findings", [])
            agent_result = llm_analyze_artifact("terraform", text, target)
            findings += agent_result.get("findings", [])
            notes += agent_result.get("notes", [])
            llm_info.append(agent_result.get("provider"))
        if message.payload.get("cloud_config_text"):
            text = message.payload["cloud_config_text"]
            target = message.payload.get("cloud_config_target") or "cloud-config"
            findings += self.mcp.call_tool("cloud.rule_scan", {"text": text, "target": target}).get("findings", [])
            agent_result = llm_analyze_artifact("cloud", text, target)
            findings += agent_result.get("findings", [])
            notes += agent_result.get("notes", [])
            llm_info.append(agent_result.get("provider"))
        return self._result(message, {"agent": self.name, "findings": findings, "llm": llm_info, "notes": notes})
