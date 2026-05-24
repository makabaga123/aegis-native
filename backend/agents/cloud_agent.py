from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class CloudSecurityAgent(BaseSecurityAgent):
    name = "cloud-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Reviews cloud inventory and Terraform/IaC for exposure, IAM, encryption and secret risks.",
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
