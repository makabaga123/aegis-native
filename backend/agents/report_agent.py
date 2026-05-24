from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.llm.agent_brain import SecurityAgentBrain
from backend.scanners.common import summarize_findings


class ReportAgent(BaseSecurityAgent):
    name = "report-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Builds executive summary and report-ready data.",
            capabilities=["summary", "report_context", "interview_story"],
            input_types=["findings", "attack_paths"],
            output_types=["summary", "executive_summary"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        findings = message.payload.get("findings") or []
        attack_paths = message.payload.get("attack_paths") or []
        brain = SecurityAgentBrain()
        return self._result(message, {
            "agent": self.name,
            "summary": summarize_findings(findings),
            "executive_summary": brain.executive_summary(findings, attack_paths),
            "llm_prompt_preview": brain.as_json_prompt(findings, attack_paths),
        })
