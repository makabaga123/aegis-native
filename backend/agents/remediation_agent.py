from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.llm.agent_brain import SecurityAgentBrain


class RemediationAgent(BaseSecurityAgent):
    name = "remediation-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Prioritizes findings and generates remediation actions.",
            capabilities=["priority_ranking", "remediation_plan", "secure_baseline_guidance"],
            input_types=["findings"],
            output_types=["priority_actions", "finding_explanations"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        findings = message.payload.get("findings") or []
        brain = SecurityAgentBrain()
        priority_actions = brain.prioritize(findings)
        for item in findings:
            item["agent_explanation"] = brain.explain_finding(item)
        return self._result(message, {"agent": self.name, "priority_actions": priority_actions, "findings": findings})
