from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.llm.agent_brain import SecurityAgentBrain


class AttackPathAgent(BaseSecurityAgent):
    name = "attack-path-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Correlates static findings and runtime findings into attack paths.",
            capabilities=["risk_correlation", "attack_path_generation", "kill_chain_summary"],
            input_types=["findings"],
            output_types=["attack_paths"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        findings = message.payload.get("findings") or []
        brain = SecurityAgentBrain()
        return self._result(message, {"agent": self.name, "attack_paths": brain.correlate_attack_paths(findings)})
