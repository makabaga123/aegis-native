from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent
from backend.llm.agent_brain import SecurityAgentBrain


class AttackPathAgent(BaseSecurityAgent):
    name = "attack-path-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Correlates static findings and runtime findings into attack paths.",
            url="/a2a/attack-path-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text", "json"],
            defaultOutputModes=["json"],
            skills=[
                AgentSkill(
                    id="attack_path_correlation",
                    name="Attack Path Correlation",
                    description="Correlates Dockerfile, K8s, cloud, and runtime findings into container escape, lateral movement, and cloud privilege escalation attack paths",
                    tags=["security", "attack-path", "correlation", "kill-chain"],
                    inputModes=["json"],
                    outputModes=["json"],
                ),
            ],
            capabilities=["risk_correlation", "attack_path_generation", "kill_chain_summary"],
            input_types=["findings"],
            output_types=["attack_paths"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        findings = message.payload.get("findings") or []
        brain = SecurityAgentBrain()
        return self._result(message, {"agent": self.name, "attack_paths": brain.correlate_attack_paths(findings)})
