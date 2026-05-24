from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class KubernetesSecurityAgent(BaseSecurityAgent):
    name = "kubernetes-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Audits Kubernetes YAML, Pod Security, RBAC, exposure and policy gaps.",
            capabilities=["pod_security", "rbac_review", "network_exposure", "llm_k8s_reasoning"],
            input_types=["k8s_yaml_text"],
            output_types=["findings", "attack_primitives"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        text = message.payload.get("k8s_yaml_text") or ""
        target = message.payload.get("k8s_target") or "k8s-yaml"
        rule_result = self.mcp.call_tool("k8s.rule_scan", {"text": text, "target": target})
        agent_result = llm_analyze_artifact("k8s", text, target)
        return self._result(message, {
            "agent": self.name,
            "findings": rule_result.get("findings", []) + agent_result.get("findings", []),
            "llm": agent_result.get("provider"),
            "notes": agent_result.get("notes", []),
        })
