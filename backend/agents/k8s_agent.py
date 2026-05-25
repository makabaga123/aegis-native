from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class KubernetesSecurityAgent(BaseSecurityAgent):
    name = "kubernetes-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Audits Kubernetes YAML, Pod Security, RBAC, exposure and policy gaps.",
            url="/a2a/kubernetes-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text", "file"],
            defaultOutputModes=["text", "json"],
            skills=[
                AgentSkill(
                    id="k8s_yaml_scan",
                    name="Kubernetes YAML Security Audit",
                    description="Detects privileged containers, hostPath, hostNetwork, hostPID, SYS_ADMIN, missing runAsNonRoot/readOnlyRootFilesystem, RBAC wildcards, Secret access, pods/exec, NodePort/LoadBalancer exposure",
                    tags=["security", "kubernetes", "pod-security", "rbac"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
            ],
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
