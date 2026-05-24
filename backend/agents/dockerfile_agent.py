from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class DockerfileAgent(BaseSecurityAgent):
    name = "dockerfile-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Detects insecure Dockerfile build practices through MCP rules and optional LLM agent review.",
            capabilities=["dockerfile_rule_scan", "dockerfile_llm_review", "supply_chain_baseline"],
            input_types=["dockerfile_text"],
            output_types=["findings", "agent_notes"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        text = message.payload.get("dockerfile_text") or ""
        target = message.payload.get("dockerfile_target") or "Dockerfile"
        rule_result = self.mcp.call_tool("dockerfile.rule_scan", {"text": text, "target": target})
        agent_result = llm_analyze_artifact("dockerfile", text, target)
        return self._result(message, {
            "agent": self.name,
            "findings": rule_result.get("findings", []) + agent_result.get("findings", []),
            "llm": agent_result.get("provider"),
            "notes": agent_result.get("notes", []),
        })
