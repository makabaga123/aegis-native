from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent
from backend.scanners.agent_llm_scanner import llm_analyze_artifact


class DockerfileAgent(BaseSecurityAgent):
    name = "dockerfile-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Detects insecure Dockerfile build practices through MCP rules and optional LLM agent review.",
            url="/a2a/dockerfile-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text", "file"],
            defaultOutputModes=["text", "json"],
            skills=[
                AgentSkill(
                    id="dockerfile_rule_scan",
                    name="Dockerfile Security Scan",
                    description="Rule-based detection of latest tag, root user, ADD vs COPY, hardcoded secrets, dangerous tools, curl-pipe-bash, missing HEALTHCHECK",
                    tags=["security", "docker", "container", "supply-chain"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
                AgentSkill(
                    id="dockerfile_llm_review",
                    name="Dockerfile LLM Review",
                    description="LLM-assisted review of Dockerfile best practices and supply chain risks",
                    tags=["security", "docker", "llm", "supply-chain"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
            ],
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
