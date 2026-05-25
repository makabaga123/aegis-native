from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent


class ImageSecurityAgent(BaseSecurityAgent):
    name = "image-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Calls Trivy through MCP to scan container image CVEs and related image risks.",
            url="/a2a/image-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text"],
            defaultOutputModes=["text", "json"],
            skills=[
                AgentSkill(
                    id="trivy_image_scan",
                    name="Trivy Image Vulnerability Scan",
                    description="Scans container images for CVEs using Trivy, returns severity breakdown (Critical/High/Medium/Low), affected packages, current versions, and fix versions",
                    tags=["security", "container", "cve", "trivy", "vulnerability"],
                    inputModes=["text"],
                    outputModes=["json"],
                ),
            ],
            capabilities=["trivy_image_scan", "cve_summary"],
            input_types=["image"],
            output_types=["findings"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        image = message.payload.get("image")
        timeout = message.payload.get("trivy_timeout") or 120
        findings = []
        if image:
            findings = self.mcp.call_tool("image.trivy_scan", {"image": image, "timeout": timeout}).get("findings", [])
        return self._result(message, {"agent": self.name, "findings": findings, "notes": []})
