from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent


class ImageSecurityAgent(BaseSecurityAgent):
    name = "image-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Calls Trivy through MCP to scan container image CVEs and related image risks.",
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
