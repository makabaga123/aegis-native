from __future__ import annotations

from backend.a2a import A2AMessage, AgentCard
from backend.agents.base import BaseSecurityAgent


class RuntimeEDRAgent(BaseSecurityAgent):
    name = "runtime-edr-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Analyzes normalized runtime EDR events from Falco/eBPF/Tetragon/KubeArmor and generic sensors.",
            capabilities=["runtime_behavior_detection", "kernel_event_normalization", "container_edr"],
            input_types=["runtime_events", "kernel_events"],
            output_types=["findings", "normalized_events"],
        )

    def handle(self, message: A2AMessage) -> A2AMessage:
        events = message.payload.get("runtime_events") or []
        kernel_events = message.payload.get("kernel_events") or []
        normalized = []
        if kernel_events:
            normalized = self.mcp.call_tool("kernel.normalize_events", {"events": kernel_events}).get("events", [])
            events = list(events or []) + normalized
        findings = self.mcp.call_tool("runtime.behavior_scan", {"events": events}).get("findings", []) if events else []
        return self._result(message, {"agent": self.name, "findings": findings, "normalized_events": normalized, "notes": []})
