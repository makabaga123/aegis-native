from __future__ import annotations

from backend.a2a import A2AMessage, AgentCapabilities, AgentCard, AgentProvider, AgentSkill
from backend.agents.base import BaseSecurityAgent


class RuntimeEDRAgent(BaseSecurityAgent):
    name = "runtime-edr-agent"

    @property
    def card(self) -> AgentCard:
        return AgentCard(
            name=self.name,
            description="Analyzes normalized runtime EDR events from Falco/eBPF/Tetragon/KubeArmor and generic sensors.",
            url="/a2a/runtime-edr-agent",
            provider=AgentProvider(organization="AegisNative"),
            version="2.0.0",
            a2a_capabilities=AgentCapabilities(),
            defaultInputModes=["text", "file"],
            defaultOutputModes=["text", "json"],
            skills=[
                AgentSkill(
                    id="runtime_behavior_detection",
                    name="Runtime EDR Behavior Detection",
                    description="Detects shell spawning, reverse shells, crypto mining, sensitive file access, docker.sock access, ServiceAccount token theft, anomalous outbound connections",
                    tags=["security", "runtime", "edr", "falco", "ebpf"],
                    inputModes=["text", "file"],
                    outputModes=["json"],
                ),
                AgentSkill(
                    id="kernel_event_normalization",
                    name="Kernel Event Normalization",
                    description="Normalizes Falco/eBPF, Tetragon/eBPF, KubeArmor/LSM events into unified runtime event schema",
                    tags=["security", "kernel", "falco", "tetragon", "ebpf"],
                    inputModes=["text", "file"],
                    outputModes=["json"],
                ),
            ],
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
