from __future__ import annotations

import json
from typing import Any, Dict, List, Type

from backend.a2a import A2AMessage, InMemoryA2ABus
from backend.agents.attack_path_agent import AttackPathAgent
from backend.agents.cloud_agent import CloudSecurityAgent
from backend.agents.dockerfile_agent import DockerfileAgent
from backend.agents.image_agent import ImageSecurityAgent
from backend.agents.k8s_agent import KubernetesSecurityAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.report_agent import ReportAgent
from backend.agents.runtime_agent import RuntimeEDRAgent
from backend.llm.provider import LLMProvider
from backend.mcp import LocalMCPClient


class SecuritySupervisorAgent:
    """Supervisor pattern: plan, call specialist agents, correlate, remediate, report."""

    name = "supervisor-agent"

    def __init__(self, mcp_client: LocalMCPClient | None = None, bus: InMemoryA2ABus | None = None) -> None:
        self.mcp = mcp_client or LocalMCPClient()
        self.bus = bus or InMemoryA2ABus()
        self.agents = {
            cls(self.mcp).name: cls(self.mcp)
            for cls in [
                DockerfileAgent,
                KubernetesSecurityAgent,
                CloudSecurityAgent,
                RuntimeEDRAgent,
                ImageSecurityAgent,
                AttackPathAgent,
                RemediationAgent,
                ReportAgent,
            ]
        }
        for agent in self.agents.values():
            self.bus.register(agent.card)

    def _normalize_inputs(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(inputs)
        runtime_events = data.get("runtime_events")
        if isinstance(runtime_events, str) and runtime_events:
            try:
                data["runtime_events"] = json.loads(runtime_events)
            except json.JSONDecodeError:
                data["runtime_events"] = []
        if isinstance(data.get("runtime_events"), dict):
            data["runtime_events"] = [data["runtime_events"]]
        kernel_events = data.get("kernel_events")
        if isinstance(kernel_events, str) and kernel_events:
            try:
                data["kernel_events"] = json.loads(kernel_events)
            except json.JSONDecodeError:
                data["kernel_events"] = []
        if isinstance(data.get("kernel_events"), dict):
            data["kernel_events"] = [data["kernel_events"]]
        return data

    def plan(self, inputs: Dict[str, Any]) -> List[Dict[str, Any]]:
        plan: List[Dict[str, Any]] = []
        if inputs.get("dockerfile_text"):
            plan.append({"agent": "dockerfile-agent", "reason": "Dockerfile 输入存在，执行规则检测 + Agent 检测"})
        if inputs.get("k8s_yaml_text"):
            plan.append({"agent": "kubernetes-agent", "reason": "K8s YAML 输入存在，检测 Pod Security/RBAC/暴露面"})
        if inputs.get("terraform_text") or inputs.get("cloud_config_text"):
            plan.append({"agent": "cloud-agent", "reason": "云/IaC 输入存在，检测 IAM、公开暴露、未加密、硬编码凭据"})
        if inputs.get("runtime_events") or inputs.get("kernel_events"):
            plan.append({"agent": "runtime-edr-agent", "reason": "运行时/内核级事件存在，执行 EDR 行为检测"})
        if inputs.get("image"):
            plan.append({"agent": "image-agent", "reason": "镜像输入存在，调用 Trivy 扫描 CVE"})
        plan.append({"agent": "attack-path-agent", "reason": "关联所有 findings，生成攻击路径"})
        plan.append({"agent": "remediation-agent", "reason": "对 findings 排序并生成修复计划"})
        plan.append({"agent": "report-agent", "reason": "生成摘要和报告上下文"})
        return plan

    def _send(self, conversation_id: str, recipient: str, payload: Dict[str, Any], intent: str = "analyze") -> Dict[str, Any]:
        message = A2AMessage(sender=self.name, recipient=recipient, intent=intent, payload=payload, role="supervisor", conversation_id=conversation_id)
        self.bus.emit(message)
        response = self.agents[recipient].handle(message)
        self.bus.emit(response)
        return response.payload

    def analyze(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        data = self._normalize_inputs(inputs)
        conversation = A2AMessage(sender="user", recipient=self.name, intent="security.analyze", payload={"input_keys": sorted([k for k, v in data.items() if v])}, role="user")
        self.bus.emit(conversation)
        conversation_id = conversation.conversation_id

        plan = self.plan(data)
        all_findings: List[Dict[str, Any]] = []
        agent_outputs: Dict[str, Any] = {}
        for step in plan:
            name = step["agent"]
            if name in {"attack-path-agent", "remediation-agent", "report-agent"}:
                continue
            output = self._send(conversation_id, name, data)
            agent_outputs[name] = output
            all_findings.extend(output.get("findings", []))

        attack_payload = self._send(conversation_id, "attack-path-agent", {"findings": all_findings})
        attack_paths = attack_payload.get("attack_paths", [])
        remed_payload = self._send(conversation_id, "remediation-agent", {"findings": all_findings, "attack_paths": attack_paths})
        final_findings = remed_payload.get("findings", all_findings)
        report_payload = self._send(conversation_id, "report-agent", {"findings": final_findings, "attack_paths": attack_paths})

        return {
            "architecture": "multi-agent-supervisor-a2a-mcp",
            "supervisor": self.name,
            "llm_provider": LLMProvider().safe_config(),
            "mcp_tools": self.mcp.list_tools(),
            "a2a_agent_cards": self.bus.discover(),
            "plan": plan,
            "agent_outputs": agent_outputs,
            "summary": report_payload.get("summary"),
            "executive_summary": report_payload.get("executive_summary"),
            "attack_paths": attack_paths,
            "priority_actions": remed_payload.get("priority_actions", []),
            "findings": final_findings,
            "llm_prompt_preview": report_payload.get("llm_prompt_preview"),
            "a2a_transcript": self.bus.get_transcript(conversation_id),
        }
