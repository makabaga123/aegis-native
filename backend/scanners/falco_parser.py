from __future__ import annotations

from typing import Any, Dict

from backend.scanners.common import make_finding, normalize_severity


def parse_falco_event(event: Dict[str, Any]) -> Dict[str, Any]:
    fields = event.get("output_fields") or {}
    rule = event.get("rule") or event.get("rule_name") or "Unknown Falco Rule"
    priority = event.get("priority") or event.get("level") or "WARNING"
    severity = normalize_severity(priority)

    namespace = fields.get("k8s.ns.name") or fields.get("k8s.namespace.name") or event.get("namespace") or "unknown"
    pod = fields.get("k8s.pod.name") or event.get("pod") or "unknown"
    container = fields.get("container.name") or event.get("container_name") or "unknown"
    output = event.get("output") or event.get("message") or "Falco runtime event"

    rule_lower = str(rule).lower()
    if "shell" in rule_lower:
        fix = "排查应用是否被 WebShell 或命令执行漏洞利用；限制容器内 shell 工具；启用只读根文件系统并降低容器权限。"
    elif "shadow" in rule_lower or "/etc" in str(output):
        fix = "排查容器内敏感文件读取行为；收紧文件权限；使用最小权限用户运行容器。"
    elif "outbound" in rule_lower or "connection" in rule_lower:
        fix = "核查外联目标是否可信；使用 NetworkPolicy 限制不必要的出站流量。"
    else:
        fix = "结合 Pod、镜像、命令行和网络行为进行排查，必要时隔离该工作负载。"

    return make_finding(
        rule_id=f"FALCO-{str(rule).upper().replace(' ', '-')[:60]}",
        severity=severity,
        title=f"Falco 运行时告警：{rule}",
        description="Falco 在容器运行阶段捕获到异常行为，说明部署后的运行态可能存在攻击、误配置或违规操作。",
        evidence=output,
        fix=fix,
        source="falco",
        target=f"{namespace}/{pod}/{container}",
        category="Runtime",
        extra={"raw_event": event},
    )
