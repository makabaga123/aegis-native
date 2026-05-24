from __future__ import annotations

import re
from typing import Any, Dict, List

SENSITIVE_PATTERN = re.compile(r"(?i)(AKIA[0-9A-Z]{12,}|eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+|password\s*=\s*[^\s]+|token\s*=\s*[^\s]+|api[_-]?key\s*=\s*[^\s]+)")


def mask_sensitive(text: str) -> str:
    return SENSITIVE_PATTERN.sub("[MASKED_SECRET]", text or "")


def generate_remediation(finding: Dict[str, Any]) -> str:
    """本地规则版修复建议生成器。真实项目中可以在这里接 OpenAI / 本地大模型。"""
    rule_id = str(finding.get("rule_id", ""))
    title = str(finding.get("title", ""))
    fix = mask_sensitive(str(finding.get("fix", "")))

    if rule_id.startswith("K8S007") or "privileged" in title.lower():
        return "删除 privileged: true；设置 allowPrivilegeEscalation: false；drop ALL capabilities；只按需添加最小 capability。"
    if rule_id.startswith("K8S005") or "hostPath" in title:
        return "避免挂载宿主机敏感路径；改用 PVC/ConfigMap/Secret；如必须使用 hostPath，请限定只读并限制路径。"
    if rule_id.startswith("DF010") or "USER" in title:
        return "在 Dockerfile 中创建普通用户，复制文件后执行 chown，并使用 USER appuser 运行应用。"
    if rule_id.startswith("IMG") or "镜像" in title:
        return "固定镜像版本或 digest；定期重建基础镜像；优先选择 slim/alpine/distroless 等较小基础镜像。"
    return fix or "按最小权限、最小镜像、最小暴露面的原则进行加固。"


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for item in findings:
        item["remediation"] = generate_remediation(item)
        item["evidence"] = mask_sensitive(str(item.get("evidence", "")))
    return findings
