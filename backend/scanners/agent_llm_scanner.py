from __future__ import annotations

import json
from typing import Any, Dict, List

from backend.llm.provider import LLMProvider, mask_sensitive_text
from backend.scanners.common import make_finding, normalize_severity

SYSTEM_PROMPT = """You are a defensive cloud native security review agent.
Return strict JSON only. Do not include secrets. Detect security risks that may be missed by static rules.
Schema: {"findings":[{"rule_id":"AGENT001","severity":"LOW|MEDIUM|HIGH|CRITICAL","title":"...","description":"...","evidence":"...","fix":"...","category":"Agent LLM"}],"notes":["..."]}
Focus on Docker, Kubernetes, Terraform, cloud configuration and runtime security. Do not provide offensive exploitation steps.
"""


def local_agent_heuristics(artifact_type: str, text: str, target: str) -> List[Dict[str, Any]]:
    """A deterministic fallback so agent detection exists even without an LLM API key."""
    lower = text.lower()
    findings: List[Dict[str, Any]] = []
    if artifact_type in {"k8s", "terraform", "cloud"} and "0.0.0.0/0" in text and ("admin" in lower or "*" in text):
        findings.append(make_finding(
            rule_id="AGENT-H001",
            severity="HIGH",
            title="Agent 发现公网暴露与高权限配置组合风险",
            description="公网入口与高权限/IAM/RBAC 配置组合时，单点漏洞可能被放大成权限滥用链路。",
            evidence="artifact contains 0.0.0.0/0 and admin/* indicators",
            fix="收敛公网 CIDR；拆分管理面和业务面；最小化权限；为入口资源增加身份校验和审计。",
            source="agent-heuristic",
            target=target,
            category="Agent Detection",
        ))
    if artifact_type == "dockerfile" and "curl" in lower and "bash" in lower:
        findings.append(make_finding(
            rule_id="AGENT-H002",
            severity="MEDIUM",
            title="Agent 发现构建阶段远程脚本执行模式",
            description="Dockerfile 中使用 curl/wget 直接管道到 shell，会降低供应链可审计性。",
            evidence="curl/wget + bash/sh pattern",
            fix="固定下载地址和校验哈希；避免管道执行远程脚本；将安装步骤拆分并记录版本。",
            source="agent-heuristic",
            target=target,
            category="Agent Detection",
        ))
    return findings


def llm_analyze_artifact(artifact_type: str, text: str, target: str, provider: LLMProvider | None = None) -> Dict[str, Any]:
    provider = provider or LLMProvider()
    masked = mask_sensitive_text(text)
    fallback = local_agent_heuristics(artifact_type, masked, target)
    user_prompt = json.dumps({"artifact_type": artifact_type, "target": target, "content": masked}, ensure_ascii=False)
    response = provider.chat_json(system=SYSTEM_PROMPT, user=user_prompt)
    findings: List[Dict[str, Any]] = list(fallback)
    notes: List[str] = []

    if response.configured and response.content and not response.error:
        parsed = provider.parse_json_content(response.content)
        for idx, item in enumerate(parsed.get("findings", []) if isinstance(parsed.get("findings"), list) else []):
            findings.append(make_finding(
                rule_id=str(item.get("rule_id") or f"AGENT-L{idx+1:03d}"),
                severity=normalize_severity(item.get("severity")),
                title=str(item.get("title") or "LLM Agent detected risk"),
                description=str(item.get("description") or "LLM Agent detected a possible cloud-native security risk."),
                evidence=str(item.get("evidence") or "LLM evidence omitted"),
                fix=str(item.get("fix") or "Review and remediate according to least privilege and secure baseline."),
                source=f"llm-agent:{response.provider}",
                target=target,
                category=str(item.get("category") or "Agent LLM"),
            ))
        if isinstance(parsed.get("notes"), list):
            notes.extend(str(x) for x in parsed["notes"][:10])
    else:
        notes.append(response.error or "LLM provider disabled; used local deterministic agent heuristics.")

    return {
        "provider": provider.safe_config(),
        "findings": findings,
        "notes": notes,
        "prompt_preview": user_prompt[:2000],
    }
