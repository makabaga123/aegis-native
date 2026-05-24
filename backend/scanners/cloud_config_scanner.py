from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, Iterable, List

from backend.scanners.common import make_finding, sort_findings


def _walk(obj: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def _is_public_cidr(value: str) -> bool:
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net) in {"0.0.0.0/0", "::/0"}
    except Exception:
        return False


def scan_cloud_config_text(text: str, target: str = "cloud-config-json") -> List[Dict[str, Any]]:
    """Scan exported cloud resource JSON / simplified inventory for risky public-cloud settings.

    It supports lightweight AWS/Azure/GCP-like JSON. This is intentionally credential-free,
    so the project can be demoed without touching real cloud accounts.
    """
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [make_finding(
            rule_id="CLOUD000",
            severity="HIGH",
            title="云配置 JSON 解析失败",
            description="云资源清单格式错误会导致检测遗漏。",
            evidence=str(exc),
            fix="导出合法 JSON，或使用平台支持的云资源清单格式。",
            source="cloud-config-agent",
            target=target,
            category="Cloud Security",
        )]

    for path, value in _walk(data):
        key = path.lower()
        val = str(value).strip() if not isinstance(value, (dict, list)) else ""

        if isinstance(value, str) and _is_public_cidr(value):
            _severity = "CRITICAL" if re.search(r"(ingress|inbound|cidr|source)", key) else "HIGH"
            findings.append(make_finding(
                rule_id="CLOUD001",
                severity=_severity,
                title="云安全组/防火墙规则向公网开放",
                description="0.0.0.0/0 或 ::/0 暴露到公网，若端口为 SSH/RDP/数据库/控制面服务，风险极高。",
                evidence=f"{path}={value}",
                fix="限制来源 CIDR；对管理端口使用 VPN/堡垒机；为公网服务增加 WAF、认证和速率限制。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

        if re.search(r"(?i)(publicread|public-read|allusers|allauthenticatedusers)", val):
            findings.append(make_finding(
                rule_id="CLOUD002",
                severity="CRITICAL",
                title="对象存储 Bucket 疑似公开访问",
                description="S3/GCS/Blob 等对象存储公开读写可能导致敏感数据泄露或供应链投毒。",
                evidence=f"{path}={val}",
                fix="关闭 public access；使用最小权限 Bucket Policy；开启访问日志、版本控制和加密。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

        if re.search(r"(?i)(password|secret|token|accesskey|secretkey|privatekey|api[_-]?key)", path) and val and not re.search(r"(?i)(arn:|\$\{|ref|secretKeyRef|keyvault|secretsmanager)", val):
            findings.append(make_finding(
                rule_id="CLOUD003",
                severity="CRITICAL",
                title="云配置中疑似硬编码凭据",
                description="AccessKey、Token、密码等凭据出现在配置清单中，可能被 Git、日志或报告泄露。",
                evidence=f"{path}=[MASKED_SECRET]",
                fix="立即轮换凭据；迁移到 KMS/Secrets Manager/Key Vault/Secret Manager；避免明文进入 IaC 和日志。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

        if re.search(r"(?i)(action|policy|permissions|allowedactions)", path) and val in {"*", "[*]"}:
            findings.append(make_finding(
                rule_id="CLOUD004",
                severity="HIGH",
                title="IAM 权限过宽",
                description="IAM Action 或权限字段使用 *，一旦凭据泄露会造成大范围横向移动和资源控制风险。",
                evidence=f"{path}={val}",
                fix="按最小权限拆分策略；限制资源 ARN；为高危操作增加条件和审批；启用审计告警。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

        if re.search(r"(?i)(encrypted|encryptionenabled|kmskey|sse)", path) and val.lower() in {"false", "none", "disabled", "null"}:
            findings.append(make_finding(
                rule_id="CLOUD005",
                severity="MEDIUM",
                title="云资源未启用加密",
                description="存储、数据库或日志资源未加密会增加数据泄露后的影响面。",
                evidence=f"{path}={val}",
                fix="启用默认加密；优先使用 KMS/CMK；为快照、备份和日志同样开启加密。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

        if re.search(r"(?i)(mfadelete|mfa_enabled|mfaenabled)", path) and val.lower() in {"false", "disabled"}:
            findings.append(make_finding(
                rule_id="CLOUD006",
                severity="MEDIUM",
                title="高危账号或存储保护未启用 MFA",
                description="缺少 MFA 会增加账号接管、删除备份或破坏数据的风险。",
                evidence=f"{path}={val}",
                fix="为控制台账号、Root 账号、关键删除操作和存储版本删除启用 MFA 或等价强认证。",
                source="cloud-config-agent",
                target=target,
                category="Cloud Security",
            ))

    return sort_findings(findings)


def scan_cloud_config_path(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return scan_cloud_config_text(f.read(), target=path)
