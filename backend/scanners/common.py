from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(severity: str | None) -> str:
    if not severity:
        return "INFO"
    s = severity.upper()
    if s in {"EMERGENCY", "ALERT", "CRITICAL"}:
        return "CRITICAL"
    if s in {"ERROR", "ERR", "HIGH"}:
        return "HIGH"
    if s in {"WARNING", "WARN", "MEDIUM"}:
        return "MEDIUM"
    if s in {"NOTICE", "LOW"}:
        return "LOW"
    return "INFO"


def make_finding(
    *,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    fix: str,
    source: str,
    target: str,
    category: str,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": normalize_severity(severity),
        "title": title,
        "description": description,
        "evidence": evidence,
        "fix": fix,
        "source": source,
        "target": target,
        "category": category,
        "created_at": now_iso(),
        "extra": extra or {},
    }


def summarize_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    total_score = 0
    finding_list = list(findings)
    for item in finding_list:
        severity = normalize_severity(item.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1
        total_score += SEVERITY_WEIGHT.get(severity, 0)

    if total_score >= 80:
        risk_level = "严重风险"
    elif total_score >= 51:
        risk_level = "高风险"
    elif total_score >= 21:
        risk_level = "中风险"
    else:
        risk_level = "低风险"

    return {
        "total": len(finding_list),
        "counts": counts,
        "risk_score": min(total_score, 100),
        "raw_score": total_score,
        "risk_level": risk_level,
    }


def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rank = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}
    return sorted(findings, key=lambda x: rank.get(normalize_severity(x.get("severity")), 999))
