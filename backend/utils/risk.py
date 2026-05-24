from __future__ import annotations

from typing import Any, Dict, Iterable

from backend.scanners.common import summarize_findings


def calculate_risk(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """统一风险评分入口，方便后续替换为更复杂的模型。"""
    return summarize_findings(findings)
