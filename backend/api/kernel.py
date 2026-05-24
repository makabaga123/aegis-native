from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body

from backend.llm.remediation_generator import enrich_findings
from backend.models.database import save_runtime_event
from backend.scanners.common import summarize_findings
from backend.scanners.kernel_event_normalizer import normalize_kernel_event, normalize_kernel_events
from backend.scanners.runtime_edr import analyze_runtime_event, analyze_runtime_events

router = APIRouter(prefix="/api/kernel", tags=["kernel-runtime-collector"])


@router.post("/events")
def receive_kernel_event(event: Dict[str, Any] = Body(...)):
    normalized = normalize_kernel_event(event)
    findings = enrich_findings(analyze_runtime_event(normalized))
    save_runtime_event(normalized, findings)
    return {"status": "received", "normalized_event": normalized, "summary": summarize_findings(findings), "findings": findings}


@router.post("/events/batch")
def receive_kernel_events(events: List[Dict[str, Any]] = Body(...)):
    normalized = normalize_kernel_events(events)
    findings = enrich_findings(analyze_runtime_events(normalized))
    for event in normalized:
        save_runtime_event(event, enrich_findings(analyze_runtime_event(event)))
    return {"status": "received", "normalized_count": len(normalized), "summary": summarize_findings(findings), "findings": findings}
