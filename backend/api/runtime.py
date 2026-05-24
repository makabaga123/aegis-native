from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body

from backend.llm.remediation_generator import enrich_findings
from backend.models.database import list_runtime_events, save_runtime_event
from backend.scanners.common import summarize_findings
from backend.scanners.runtime_edr import analyze_runtime_event, analyze_runtime_events
from backend.schemas import RuntimeEventResponse

router = APIRouter(prefix="/api/runtime", tags=["runtime-edr"])


@router.post("/events", response_model=RuntimeEventResponse)
def receive_runtime_event(event: Dict[str, Any] = Body(...)):
    findings = enrich_findings(analyze_runtime_event(event))
    save_runtime_event(event, findings)
    return RuntimeEventResponse(status="received", summary=summarize_findings(findings), findings=findings)


@router.post("/events/batch")
def receive_runtime_events(events: List[Dict[str, Any]] = Body(...)):
    findings = enrich_findings(analyze_runtime_events(events))
    for event in events:
        event_findings = enrich_findings(analyze_runtime_event(event))
        save_runtime_event(event, event_findings)
    return {"status": "received", "summary": summarize_findings(findings), "findings": findings}


@router.get("/timeline")
def runtime_timeline(limit: int = 200):
    return {"items": list_runtime_events(limit=limit)}
