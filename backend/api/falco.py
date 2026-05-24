from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body

from backend.llm.remediation_generator import enrich_findings
from backend.models.database import save_falco_event
from backend.scanners.falco_parser import parse_falco_event
from backend.schemas import FalcoEventResponse

router = APIRouter(prefix="/api/falco", tags=["falco"])


@router.post("/events", response_model=FalcoEventResponse)
def receive_falco_event(event: Dict[str, Any] = Body(...)):
    finding = enrich_findings([parse_falco_event(event)])[0]
    save_falco_event(event, finding)
    return FalcoEventResponse(status="received", finding=finding)
