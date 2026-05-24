from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

from backend.models.database import list_findings, list_tasks
from backend.reports.generator import render_report, save_report

router = APIRouter(prefix="/api/report", tags=["report"])


@router.get("/html", response_class=HTMLResponse)
def report_html():
    return HTMLResponse(render_report())


@router.get("/file")
def report_file():
    path = save_report()
    return FileResponse(path, media_type="text/html", filename=path.name)


@router.get("/findings")
def findings(limit: int = 200):
    return {"items": list_findings(limit=limit)}


@router.get("/tasks")
def tasks(limit: int = 100):
    return {"items": list_tasks(limit=limit)}
