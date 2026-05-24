from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.llm.remediation_generator import enrich_findings
from backend.models.database import list_findings, list_tasks
from backend.scanners.common import sort_findings, summarize_findings

REPORT_DIR = Path(__file__).resolve().parent
GENERATED_DIR = REPORT_DIR / "generated"


def render_report(findings: List[Dict[str, Any]] | None = None, tasks: List[Dict[str, Any]] | None = None) -> str:
    findings = enrich_findings(findings if findings is not None else list_findings())
    findings = sort_findings(findings)
    tasks = tasks if tasks is not None else list_tasks()
    summary = summarize_findings(findings)

    env = Environment(
        loader=FileSystemLoader(REPORT_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report_template.html")
    return template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary=summary,
        findings=findings,
        tasks=tasks,
    )


def save_report() -> Path:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    path = GENERATED_DIR / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    path.write_text(render_report(), encoding="utf-8")
    return path
