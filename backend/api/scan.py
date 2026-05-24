from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.llm.remediation_generator import enrich_findings
from backend.models.database import create_task, finish_task, save_findings
from backend.scanners.common import summarize_findings
from backend.scanners.dockerfile_scanner import scan_dockerfile_text
from backend.scanners.k8s_yaml_scanner import scan_k8s_yaml_text
from backend.scanners.trivy_image import scan_image_with_trivy
from backend.schemas import ImageScanRequest, ScanResponse

router = APIRouter(prefix="/api/scan", tags=["scan"])


def _finish(task_id: int, target: str, findings):
    findings = enrich_findings(list(findings))
    summary = summarize_findings(findings)
    save_findings(task_id, findings)
    finish_task(task_id, "finished", summary)
    return ScanResponse(task_id=task_id, target=target, summary=summary, findings=findings)


@router.post("/image", response_model=ScanResponse)
def scan_image(req: ImageScanRequest):
    if not req.image.strip():
        raise HTTPException(status_code=400, detail="image cannot be empty")
    target = req.image.strip()
    task_id = create_task("image_scan", target)
    try:
        findings = scan_image_with_trivy(target)
        return _finish(task_id, target, findings)
    except Exception as exc:  # noqa: BLE001
        finish_task(task_id, "failed", {"error": str(exc)})
        raise


@router.post("/dockerfile", response_model=ScanResponse)
async def scan_dockerfile(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Dockerfile must be UTF-8 text")
    target = file.filename or "Dockerfile"
    task_id = create_task("dockerfile_scan", target)
    try:
        findings = scan_dockerfile_text(text, target=target)
        return _finish(task_id, target, findings)
    except Exception:  # noqa: BLE001
        finish_task(task_id, "failed")
        raise


@router.post("/k8s-yaml", response_model=ScanResponse)
async def scan_k8s_yaml(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="YAML must be UTF-8 text")
    target = file.filename or "k8s.yaml"
    task_id = create_task("k8s_yaml_scan", target)
    try:
        findings = scan_k8s_yaml_text(text, target=target)
        return _finish(task_id, target, findings)
    except Exception:  # noqa: BLE001
        finish_task(task_id, "failed")
        raise
