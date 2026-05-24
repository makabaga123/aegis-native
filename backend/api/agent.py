from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, UploadFile

from backend.agent.security_agent import CloudNativeSecurityAgent
from backend.schemas import AgentAnalyzeRequest

router = APIRouter(prefix="/api/agent", tags=["ai-agent"])


@router.post("/analyze")
def analyze_json(req: AgentAnalyzeRequest):
    agent = CloudNativeSecurityAgent()
    return agent.analyze(req.model_dump(), persist=req.persist)


@router.post("/analyze-files")
async def analyze_files(
    image: Optional[str] = Form(default=None),
    persist: bool = Form(default=False),
    dockerfile: Optional[UploadFile] = File(default=None),
    k8s_yaml: Optional[UploadFile] = File(default=None),
    terraform: Optional[UploadFile] = File(default=None),
    cloud_config: Optional[UploadFile] = File(default=None),
    runtime_events_json: Optional[str] = Form(default=None),
):
    inputs: Dict[str, Any] = {"image": image, "persist": persist}

    async def read_text(file: Optional[UploadFile]) -> str | None:
        if not file:
            return None
        raw = await file.read()
        return raw.decode("utf-8")

    dockerfile_text = await read_text(dockerfile)
    if dockerfile_text:
        inputs["dockerfile_text"] = dockerfile_text
        inputs["dockerfile_target"] = dockerfile.filename

    k8s_yaml_text = await read_text(k8s_yaml)
    if k8s_yaml_text:
        inputs["k8s_yaml_text"] = k8s_yaml_text
        inputs["k8s_target"] = k8s_yaml.filename

    terraform_text = await read_text(terraform)
    if terraform_text:
        inputs["terraform_text"] = terraform_text
        inputs["terraform_target"] = terraform.filename

    cloud_config_text = await read_text(cloud_config)
    if cloud_config_text:
        inputs["cloud_config_text"] = cloud_config_text
        inputs["cloud_config_target"] = cloud_config.filename

    if runtime_events_json:
        try:
            parsed = json.loads(runtime_events_json)
            inputs["runtime_events"] = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            inputs["runtime_events"] = []

    agent = CloudNativeSecurityAgent()
    return agent.analyze(inputs, persist=persist)
