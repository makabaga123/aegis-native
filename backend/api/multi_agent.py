from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, File, Form, UploadFile

from backend.agents import SecuritySupervisorAgent
from backend.schemas import AgentAnalyzeRequest

router = APIRouter(prefix="/api/multi-agent", tags=["multi-agent-a2a-mcp"])


@router.post("/analyze")
def analyze_multi_agent(req: AgentAnalyzeRequest):
    supervisor = SecuritySupervisorAgent()
    return supervisor.analyze(req.model_dump())


@router.post("/analyze-files")
async def analyze_files_multi_agent(
    image: Optional[str] = Form(default=None),
    dockerfile: Optional[UploadFile] = File(default=None),
    k8s_yaml: Optional[UploadFile] = File(default=None),
    terraform: Optional[UploadFile] = File(default=None),
    cloud_config: Optional[UploadFile] = File(default=None),
    runtime_events_json: Optional[str] = Form(default=None),
    kernel_events_json: Optional[str] = Form(default=None),
):
    inputs: Dict[str, Any] = {"image": image}

    async def read_text(file: Optional[UploadFile]) -> str | None:
        if not file:
            return None
        return (await file.read()).decode("utf-8")

    if dockerfile_text := await read_text(dockerfile):
        inputs["dockerfile_text"] = dockerfile_text
        inputs["dockerfile_target"] = dockerfile.filename
    if k8s_yaml_text := await read_text(k8s_yaml):
        inputs["k8s_yaml_text"] = k8s_yaml_text
        inputs["k8s_target"] = k8s_yaml.filename
    if terraform_text := await read_text(terraform):
        inputs["terraform_text"] = terraform_text
        inputs["terraform_target"] = terraform.filename
    if cloud_config_text := await read_text(cloud_config):
        inputs["cloud_config_text"] = cloud_config_text
        inputs["cloud_config_target"] = cloud_config.filename
    if runtime_events_json:
        try:
            inputs["runtime_events"] = json.loads(runtime_events_json)
        except json.JSONDecodeError:
            inputs["runtime_events"] = []
    if kernel_events_json:
        try:
            inputs["kernel_events"] = json.loads(kernel_events_json)
        except json.JSONDecodeError:
            inputs["kernel_events"] = []

    supervisor = SecuritySupervisorAgent()
    return supervisor.analyze(inputs)
