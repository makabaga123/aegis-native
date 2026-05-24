from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ImageScanRequest(BaseModel):
    image: str = Field(..., examples=["nginx:latest"])


class ScanResponse(BaseModel):
    task_id: int | None = None
    target: str
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]


class FalcoEventResponse(BaseModel):
    status: str
    finding: Dict[str, Any]


class RuntimeEventResponse(BaseModel):
    status: str
    summary: Dict[str, Any]
    findings: List[Dict[str, Any]]


class AgentAnalyzeRequest(BaseModel):
    image: str | None = Field(default=None, examples=["nginx:latest"])
    dockerfile_text: str | None = None
    dockerfile_target: str | None = None
    k8s_yaml_text: str | None = None
    k8s_target: str | None = None
    terraform_text: str | None = None
    terraform_target: str | None = None
    cloud_config_text: str | None = None
    cloud_config_target: str | None = None
    runtime_events: List[Dict[str, Any]] | Dict[str, Any] | str | None = None
    kernel_events: List[Dict[str, Any]] | Dict[str, Any] | str | None = None
    trivy_timeout: int | None = 120
    persist: bool = False
