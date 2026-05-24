from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Body

from backend.mcp import LocalMCPServer

router = APIRouter(prefix="/api/mcp", tags=["mcp-tools"])
server = LocalMCPServer()


@router.get("/tools")
def list_tools():
    return server.list_tools()


@router.post("/call")
def call_tool(payload: Dict[str, Any] = Body(...)):
    name = payload.get("name")
    arguments = payload.get("arguments") or {}
    return server.call_tool(name, arguments)
