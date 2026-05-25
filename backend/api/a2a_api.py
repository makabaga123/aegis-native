"""Standard A2A HTTP endpoints — Agent Card discovery and Task execution.

Implements the Google A2A protocol HTTP API surface:
- Agent discovery via AgentCard
- Task send / get / cancel operations
- Supervisor-level aggregate view of all agents
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, HTTPException

from backend.agents import SecuritySupervisorAgent
from backend.a2a.protocol import TaskSendRequest
from backend.a2a.server import A2AServer
from backend.mcp import LocalMCPClient

router = APIRouter(prefix="/a2a", tags=["a2a-standard"])

# Build the A2A server with all registered agents
_mcp_client = LocalMCPClient()
_supervisor = SecuritySupervisorAgent(mcp_client=_mcp_client)
_a2a_server = A2AServer(bus=_supervisor.bus)

for _agent in _supervisor.agents.values():
    _a2a_server.register_agent(_agent)

# ── Agent Discovery ──────────────────────────────────────────────────────


@router.get("/.well-known/agent-card.json")
def discover_all_agents():
    """Standard A2A discovery — returns all registered AgentCards."""
    return {"agents": _a2a_server.get_all_agent_cards()}


@router.get("/{agent_name}/.well-known/agent-card.json")
def get_agent_card(agent_name: str):
    """Standard A2A agent-specific discovery — returns a single AgentCard."""
    card = _a2a_server.get_agent_card(agent_name)
    if card is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
    return card


# ── Task Operations ──────────────────────────────────────────────────────


@router.post("/{agent_name}/tasks/send")
def send_task(agent_name: str, request: Dict[str, Any] = Body(...)):
    """Standard A2A tasks/send — send a task to a specific agent.

    Request body should contain:
    - message: A2A message with parts array
    - metadata: optional metadata dict
    """
    task_request = TaskSendRequest(
        message=request.get("message", {}),
        metadata=request.get("metadata", {}),
    )
    result = _a2a_server.send_task_to_agent(agent_name, task_request)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
    return result


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """Standard A2A tasks/get — retrieve task status and history."""
    task = _a2a_server.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    return task


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: str):
    """Standard A2A tasks/cancel — cancel a running task."""
    # Try cancel on all handlers
    for handler in _a2a_server._handlers.values():
        result = handler.cancel_task(task_id)
        if "error" not in result:
            return result
    raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")


# ── Supervisor aggregate ─────────────────────────────────────────────────


@router.get("/agents")
def list_agents():
    """List all registered A2A agents with their cards."""
    return {
        "supervisor": _supervisor.name,
        "agents": _a2a_server.get_all_agent_cards(),
    }


@router.post("/supervisor/tasks/send")
def send_supervisor_task(request: Dict[str, Any] = Body(...)):
    """Send a high-level analysis task through the supervisor.

    The supervisor plans, dispatches to specialist agents, correlates
    results, and returns findings with attack paths and remediation.

    Accepts a flat payload with artifact keys (dockerfile_text,
    k8s_yaml_text, terraform_text, cloud_config_text, runtime_events,
    kernel_events, image).
    """
    payload = request.get("message", {}).get("payload", request.get("payload", request))
    # Flatten: extract payload from parts if present
    if "parts" in request.get("message", {}):
        import json
        for part in request["message"]["parts"]:
            if part.get("type") == "text" and part.get("text"):
                try:
                    payload.update(json.loads(part["text"]))
                except (json.JSONDecodeError, TypeError):
                    pass
    result = _supervisor.analyze(payload)
    return result
