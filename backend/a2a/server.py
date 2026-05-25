"""Standard A2A HTTP server — exposes AgentCard discovery and task endpoints.

Implements the Google A2A protocol HTTP API:
- GET  /.well-known/agent-card.json  — AgentCard discovery
- POST /tasks/send                    — Send a task to an agent
- GET  /tasks/{taskId}                — Get task status/result
- POST /tasks/{taskId}/cancel         — Cancel a task
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from backend.a2a.bus import InMemoryA2ABus
from backend.a2a.protocol import (
    A2AMessage,
    A2ATask,
    AgentCard,
    TaskSendRequest,
    TaskSendResponse,
    TaskStatus,
)

logger = logging.getLogger(__name__)


class A2AAgentHandler:
    """Protocol adapter: maps standard A2A HTTP requests to agent handle() calls.

    Each specialist agent exposes one of these behind its own URL prefix
    (e.g. /a2a/dockerfile-agent/).
    """

    def __init__(self, agent: Any, bus: InMemoryA2ABus | None = None) -> None:
        self.agent = agent
        self.bus = bus or InMemoryA2ABus()

    @property
    def card(self) -> AgentCard:
        return self.agent.card

    # ── Standard A2A endpoints ───────────────────────────────────────────

    def get_agent_card(self) -> Dict[str, Any]:
        """Return the standard A2A AgentCard for this agent."""
        return self.card.to_dict()

    def send_task(self, request: TaskSendRequest) -> Dict[str, Any]:
        """Process a standard A2A tasks/send request."""
        message_data = request.message
        conversation_id = message_data.get("contextId") or message_data.get("conversation_id", "")

        # Build internal A2A message from standard parts
        parts = message_data.get("parts", [])
        payload: Dict[str, Any] = {}
        for part in parts:
            if part.get("type") == "text" and part.get("text"):
                # Attempt to parse as JSON, fall back to plain text
                import json
                try:
                    payload.update(json.loads(part["text"]))
                except (json.JSONDecodeError, TypeError):
                    payload["text"] = payload.get("text", "") + part["text"]
            elif part.get("type") == "data" and part.get("data"):
                payload.update(part["data"])

        msg = A2AMessage(
            sender=message_data.get("sender", "external-client"),
            recipient=self.agent.name,
            intent=message_data.get("intent", "analyze"),
            payload=payload,
            role="user",
            conversation_id=conversation_id or "",
            context_id=message_data.get("contextId"),
            task_id=message_data.get("taskId"),
            parts=[],  # normalized into payload above
        )

        # Route to agent
        response_msg = self.agent.handle(msg)
        if self.bus:
            self.bus.emit(msg)
            self.bus.emit(response_msg)

        # Create standard A2A task for the response
        task = A2ATask(
            contextId=conversation_id or msg.conversation_id,
            status=TaskStatus(state="completed"),
        )

        return TaskSendResponse(
            task=task,
            message=response_msg.to_dict(),
        ).to_dict()

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Return task status (standard A2A tasks/get)."""
        if self.bus:
            task = self.bus.get_task(task_id)
            if task:
                return task.to_dict()
        return None

    def cancel_task(self, task_id: str) -> Dict[str, Any]:
        """Cancel a task (standard A2A tasks/cancel)."""
        if self.bus:
            task = self.bus.update_task_status(task_id, "cancelled")
            if task:
                return task.to_dict()
        return {"error": f"Task {task_id} not found"}


class A2AServer:
    """Aggregate A2A server exposing all registered agents.

    Provides the supervisor-level view — lists all agent cards and
    routes tasks to the appropriate specialist agent.
    """

    def __init__(self, bus: InMemoryA2ABus | None = None) -> None:
        self.bus = bus or InMemoryA2ABus()
        self._handlers: Dict[str, A2AAgentHandler] = {}

    def register_agent(self, agent: Any) -> None:
        """Register a specialist agent and expose it via A2A."""
        handler = A2AAgentHandler(agent, self.bus)
        self._handlers[agent.name] = handler
        if self.bus:
            self.bus.register(agent.card)

    def get_all_agent_cards(self) -> list:
        """Return all registered AgentCards (A2A discovery)."""
        return [h.card.to_dict() for h in self._handlers.values()]

    def get_agent_card(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Return a single agent's card."""
        handler = self._handlers.get(agent_name)
        return handler.get_agent_card() if handler else None

    def send_task_to_agent(self, agent_name: str, request: TaskSendRequest) -> Optional[Dict[str, Any]]:
        """Route a task to a specific agent."""
        handler = self._handlers.get(agent_name)
        if handler is None:
            return None
        return handler.send_task(request)

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status from any registered handler."""
        for handler in self._handlers.values():
            result = handler.get_task(task_id)
            if result:
                return result
        return None
