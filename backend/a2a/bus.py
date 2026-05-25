"""Standard A2A message bus — in-process agent discovery and task routing.

Implements the agent discovery and task execution patterns from the
Google A2A specification while running fully in-process for local deployment.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from backend.a2a.protocol import (
    A2AMessage,
    A2ATask,
    A2ATranscript,
    AgentCard,
    TaskStatus,
)


class InMemoryA2ABus:
    """In-process A2A message bus supporting standard A2A patterns.

    Capabilities:
    - Agent registration with AgentCard (standard A2A discovery)
    - Task creation and lifecycle tracking (standard A2A tasks)
    - Message emission with full transcript recording
    - Agent discovery via list of AgentCards

    For local demo, testing, and single-process deployment. Can be
    replaced by a networked A2A implementation without changing agent logic.
    """

    def __init__(self) -> None:
        self.agent_cards: Dict[str, AgentCard] = {}
        self.transcripts: Dict[str, A2ATranscript] = {}
        self.tasks: Dict[str, A2ATask] = {}

    # ── Agent discovery (standard A2A) ───────────────────────────────────

    def register(self, card: AgentCard) -> None:
        """Register an agent with its standard A2A AgentCard."""
        self.agent_cards[card.name] = card

    def discover(self) -> List[dict]:
        """Return all registered agent cards (standard A2A discovery)."""
        return [card.to_dict() for card in self.agent_cards.values()]

    def get_agent_card(self, name: str) -> Optional[dict]:
        """Get a single agent's card by name (A2A .well-known pattern)."""
        card = self.agent_cards.get(name)
        return card.to_dict() if card else None

    # ── Task management (standard A2A) ───────────────────────────────────

    def create_task(self, context_id: str | None = None, metadata: dict | None = None) -> A2ATask:
        """Create a standard A2A task."""
        task = A2ATask(
            contextId=context_id or "",
            metadata=metadata or {},
        )
        self.tasks[task.id] = task
        return task

    def get_task(self, task_id: str) -> Optional[A2ATask]:
        """Retrieve a task by ID (standard A2A tasks/get)."""
        return self.tasks.get(task_id)

    def update_task_status(self, task_id: str, state: str, message: str | None = None) -> Optional[A2ATask]:
        """Update a task's status (standard A2A lifecycle)."""
        task = self.tasks.get(task_id)
        if task:
            task.status = TaskStatus(state=state, message=message)  # type: ignore[arg-type]
        return task

    # ── Message routing ──────────────────────────────────────────────────

    def emit(self, message: A2AMessage) -> None:
        """Record a message in its conversation transcript."""
        transcript = self.transcripts.setdefault(
            message.conversation_id,
            A2ATranscript(conversation_id=message.conversation_id),
        )
        transcript.append(message)

    def get_transcript(self, conversation_id: str) -> dict:
        """Return the full transcript for a conversation."""
        return self.transcripts.get(
            conversation_id,
            A2ATranscript(conversation_id=conversation_id),
        ).to_dict()
