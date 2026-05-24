from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
import uuid

Role = Literal["user", "supervisor", "agent", "tool", "system"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AgentCard:
    """A2A-style agent identity/capability card.

    The project keeps this intentionally lightweight so it can run locally without
    external infrastructure, while still making each agent discoverable and
    callable through a common envelope.
    """

    name: str
    description: str
    capabilities: List[str]
    input_types: List[str]
    output_types: List[str]
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class A2AMessage:
    """A2A-style message envelope used by all agents in this project."""

    sender: str
    recipient: str
    intent: str
    payload: Dict[str, Any]
    role: Role = "agent"
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    conversation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    created_at: str = field(default_factory=_now)

    def reply(self, *, sender: str, payload: Dict[str, Any], intent: str = "result") -> "A2AMessage":
        return A2AMessage(
            sender=sender,
            recipient=self.sender,
            intent=intent,
            payload=payload,
            role="agent",
            conversation_id=self.conversation_id,
            correlation_id=self.message_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class A2ATranscript:
    conversation_id: str
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def append(self, message: A2AMessage) -> None:
        self.messages.append(message.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {"conversation_id": self.conversation_id, "messages": self.messages}
