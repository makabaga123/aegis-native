"""A2A (Agent-to-Agent) protocol — Google A2A standard data models.

Implements the standard A2A AgentCard, AgentSkill, Task, and Message types
as defined by the Google A2A specification, while retaining internal
convenience fields for the supervisor-orchestrated multi-agent workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
import uuid

Role = Literal["user", "supervisor", "agent", "tool", "system"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Standard A2A AgentCard types ─────────────────────────────────────────

@dataclass
class AgentProvider:
    """Standard A2A provider information."""
    organization: str
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"organization": self.organization}
        if self.url:
            d["url"] = self.url
        return d


@dataclass
class AgentCapabilities:
    """Standard A2A agent capabilities."""
    streaming: bool = False
    pushNotifications: bool = False
    stateTransitionHistory: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "streaming": self.streaming,
            "pushNotifications": self.pushNotifications,
            "stateTransitionHistory": self.stateTransitionHistory,
        }


@dataclass
class AgentSkill:
    """Standard A2A skill definition."""
    id: str
    name: str
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    inputModes: List[str] = field(default_factory=lambda: ["text"])
    outputModes: List[str] = field(default_factory=lambda: ["text"])

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "tags": self.tags,
            "examples": self.examples,
            "inputModes": self.inputModes,
            "outputModes": self.outputModes,
        }
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class AgentCard:
    """Standard A2A AgentCard — agent identity and capability descriptor.

    Compatible with the Google A2A specification. Also retains convenience
    aliases (capabilities list, input_types, output_types) for the internal
    supervisor workflow.
    """

    name: str
    description: str
    url: str = ""
    provider: AgentProvider = field(default_factory=lambda: AgentProvider(organization="AegisNative"))
    version: str = "1.0.0"
    a2a_capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    defaultInputModes: List[str] = field(default_factory=lambda: ["text", "file"])
    defaultOutputModes: List[str] = field(default_factory=lambda: ["text", "json"])
    skills: List[AgentSkill] = field(default_factory=list)

    # Convenience aliases for internal supervisor use
    capabilities: List[str] = field(default_factory=list)
    input_types: List[str] = field(default_factory=list)
    output_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "provider": self.provider.to_dict(),
            "version": self.version,
            "capabilities": self.a2a_capabilities.to_dict(),
            "defaultInputModes": self.defaultInputModes,
            "defaultOutputModes": self.defaultOutputModes,
            "skills": [s.to_dict() for s in self.skills],
            # Keep backward compat
            "capabilities_list": self.capabilities,
            "input_types": self.input_types,
            "output_types": self.output_types,
        }


# ── Standard A2A Part / Message types ────────────────────────────────────

@dataclass
class Part:
    """Standard A2A message part."""
    type: Literal["text", "file", "data"] = "text"
    text: Optional[str] = None
    file: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type}
        if self.type == "text" and self.text is not None:
            d["text"] = self.text
        elif self.type == "file" and self.file is not None:
            d["file"] = self.file
        elif self.type == "data" and self.data is not None:
            d["data"] = self.data
        return d

    @classmethod
    def from_text(cls, text: str) -> "Part":
        return cls(type="text", text=text)


@dataclass
class A2AMessage:
    """Standard A2A message envelope with internal convenience fields.

    Compatible with Google A2A message format (parts-based) while keeping
    the internal payload field for supervisor-orchestrated workflows.
    """

    sender: str
    recipient: str
    intent: str
    payload: Dict[str, Any] = field(default_factory=dict)
    role: Role = "agent"
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    conversation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    created_at: str = field(default_factory=_now)

    # Standard A2A fields
    parts: List[Part] = field(default_factory=list)
    task_id: Optional[str] = None
    context_id: Optional[str] = None

    def reply(self, *, sender: str, payload: Dict[str, Any], intent: str = "result") -> "A2AMessage":
        """Create a reply message, linking correlation_id to the original message_id."""
        return A2AMessage(
            sender=sender,
            recipient=self.sender,
            intent=intent,
            payload=payload,
            role="agent",
            conversation_id=self.conversation_id,
            context_id=self.context_id or self.conversation_id,
            correlation_id=self.message_id,
            task_id=self.task_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "sender": self.sender,
            "recipient": self.recipient,
            "intent": self.intent,
            "payload": self.payload,
            "role": self.role,
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "created_at": self.created_at,
        }
        if self.correlation_id:
            d["correlation_id"] = self.correlation_id
        if self.task_id:
            d["task_id"] = self.task_id
        if self.context_id:
            d["context_id"] = self.context_id
        if self.parts:
            d["parts"] = [p.to_dict() for p in self.parts]
        return d


# ── Standard A2A Task types ──────────────────────────────────────────────

@dataclass
class TaskStatus:
    """Standard A2A task status."""
    state: Literal["submitted", "working", "input-required", "completed", "failed", "cancelled"] = "submitted"
    message: Optional[str] = None
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"state": self.state, "timestamp": self.timestamp}
        if self.message:
            d["message"] = self.message
        return d


@dataclass
class A2ATask:
    """Standard A2A task — the unit of work in A2A protocol."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contextId: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: TaskStatus = field(default_factory=TaskStatus)
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "contextId": self.contextId,
            "status": self.status.to_dict(),
            "history": self.history,
            "metadata": self.metadata,
        }


# ── A2A Transcript (project-specific, not in spec) ──────────────────────

@dataclass
class A2ATranscript:
    """Records a full conversation as an ordered list of A2A messages.

    This is a project-specific convenience on top of the standard A2A protocol,
    useful for audit, debugging, and returning full analysis traces.
    """

    conversation_id: str
    messages: List[Dict[str, Any]] = field(default_factory=list)

    def append(self, message: A2AMessage) -> None:
        self.messages.append(message.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {"conversation_id": self.conversation_id, "messages": self.messages}


# ── Standard A2A HTTP types ──────────────────────────────────────────────

@dataclass
class TaskSendRequest:
    """Standard A2A tasks/send request."""
    message: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"message": self.message, "metadata": self.metadata}


@dataclass
class TaskSendResponse:
    """Standard A2A tasks/send response."""
    task: A2ATask
    message: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"task": self.task.to_dict()}
        if self.message:
            d["message"] = self.message
        return d
