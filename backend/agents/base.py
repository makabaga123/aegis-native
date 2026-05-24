from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from backend.a2a import A2AMessage, AgentCard
from backend.mcp import LocalMCPClient


class BaseSecurityAgent(ABC):
    name = "base"

    def __init__(self, mcp_client: LocalMCPClient) -> None:
        self.mcp = mcp_client

    @property
    @abstractmethod
    def card(self) -> AgentCard:
        raise NotImplementedError

    @abstractmethod
    def handle(self, message: A2AMessage) -> A2AMessage:
        raise NotImplementedError

    def _result(self, message: A2AMessage, payload: Dict[str, Any]) -> A2AMessage:
        return message.reply(sender=self.name, payload=payload, intent="agent.result")
