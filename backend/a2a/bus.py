from __future__ import annotations

from typing import Dict, List

from backend.a2a.protocol import A2AMessage, A2ATranscript, AgentCard


class InMemoryA2ABus:
    """In-process A2A message bus for demo, tests, and local deployment."""

    def __init__(self) -> None:
        self.agent_cards: Dict[str, AgentCard] = {}
        self.transcripts: Dict[str, A2ATranscript] = {}

    def register(self, card: AgentCard) -> None:
        self.agent_cards[card.name] = card

    def discover(self) -> List[dict]:
        return [card.to_dict() for card in self.agent_cards.values()]

    def emit(self, message: A2AMessage) -> None:
        transcript = self.transcripts.setdefault(message.conversation_id, A2ATranscript(conversation_id=message.conversation_id))
        transcript.append(message)

    def get_transcript(self, conversation_id: str) -> dict:
        return self.transcripts.get(conversation_id, A2ATranscript(conversation_id=conversation_id)).to_dict()
