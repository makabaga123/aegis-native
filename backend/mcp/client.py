from __future__ import annotations

from typing import Any, Dict, List

from backend.mcp.server import LocalMCPServer


class LocalMCPClient:
    """Client used by agents to access MCP tools."""

    def __init__(self, server: LocalMCPServer | None = None) -> None:
        self.server = server or LocalMCPServer()

    def list_tools(self) -> List[Dict[str, Any]]:
        return self.server.list_tools()["tools"]

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.server.call_tool(name, arguments)["result"]
