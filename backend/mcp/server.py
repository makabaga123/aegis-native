from __future__ import annotations

from typing import Any, Dict

from backend.mcp.tools.security_tools import SecurityToolRegistry


class LocalMCPServer:
    """Small MCP-like server facade used by this project.

    The API mirrors the core MCP idea: list tools and call a selected tool with
    structured arguments. It can later be replaced by the official MCP SDK
    without changing agent logic.
    """

    def __init__(self, registry: SecurityToolRegistry | None = None) -> None:
        self.registry = registry or SecurityToolRegistry()

    def list_tools(self) -> Dict[str, Any]:
        return {"tools": self.registry.list_tools()}

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {"tool": name, "result": self.registry.call_tool(name, arguments)}
