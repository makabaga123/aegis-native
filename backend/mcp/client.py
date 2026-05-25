"""Standard MCP client with JSON-RPC 2.0 protocol.

Used by agents to discover and call MCP tools through the standard protocol.
Supports both in-process (direct server reference) and HTTP transport.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx

from backend.mcp.protocol import (
    MCP_PROTOCOL_VERSION,
    InitializeRequest,
    JSONRPCRequest,
    MCPMethod,
)
from backend.mcp.server import StandardMCPServer

logger = logging.getLogger(__name__)


class StandardMCPClient:
    """MCP client that speaks JSON-RPC 2.0.

    Two modes:
    - In-process: pass a StandardMCPServer instance (used by agents)
    - HTTP: provide a base_url (used by external clients)
    """

    def __init__(
        self,
        server: StandardMCPServer | None = None,
        base_url: str | None = None,
    ) -> None:
        self._server = server
        self._base_url = base_url
        # Auto-create a server if neither server nor base_url is provided
        if self._server is None and self._base_url is None:
            self._server = StandardMCPServer()
        self._session_id: str | None = None
        self._initialized = False

    # ── Initialize handshake ─────────────────────────────────────────────

    def initialize(self) -> Dict[str, Any]:
        """Perform the standard MCP initialize handshake."""
        init_result = self._send_request(
            MCPMethod.INITIALIZE,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "aegis-native-agent", "version": "2.0.0"},
            },
        )
        # Send initialized notification
        self._send_notification(MCPMethod.INITIALIZED, {})
        self._initialized = True
        logger.info("MCP initialize handshake complete: %s", init_result.get("serverInfo", {}))
        return init_result

    # ── Tools ────────────────────────────────────────────────────────────

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return the list of available MCP tools (standard format)."""
        if not self._initialized:
            self.initialize()
        result = self._send_request(MCPMethod.TOOLS_LIST, {})
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a named MCP tool with structured arguments."""
        if not self._initialized:
            self.initialize()
        result = self._send_request(MCPMethod.TOOLS_CALL, {"name": name, "arguments": arguments})
        # Unwrap standard MCP CallToolResult content
        content = result.get("content", [])
        is_error = result.get("isError", False)
        if is_error:
            text = content[0].get("text", "Unknown tool error") if content else "Unknown tool error"
            raise RuntimeError(text)
        if content:
            first = content[0]
            if first.get("type") == "text":
                try:
                    return json.loads(first["text"])
                except (json.JSONDecodeError, TypeError):
                    return {"text": first.get("text", "")}
        return result

    # ── JSON-RPC transport ───────────────────────────────────────────────

    def _send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the result."""
        req = JSONRPCRequest(method=method, params=params)
        response = self._transport(req.to_dict())
        if "error" in response:
            err = response["error"]
            raise RuntimeError(f"MCP error [{err.get('code')}]: {err.get('message')}")
        return response.get("result", {})

    def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        notification = {"jsonrpc": "2.0", "method": method, "params": params}
        self._transport(notification)

    def _transport(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Transport layer — routes to in-process server or HTTP endpoint."""
        if self._server is not None:
            raw = json.dumps(message, ensure_ascii=False)
            resp = self._server.process_message(raw)
            if resp is None:
                return {}
            return json.loads(resp)

        if self._base_url is not None:
            headers = {"Content-Type": "application/json"}
            if self._session_id:
                headers["Mcp-Session-Id"] = self._session_id
            resp = httpx.post(self._base_url, json=message, headers=headers)
            if "Mcp-Session-Id" in resp.headers:
                self._session_id = resp.headers["Mcp-Session-Id"]
            resp.raise_for_status()
            return resp.json()

        raise RuntimeError("MCP client has neither server nor base_url configured")

    # ── Backward-compatible client info ──────────────────────────────────

    @property
    def server_info(self) -> Dict[str, Any]:
        """Return cached server info from initialize handshake."""
        return {"name": "aegis-native-mcp", "version": "2.0.0"}


LocalMCPClient = StandardMCPClient
