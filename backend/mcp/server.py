"""Standard MCP server with JSON-RPC 2.0 protocol and lifecycle management.

Supports both in-process calls (for agent use) and streamable HTTP transport
(exposed via FastAPI endpoints).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Union

from backend.mcp.protocol import (
    MCP_PROTOCOL_VERSION,
    CallToolResult,
    InitializeResult,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
    ListToolsResult,
    MCPMethod,
)
from backend.mcp.tools.security_tools import SecurityToolRegistry

logger = logging.getLogger(__name__)


class StandardMCPServer:
    """MCP server implementing the standard JSON-RPC 2.0 protocol.

    Lifecycle: initialize → initialized → tools/list | tools/call
    """

    def __init__(self, registry: SecurityToolRegistry | None = None) -> None:
        self.registry = registry or SecurityToolRegistry()
        self._initialized = False
        self._client_capabilities: Dict[str, Any] = {}
        self._client_info: Dict[str, str] = {}

    # ── Lifecycle ────────────────────────────────────────────────────────

    @property
    def initialized(self) -> bool:
        return self._initialized

    def _handle_initialize(self, req: JSONRPCRequest) -> InitializeResult:
        params = req.params or {}
        self._client_capabilities = params.get("capabilities", {})
        self._client_info = params.get("clientInfo", {})
        self._initialized = True
        logger.info("MCP client initialized: %s (v%s)", self._client_info.get("name", "unknown"), params.get("protocolVersion", "unknown"))
        return InitializeResult(
            protocolVersion=MCP_PROTOCOL_VERSION,
            capabilities={"tools": {"listChanged": False}},
            serverInfo={"name": "aegis-native-mcp", "version": "2.0.0"},
        )

    def _handle_initialized(self, _req: JSONRPCRequest) -> None:
        pass  # notification — no response

    # ── Tools ────────────────────────────────────────────────────────────

    def _handle_tools_list(self, _req: JSONRPCRequest) -> ListToolsResult:
        return ListToolsResult(tools=self.registry.list_tools())

    def _handle_tools_call(self, req: JSONRPCRequest) -> CallToolResult:
        params = req.params or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}

        if not name:
            return CallToolResult(
                content=[{"type": "text", "text": "Error: tool name is required"}],
                isError=True,
            )

        try:
            result = self.registry.call_tool(name, arguments)
            return CallToolResult.json_result(result)
        except ValueError as exc:
            return CallToolResult(
                content=[{"type": "text", "text": str(exc)}],
                isError=True,
            )
        except Exception as exc:
            logger.exception("Tool call failed: %s", name)
            return CallToolResult(
                content=[{"type": "text", "text": f"Tool error: {exc}"}],
                isError=True,
            )

    # ── Method dispatch ──────────────────────────────────────────────────

    _METHOD_TABLE = {
        MCPMethod.INITIALIZE: "_handle_initialize",
        MCPMethod.INITIALIZED: "_handle_initialized",
        MCPMethod.TOOLS_LIST: "_handle_tools_list",
        MCPMethod.TOOLS_CALL: "_handle_tools_call",
    }

    def dispatch(self, request: JSONRPCRequest) -> Union[JSONRPCResponse, JSONRPCError, None]:
        """Route a JSON-RPC request to the appropriate handler.

        Returns None for notifications (no response expected).
        """
        method = request.method

        if method not in self._METHOD_TABLE:
            return JSONRPCError.method_not_found(request.id)

        # Enforce lifecycle: initialize must be called first
        if not self._initialized and method != MCPMethod.INITIALIZE:
            return JSONRPCError.invalid_request("Server not initialized — send 'initialize' first")

        handler_name = self._METHOD_TABLE[method]
        handler = getattr(self, handler_name)

        try:
            result = handler(request)
        except Exception as exc:
            logger.exception("Handler error for %s", method)
            return JSONRPCError(id=request.id, code=-32603, message=str(exc))

        if result is None:
            return None  # notification

        return JSONRPCResponse(id=request.id, result=result.to_dict() if hasattr(result, "to_dict") else result)

    # ── Raw message processing (for HTTP transport) ──────────────────────

    def process_message(self, raw: str) -> Optional[str]:
        """Parse a raw JSON-RPC 2.0 message and return the JSON response string.

        Returns None for notifications or parse errors (no response to send).
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            err = JSONRPCError.parse_error(str(exc))
            return json.dumps(err.to_dict(), ensure_ascii=False)

        # Support batch requests
        if isinstance(data, list):
            responses = []
            for item in data:
                resp = self._process_single(item)
                if resp is not None:
                    responses.append(resp.to_dict() if hasattr(resp, "to_dict") else resp)
            return json.dumps(responses, ensure_ascii=False) if responses else None

        resp = self._process_single(data)
        if resp is None:
            return None
        return json.dumps(resp.to_dict() if hasattr(resp, "to_dict") else resp, ensure_ascii=False)

    def _process_single(self, data: Dict[str, Any]) -> Optional[Union[JSONRPCResponse, JSONRPCError]]:
        if not isinstance(data, dict) or data.get("jsonrpc") != "2.0":
            return JSONRPCError.invalid_request("Missing or invalid 'jsonrpc' field")

        req = JSONRPCRequest.from_dict(data)
        return self.dispatch(req)

    # ── Convenience (keeps backward compat with agent code) ──────────────

    def list_tools(self) -> Dict[str, Any]:
        """Convenience method for in-process tool listing."""
        return {"tools": self.registry.list_tools()}

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience method for in-process tool calling."""
        return {"tool": name, "result": self.registry.call_tool(name, arguments)}


# Keep alias for backward compatibility
LocalMCPServer = StandardMCPServer
