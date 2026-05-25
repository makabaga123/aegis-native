"""MCP (Model Context Protocol) — JSON-RPC 2.0 message types.

Implements the standard MCP lifecycle and tool-calling protocol on top of
JSON-RPC 2.0 as defined by the 2024-11-05 specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Union
import uuid

# ── JSON-RPC 2.0 primitives ──────────────────────────────────────────────

@dataclass
class JSONRPCRequest:
    jsonrpc: str = "2.0"
    id: Union[int, str] = field(default_factory=lambda: str(uuid.uuid4()))
    method: str = ""
    params: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id, "method": self.method}
        if self.params is not None:
            d["params"] = self.params
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JSONRPCRequest":
        return cls(
            jsonrpc=data.get("jsonrpc", "2.0"),
            id=data.get("id", 0),
            method=data.get("method", ""),
            params=data.get("params"),
        )


@dataclass
class JSONRPCResponse:
    jsonrpc: str = "2.0"
    id: Union[int, str, None] = None
    result: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {"jsonrpc": self.jsonrpc, "id": self.id, "result": self.result}


@dataclass
class JSONRPCError:
    jsonrpc: str = "2.0"
    id: Union[int, str, None] = None
    code: int = -32603
    message: str = "Internal error"
    data: Any = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "jsonrpc": self.jsonrpc,
            "id": self.id,
            "error": {"code": self.code, "message": self.message},
        }
        if self.data is not None:
            d["error"]["data"] = self.data
        return d

    @classmethod
    def method_not_found(cls, req_id: Union[int, str, None] = None) -> "JSONRPCError":
        return cls(id=req_id, code=-32601, message="Method not found")

    @classmethod
    def invalid_params(cls, req_id: Union[int, str, None] = None, detail: str = "") -> "JSONRPCError":
        return cls(id=req_id, code=-32602, message=f"Invalid params: {detail}")

    @classmethod
    def invalid_request(cls, detail: str = "") -> "JSONRPCError":
        return cls(code=-32600, message=f"Invalid Request: {detail}")

    @classmethod
    def parse_error(cls, detail: str = "") -> "JSONRPCError":
        return cls(code=-32700, message=f"Parse error: {detail}")


# ── MCP lifecycle types ──────────────────────────────────────────────────

MCP_PROTOCOL_VERSION = "2024-11-05"


@dataclass
class InitializeRequest:
    protocolVersion: str = MCP_PROTOCOL_VERSION
    capabilities: Dict[str, Any] = field(default_factory=dict)
    clientInfo: Dict[str, str] = field(default_factory=dict)


@dataclass
class InitializeResult:
    protocolVersion: str = MCP_PROTOCOL_VERSION
    capabilities: Dict[str, Any] = field(default_factory=dict)
    serverInfo: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocolVersion": self.protocolVersion,
            "capabilities": self.capabilities,
            "serverInfo": self.serverInfo,
        }


# ── MCP tool types ───────────────────────────────────────────────────────

@dataclass
class ToolDefinition:
    """Standard MCP tool definition with JSON Schema inputSchema."""
    name: str
    description: str
    inputSchema: Dict[str, Any]  # JSON Schema object

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.inputSchema,
        }


@dataclass
class ListToolsResult:
    tools: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"tools": self.tools}


@dataclass
class CallToolResult:
    content: List[Dict[str, Any]] = field(default_factory=list)
    isError: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"content": self.content, "isError": self.isError}

    @classmethod
    def text(cls, text: str) -> "CallToolResult":
        return cls(content=[{"type": "text", "text": text}])

    @classmethod
    def json_result(cls, data: Any) -> "CallToolResult":
        import json
        return cls(content=[{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}])


# ── MCP method names ─────────────────────────────────────────────────────

class MCPMethod:
    INITIALIZE = "initialize"
    INITIALIZED = "notifications/initialized"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
