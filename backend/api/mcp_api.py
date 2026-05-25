"""Standard MCP HTTP endpoints — JSON-RPC 2.0 over streamable HTTP.

Provides standard MCP endpoints compatible with MCP clients (Claude Desktop,
Continue, Cursor, etc.) alongside backward-compatible REST endpoints.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Body, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from backend.mcp import StandardMCPServer

router = APIRouter(prefix="/api/mcp", tags=["mcp-standard"])
server = StandardMCPServer()

# ── Standard MCP JSON-RPC 2.0 endpoint ──────────────────────────────────


@router.post("/message")
async def mcp_message(request: Request):
    """Standard MCP JSON-RPC 2.0 endpoint (streamable HTTP transport).

    Compatible with standard MCP clients. Accepts JSON-RPC 2.0 requests
    and returns JSON-RPC 2.0 responses. Supports the full MCP lifecycle:
    initialize → initialized → tools/list → tools/call.
    """
    body = await request.body()
    raw = body.decode("utf-8")

    # Handle empty POST (SSE session establishment for older clients)
    if not raw.strip():
        session_id = "aegis-native-mcp-session"
        return JSONResponse(
            content={"jsonrpc": "2.0", "id": None, "result": None},
            headers={
                "Mcp-Session-Id": session_id,
                "Content-Type": "application/json",
            },
        )

    result = server.process_message(raw)
    if result is None:
        # Notification — 202 Accepted with no body
        return JSONResponse(
            content={"jsonrpc": "2.0", "id": None, "result": None},
            status_code=202,
        )

    return JSONResponse(
        content=json.loads(result),
        headers={
            "Mcp-Session-Id": "aegis-native-mcp-session",
            "Content-Type": "application/json",
        },
    )


# ── Backward-compatible REST endpoints ───────────────────────────────────


@router.get("/tools")
def list_tools():
    """List all available MCP tools in standard format (REST convenience)."""
    return server.list_tools()


@router.post("/call")
def call_tool(payload: Dict[str, Any] = Body(...)):
    """Call a named MCP tool (REST convenience)."""
    name = payload.get("name")
    arguments = payload.get("arguments") or {}
    return server.call_tool(name, arguments)


# ── Standard MCP health / info ───────────────────────────────────────────


@router.get("/health")
def mcp_health():
    """MCP server health check."""
    return {
        "protocol": "MCP 2024-11-05",
        "transport": "streamable-http",
        "jsonrpc": "2.0",
        "tools_count": len(server.registry.list_tools()),
        "initialized": server.initialized,
    }
