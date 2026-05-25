# Multi-Agent + MCP + A2A Design (Standard Protocols)

This version upgrades the project from custom "style" implementations to standard protocols:
- **MCP**: Model Context Protocol 2024-11-05 with JSON-RPC 2.0
- **A2A**: Google Agent-to-Agent Protocol with AgentCard discovery and Task lifecycle

## Architecture

```text
User / CI / Runtime Sensor / MCP Client / A2A Client
        |
        v
SecuritySupervisorAgent
        |
        |-- Standard A2A message envelope (AgentCard, Task, Message)
        |-- Agent discovery through AgentCard (GET /.well-known/agent-card.json)
        |-- Standard MCP JSON-RPC 2.0 tool invocation (tools/list, tools/call)
        v
Specialist Agents
        |-- DockerfileAgent        (MCP: dockerfile.rule_scan)
        |-- KubernetesSecurityAgent (MCP: k8s.rule_scan)
        |-- CloudSecurityAgent     (MCP: terraform.rule_scan, cloud.rule_scan)
        |-- ImageSecurityAgent     (MCP: image.trivy_scan)
        |-- RuntimeEDRAgent        (MCP: kernel.normalize_events, runtime.behavior_scan)
        |-- AttackPathAgent
        |-- RemediationAgent
        |-- ReportAgent
```

## Supervisor Pattern

The supervisor receives mixed inputs and dynamically selects specialist agents:

- `dockerfile_text` -> DockerfileAgent
- `k8s_yaml_text` -> KubernetesSecurityAgent
- `terraform_text` or `cloud_config_text` -> CloudSecurityAgent
- `runtime_events` or `kernel_events` -> RuntimeEDRAgent
- `image` -> ImageSecurityAgent
- all findings -> AttackPathAgent, RemediationAgent, ReportAgent

## MCP Protocol (Model Context Protocol 2024-11-05)

The project implements the standard MCP protocol using JSON-RPC 2.0 message format.

### Lifecycle

```
Client                          Server
  │                                │
  │──── initialize ───────────────>│  Protocol version negotiation
  │<─── InitializeResult ──────────│  Capabilities exchange
  │                                │
  │──── notifications/initialized ─>│  Client ready notification
  │                                │
  │──── tools/list ───────────────>│  List available tools
  │<─── ListToolsResult ───────────│
  │                                │
  │──── tools/call ───────────────>│  Call a specific tool
  │<─── CallToolResult ────────────│
```

### JSON-RPC 2.0 Message Format

Request:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "dockerfile.rule_scan",
    "arguments": {
      "text": "FROM ubuntu:latest\nUSER root",
      "target": "Dockerfile"
    }
  }
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"findings\": [...]}"
      }
    ],
    "isError": false
  }
}
```

### Tool Definitions (Standard MCP inputSchema)

Each tool is defined with a JSON Schema `inputSchema`, making it compatible with
standard MCP clients (Claude Desktop, Continue, Cursor, etc.):

```json
{
  "name": "k8s.rule_scan",
  "description": "Rule-based Kubernetes security audit...",
  "inputSchema": {
    "type": "object",
    "properties": {
      "text": {"type": "string", "description": "Kubernetes YAML manifest content to scan"},
      "target": {"type": "string", "description": "File name or resource identifier"}
    },
    "required": ["text"]
  }
}
```

### Transport

- **In-process**: Agents use `StandardMCPClient(server=...)` to call tools directly
  through the JSON-RPC 2.0 layer without network overhead
- **Streamable HTTP**: External MCP clients connect via `POST /api/mcp/message`
  with standard `Mcp-Session-Id` header support

### API Endpoints

```text
POST /api/mcp/message    # Standard MCP JSON-RPC 2.0 endpoint
GET  /api/mcp/tools      # REST convenience: list tools
POST /api/mcp/call       # REST convenience: call a tool
GET  /api/mcp/health     # MCP server health check
```

## A2A Protocol (Google Agent-to-Agent)

The project implements the standard Google A2A protocol for agent discovery,
task management, and inter-agent communication.

### AgentCard (Standard A2A Format)

Each specialist agent exposes a standard A2A AgentCard:

```json
{
  "name": "dockerfile-agent",
  "description": "Detects insecure Dockerfile build practices through MCP rules and optional LLM agent review.",
  "url": "/a2a/dockerfile-agent",
  "provider": {"organization": "AegisNative"},
  "version": "2.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "stateTransitionHistory": false
  },
  "defaultInputModes": ["text", "file"],
  "defaultOutputModes": ["text", "json"],
  "skills": [
    {
      "id": "dockerfile_rule_scan",
      "name": "Dockerfile Security Scan",
      "description": "Rule-based detection of latest tag, root user, ADD vs COPY, hardcoded secrets, dangerous tools, curl-pipe-bash, missing HEALTHCHECK",
      "tags": ["security", "docker", "container", "supply-chain"],
      "inputModes": ["text"],
      "outputModes": ["json"]
    }
  ]
}
```

### Task Lifecycle

```text
tasks/send  →  submitted  →  working  →  completed
                                    ↘  failed
                                    ↘  cancelled (tasks/cancel)
```

### Message Envelope

The internal message format extends the standard A2A message with convenience
fields for supervisor-orchestrated workflows while remaining compatible with
the standard parts-based message format:

```json
{
  "sender": "supervisor-agent",
  "recipient": "kubernetes-agent",
  "intent": "analyze",
  "payload": {},
  "role": "supervisor",
  "message_id": "...",
  "conversation_id": "...",
  "correlation_id": "...",
  "context_id": "...",
  "task_id": "...",
  "parts": []
}
```

### API Endpoints

```text
# Agent Discovery
GET  /a2a/.well-known/agent-card.json
GET  /a2a/{agent-name}/.well-known/agent-card.json
GET  /a2a/agents

# Task Operations
POST /a2a/{agent-name}/tasks/send
GET  /a2a/tasks/{taskId}
POST /a2a/tasks/{taskId}/cancel

# Supervisor
POST /a2a/supervisor/tasks/send
```

## MCP Tool Layer

Agents call MCP tools through the standard JSON-RPC 2.0 protocol:

| Tool | Agent | Description |
|---|---|---|
| `dockerfile.rule_scan` | DockerfileAgent | Dockerfile security audit |
| `k8s.rule_scan` | KubernetesSecurityAgent | K8s YAML/Pod Security/RBAC audit |
| `terraform.rule_scan` | CloudSecurityAgent | Terraform/IaC audit |
| `cloud.rule_scan` | CloudSecurityAgent | Cloud config audit |
| `runtime.behavior_scan` | RuntimeEDRAgent | EDR behavior detection |
| `kernel.normalize_events` | RuntimeEDRAgent | Event normalization |
| `image.trivy_scan` | ImageSecurityAgent | Trivy CVE scan |

### In-Process Tool Calling

Agents use the standard MCP client for in-process tool invocation:

```python
class DockerfileAgent(BaseSecurityAgent):
    def handle(self, message: A2AMessage) -> A2AMessage:
        rule_result = self.mcp.call_tool("dockerfile.rule_scan", {
            "text": text,
            "target": target,
        })
        # rule_result is the unpacked tool result dict
```

### External MCP Client Compatibility

The MCP server is compatible with standard MCP clients. Configure your MCP client:

```json
{
  "mcpServers": {
    "aegis-native": {
      "url": "http://127.0.0.1:8000/api/mcp/message",
      "transport": "streamable-http"
    }
  }
}
```

## Rule Detection + Agent Detection

Each relevant specialist agent runs both:

1. deterministic rules, such as `privileged: true`, `hostPath`, `0.0.0.0/0`, `USER root`, `xmrig`;
2. agent analysis through `llm_analyze_artifact()`.

If no LLM API key is configured, the platform falls back to deterministic local agent heuristics. If an API key is provided, it calls the configured model through an OpenAI-compatible chat-completions endpoint.

## LLM Provider Selection

Set environment variables at runtime. Do not commit API keys.

```bash
export LLM_PROVIDER=deepseek
export DEEPSEEK_API_KEY="sk-..."
export DEEPSEEK_MODEL="deepseek-chat"
```

```bash
export LLM_PROVIDER=zhipu
export ZHIPU_API_KEY="..."
export ZHIPU_MODEL="glm-4-flash"
```

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o-mini"
```

```bash
export LLM_PROVIDER=ollama
export OLLAMA_BASE_URL="http://127.0.0.1:11434/v1"
export OLLAMA_MODEL="qwen2.5-coder:7b"
```

## Kernel-Level Runtime Collection

The platform does not load a custom kernel module. Instead, it supports safe defensive kernel-level collection through existing tools:

- Falco with eBPF driver
- Tetragon with eBPF
- KubeArmor / LSM style events

Collectors post JSON to:

```text
POST /api/kernel/events
POST /api/kernel/events/batch
```

The platform normalizes these events and applies Runtime EDR behavior rules.
