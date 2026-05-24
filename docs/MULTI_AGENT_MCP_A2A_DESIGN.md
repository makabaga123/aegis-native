# Multi-Agent + A2A + MCP Design

This version upgrades the project from a single agent coordinator into a multi-agent security analysis system.

## Architecture

```text
User / CI / Runtime Sensor
        |
        v
SecuritySupervisorAgent
        |
        |-- A2A message envelope
        |-- Agent discovery through AgentCard
        |-- MCP tool invocation
        v
Specialist Agents
        |-- DockerfileAgent
        |-- KubernetesSecurityAgent
        |-- CloudSecurityAgent
        |-- ImageSecurityAgent
        |-- RuntimeEDRAgent
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

## A2A Communication

The project implements a lightweight A2A-style message envelope:

```json
{
  "sender": "supervisor-agent",
  "recipient": "kubernetes-agent",
  "intent": "analyze",
  "payload": {},
  "conversation_id": "...",
  "message_id": "...",
  "correlation_id": "..."
}
```

Each agent exposes an `AgentCard` with name, description, capabilities, input types, and output types. The full transcript is returned as `a2a_transcript`.

## MCP Tool Layer

Agents do not import scanner functions directly. They call MCP-style tools:

- `dockerfile.rule_scan`
- `k8s.rule_scan`
- `terraform.rule_scan`
- `cloud.rule_scan`
- `runtime.behavior_scan`
- `kernel.normalize_events`
- `image.trivy_scan`

API endpoints:

```text
GET  /api/mcp/tools
POST /api/mcp/call
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
