# AegisNative

<p align="center">
  <strong>基于多 Agent 协作的云原生安全检测与运行时风险治理平台</strong>
</p>

<p align="center">
  <a href="#"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-blue"></a>
  <a href="#"><img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Backend-009688"></a>
  <a href="#"><img alt="React" src="https://img.shields.io/badge/React-19-61DAFB"></a>
  <a href="#"><img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-Frontend-3178C6"></a>
  <a href="#"><img alt="Kubernetes" src="https://img.shields.io/badge/Kubernetes-Security-326CE5"></a>
  <a href="#"><img alt="Multi Agent" src="https://img.shields.io/badge/Multi--Agent-Supervisor-purple"></a>
  <a href="#"><img alt="MCP" src="https://img.shields.io/badge/MCP-2024--11--05-orange"></a>
  <a href="#"><img alt="A2A" src="https://img.shields.io/badge/A2A-Google%20Protocol-blue"></a>
  <a href="#"><img alt="Runtime Security" src="https://img.shields.io/badge/Runtime-Falco%2FeBPF-red"></a>
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-green"></a>
</p>

<p align="center">
  <strong>Aegis</strong> 意为"神盾"，<strong>Native</strong> 表示"云原生"。AegisNative 旨在把容器、Kubernetes、云资源、IaC 与运行时安全事件统一到一个可扩展的 Agentic Security 平台中。
</p>

---

## 项目简介

**AegisNative** 是一个面向 DevSecOps / CNAPP / CWPP 场景的云原生安全检测与运行时风险治理平台。

项目通过 **Supervisor 多 Agent 调度**、**标准 A2A 协议 (Google Agent-to-Agent)**、**标准 MCP 协议 (Model Context Protocol 2024-11-05)**，对 Dockerfile、容器镜像、Kubernetes YAML / RBAC、Terraform、云资源配置、Falco / eBPF 运行时事件进行统一检测、关联分析和修复建议生成。

它不是单纯调用一个扫描器，而是把云原生安全治理拆成多个专业安全 Agent：

```text
Dockerfile 风险检测
    + 镜像漏洞扫描
    + Kubernetes 配置审计
    + Terraform / 云配置审计
    + 运行时内核事件分析
    + 攻击路径关联
    + LLM 辅助解释与修复建议
    = 云原生安全风险治理闭环
```

---

## 适合用来做什么

- 云原生安全项目
- DevSecOps 安全检测平台
- AI Agent for Security 实践项目
- CNAPP / CWPP / KSPM / CSPM 入门项目
- Kubernetes 安全、容器安全、运行时安全样例
- 标准 MCP / A2A 协议参考实现

---

## 核心特性

| 能力 | 说明 |
|---|---|
| 多 Agent 协作 | 使用 Supervisor 范式调度不同安全 Agent |
| 标准 A2A 协议 | 实现 Google A2A 协议：AgentCard 发现、Skill 定义、Task 生命周期管理、Transcript 审计 |
| 标准 MCP 协议 | 实现 JSON-RPC 2.0 协议，标准 initialize 握手，tools/list + tools/call，兼容 MCP 客户端 |
| 规则检测 | 稳定检测高危配置、危险命令、过权策略、运行时异常行为 |
| Agent / LLM 检测 | 支持 DeepSeek、智谱、OpenAI / GPT、Ollama、OpenAI-compatible API |
| Dockerfile 审计 | 检测 latest、root、ADD、硬编码密钥、危险工具、curl download 等风险 |
| 镜像漏洞扫描 | 调用 Trivy 扫描镜像 CVE、依赖漏洞和严重等级 |
| Kubernetes 安全审计 | 检测 privileged、hostPath、hostNetwork、SYS_ADMIN、RBAC 过权、Service 暴露等 |
| Terraform / IaC 审计 | 检测公网安全组、公开 Bucket、IAM `*` 权限、硬编码凭据、未加密资源等 |
| 云资源配置审计 | 检测公网暴露、公开对象存储、MFA 缺失、AccessKey 泄露、IAM 过权等 |
| Runtime EDR 检测 | 检测 shell、反弹连接、挖矿、敏感文件访问、docker.sock、ServiceAccount Token 等 |
| 内核级事件接入 | 接收 Falco eBPF、Tetragon eBPF、KubeArmor / LSM 或通用内核事件 |
| 攻击路径关联 | 将单点风险关联成容器逃逸、横向移动、云权限滥用等攻击链 |
| 报告生成 | 生成风险评分、修复建议、优先级动作和 HTML 报告 |

---

## 架构设计

```text
用户 / CI Pipeline / SOC / Runtime Sensor / MCP Client
        │
        │ Dockerfile / Image / K8s YAML / Terraform / Cloud JSON / Runtime Events
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        SecuritySupervisorAgent                        │
│                                                                      │
│  1. Plan      判断输入类型，决定需要调用哪些 Agent                    │
│  2. Dispatch  通过标准 A2A 消息分发任务                               │
│  3. Execute   通过标准 MCP JSON-RPC 2.0 调用安全检测工具              │
│  4. Correlate 关联配置风险、漏洞风险、运行时事件，生成攻击路径         │
│  5. Respond   生成修复建议、优先级动作和报告数据                     │
└──────────────────────────────────────────────────────────────────────┘
        │
        ├── DockerfileAgent        ← MCP: dockerfile.rule_scan
        ├── ImageSecurityAgent     ← MCP: image.trivy_scan
        ├── KubernetesSecurityAgent ← MCP: k8s.rule_scan
        ├── CloudSecurityAgent     ← MCP: terraform.rule_scan, cloud.rule_scan
        ├── RuntimeEDRAgent        ← MCP: kernel.normalize_events, runtime.behavior_scan
        ├── AttackPathAgent
        ├── RemediationAgent
        └── ReportAgent
        │
        ▼
Findings + Risk Score + Attack Paths + Priority Actions + HTML Report
```

---

## 标准 MCP 协议 (Model Context Protocol)

项目实现了标准的 **MCP 2024-11-05** 协议，基于 **JSON-RPC 2.0** 消息格式，支持完整的 MCP 生命周期：

```
Client                          Server
  │                                │
  │──── initialize ───────────────>│  握手协商协议版本和能力
  │<─── InitializeResult ──────────│
  │                                │
  │──── notifications/initialized ─>│  客户端就绪通知
  │                                │
  │──── tools/list ───────────────>│  列出所有可用工具
  │<─── ListToolsResult ───────────│
  │                                │
  │──── tools/call ───────────────>│  调用指定工具
  │<─── CallToolResult ────────────│
```

### MCP 工具列表

| 工具名称 | 描述 |
|---|---|
| `dockerfile.rule_scan` | Dockerfile 安全审计 |
| `k8s.rule_scan` | Kubernetes YAML / Pod Security / RBAC 审计 |
| `terraform.rule_scan` | Terraform / IaC 云配置错误审计 |
| `cloud.rule_scan` | 云配置公开暴露、IAM、加密风险审计 |
| `runtime.behavior_scan` | 运行时 EDR 行为检测 |
| `kernel.normalize_events` | Falco/eBPF/Tetragon/KubeArmor 事件归一化 |
| `image.trivy_scan` | Trivy 镜像 CVE 漏洞扫描 |

### 标准 MCP JSON-RPC 2.0 调用

```bash
# 1. 初始化握手
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "my-client", "version": "1.0.0"}
    }
  }'

# 2. 列出工具
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'

# 3. 调用工具
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "dockerfile.rule_scan",
      "arguments": {
        "text": "FROM ubuntu:latest\nUSER root\nADD . /app"
      }
    }
  }'
```

### 兼容标准 MCP 客户端

可将 AegisNative 配置为 Claude Desktop、Continue、Cursor 等支持 MCP 的工具的后端：

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

### REST 便捷接口（向后兼容）

```bash
# 查看工具列表
curl http://127.0.0.1:8000/api/mcp/tools

# 调用工具
curl -X POST http://127.0.0.1:8000/api/mcp/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dockerfile.rule_scan",
    "arguments": {
      "text": "FROM ubuntu:latest\nUSER root\nADD . /app"
    }
  }'
```

---

## 标准 A2A 协议 (Google Agent-to-Agent)

项目实现了标准的 **Google A2A 协议**，包括 AgentCard 发现、Skill 定义、Task 生命周期管理和完整的对话 Transcript 审计。

### AgentCard 示例

每个 Agent 都暴露标准 A2A AgentCard：

```json
{
  "name": "kubernetes-agent",
  "description": "Audits Kubernetes YAML, Pod Security, RBAC, exposure and policy gaps.",
  "url": "/a2a/kubernetes-agent",
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
      "id": "k8s_yaml_scan",
      "name": "Kubernetes YAML Security Audit",
      "description": "Detects privileged containers, hostPath, hostNetwork...",
      "tags": ["security", "kubernetes", "pod-security", "rbac"],
      "inputModes": ["text"],
      "outputModes": ["json"]
    }
  ]
}
```

### A2A API 端点

```text
# Agent 发现
GET  /a2a/.well-known/agent-card.json          # 所有 Agent 卡片
GET  /a2a/{agent-name}/.well-known/agent-card.json  # 单个 Agent 卡片
GET  /a2a/agents                                # Agent 列表

# Task 操作
POST /a2a/{agent-name}/tasks/send               # 发送任务到指定 Agent
GET  /a2a/tasks/{taskId}                        # 查询任务状态
POST /a2a/tasks/{taskId}/cancel                 # 取消任务

# Supervisor 聚合入口
POST /a2a/supervisor/tasks/send                 # 通过 Supervisor 执行完整分析
```

### A2A 调用示例

```bash
# 发现所有 Agent
curl http://127.0.0.1:8000/a2a/.well-known/agent-card.json

# 查看 Kubernetes Agent 卡片
curl http://127.0.0.1:8000/a2a/kubernetes-agent/.well-known/agent-card.json

# 通过 Supervisor 执行多 Agent 分析
curl -X POST http://127.0.0.1:8000/a2a/supervisor/tasks/send \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "parts": [
        {
          "type": "text",
          "text": "{\"dockerfile_text\": \"FROM ubuntu:latest\\nUSER root\"}"
        }
      ]
    }
  }'
```

---

## 多 Agent 模块

```text
SecuritySupervisorAgent
├── DockerfileAgent          # Dockerfile 构建阶段风险检测
├── ImageSecurityAgent       # Trivy 镜像漏洞扫描
├── KubernetesSecurityAgent  # K8s YAML / RBAC / 暴露面检测
├── CloudSecurityAgent       # 云资源配置与 Terraform 风险检测
├── RuntimeEDRAgent          # 运行时行为与内核事件检测
├── AttackPathAgent          # 攻击路径关联分析
├── RemediationAgent         # 修复建议生成
└── ReportAgent              # 报告数据整理
```

每个 Agent 都实现了标准的 A2A AgentCard，通过 MCP 工具调用安全检测能力，并返回标准化的 findings。

---

## 检测范围

### Dockerfile 安全检测

- 使用 `latest` 标签
- 未设置非 root 用户
- 使用 `USER root`
- 使用 `ADD` 替代 `COPY`
- Dockerfile 中出现密码、Token、Key、Secret
- 安装 `curl`、`wget`、`ssh`、`netcat` 等高风险工具
- `curl | bash` / `wget | sh` 远程脚本执行
- 未配置 `HEALTHCHECK`

### 容器镜像扫描

- 调用 Trivy 扫描镜像漏洞
- 统计 Critical / High / Medium / Low 数量
- 提取 CVE、包名、当前版本、修复版本
- 根据漏洞严重等级生成风险评分

> 如果本机没有安装 Trivy，镜像扫描接口仍可运行，但会返回 Trivy 未安装的提示。

### Kubernetes YAML / RBAC 检测

- `privileged: true`
- `hostPath` 挂载宿主机目录
- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`
- `allowPrivilegeEscalation: true`
- 添加 `SYS_ADMIN` 等高危 Capability
- 未设置 `runAsNonRoot`
- 未设置 `readOnlyRootFilesystem`
- ServiceAccount Token 自动挂载
- RBAC 中使用 `*` 权限
- 可读取 Secret 的 Role / ClusterRole
- `pods/exec`、`pods/attach` 等高危权限
- NodePort / LoadBalancer 暴露面

### Terraform / 云配置检测

- 安全组开放 `0.0.0.0/0`
- SSH / RDP / 数据库端口公网暴露
- S3 / OSS / COS Bucket 公开访问
- IAM Action / Resource 使用 `*`
- 硬编码 AccessKey / SecretKey / Token
- 云磁盘、数据库、对象存储未加密
- MFA 缺失
- 高危云资源配置组合

### 运行时 EDR 检测

- 容器内启动 shell
- 执行 `nc`、`socat`、`bash -i` 等反弹连接行为
- 访问 `/etc/shadow`、`/etc/passwd`
- 访问 `/var/run/docker.sock`
- 读取 ServiceAccount Token
- 运行时安装软件包
- 执行 `curl | bash` / `wget | sh`
- 出现挖矿进程或矿池连接
- 修改 `/etc`、`/usr/bin` 等系统关键路径
- 异常外联、扫描、隧道行为

### 内核级事件接入

当前支持接收和归一化以下事件来源：

- Falco eBPF 事件
- Tetragon eBPF 事件
- KubeArmor / LSM 事件
- 通用 process / file / network / syscall JSON 事件

接口：

```text
POST /api/kernel/events
POST /api/kernel/events/batch
```

---

## LLM Provider 支持

项目支持通过 `.env` 文件或环境变量切换 LLM Provider。**不会在启动时弹出交互式提示要求输入 API Key** — 所有配置都是声明式的。

默认模式（无需 API Key，开箱即用）：

```bash
export LLM_PROVIDER=local
```

`local` 模式不调用任何外部大模型，所有检测、关联分析、风险评分均由内置规则引擎完成。这也是为什么启动后不会让你输入 API Key — 默认配置下根本不需要。当你需要 LLM 生成修复建议或更智能的关联分析时，再切换到下面的 Provider。

### DeepSeek

```bash
export LLM_PROVIDER=deepseek
export DEEPSEEK_API_KEY="sk-xxx"
export DEEPSEEK_MODEL="deepseek-chat"
export DEEPSEEK_BASE_URL="https://api.deepseek.com/v1"
```

### 智谱 GLM

```bash
export LLM_PROVIDER=zhipu
export ZHIPU_API_KEY="xxx"
export ZHIPU_MODEL="glm-4-flash"
export ZHIPU_BASE_URL="https://open.bigmodel.cn/api/paas/v4"
```

### OpenAI / GPT

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY="sk-xxx"
export OPENAI_MODEL="gpt-4o-mini"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

### OpenAI-compatible 网关

适合接入 SiliconFlow、one-api、vLLM、LiteLLM、Qwen、DeepSeek 兼容接口等。

```bash
export LLM_PROVIDER=openai-compatible
export LLM_API_KEY="xxx"
export LLM_BASE_URL="https://your-compatible-endpoint/v1"
export LLM_MODEL="your-model-name"
```

### Ollama 本地模型

```bash
export LLM_PROVIDER=ollama
export OLLAMA_BASE_URL="http://127.0.0.1:11434/v1"
export OLLAMA_MODEL="qwen2.5-coder:7b"
```

> **注意：系统不会在启动时交互式地让你输入 API Key。** 所有配置都通过 `.env` 文件或操作系统环境变量完成。复制 `.env.example` 为 `.env`，取消对应 Provider 的注释并填入你的 Key，然后重启服务即可。

---

## 前端 Dashboard

项目包含一个基于 React 19 + TypeScript + Vite + Tailwind CSS 4 的现代化前端 Dashboard，覆盖所有后端功能：

| 页面 | 路由 | 功能 |
|---|---|---|
| Landing | `/` | 产品展示页，介绍平台特性与架构 |
| Dashboard | `/dashboard` | 系统状态概览，快速导航到各工具 |
| Scan Hub | `/scan` | Dockerfile / 镜像 (Trivy) / K8s YAML 扫描 |
| AI Agent | `/agent` | 单 Agent 分析，支持文件上传与 JSON 输入 |
| Multi-Agent | `/multi-agent` | Supervisor 多 Agent 协同分析，含内核事件 |
| Runtime EDR | `/runtime` | 运行时事件时间线，可展开查看详情 |
| MCP Tools | `/mcp` | MCP 工具列表，可在线调用查看结果 |
| Reports | `/reports` | Findings 列表与 Task 历史记录 |

### 启动前端

```bash
cd frontend
npm install
npm run dev
```

前端运行在 `http://localhost:3000`，通过 Vite proxy 将 `/api` 请求转发到后端 `http://localhost:8000`。

### 生产构建

```bash
cd frontend
npm run build
```

构建产物在 `frontend/dist/`，后端会自动 serve 静态文件。

---

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/your-username/aegis-native.git
cd aegis-native
```

### 2. 创建虚拟环境

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows PowerShell：

```powershell
.venv\Scripts\activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

```bash
cp .env.example .env
```

默认不需要 API Key：

```bash
export LLM_PROVIDER=local
```

如果要启用 DeepSeek / 智谱 / GPT / Ollama，参考上面的 LLM Provider 配置。

### 5. 启动服务

```bash
uvicorn backend.main:app --reload
```

打开 API 文档：

```text
http://127.0.0.1:8000/docs
```

---

## 一键 Demo

```bash
python run_demo.py
```

Demo 会自动执行：

1. 扫描示例 Dockerfile
2. 扫描示例 Kubernetes YAML
3. 扫描示例 Terraform / 云配置
4. 分析示例运行时事件
5. 调用多 Agent Supervisor
6. 生成攻击路径和修复建议
7. 输出 HTML 报告

---

## API 使用示例

### 标准 MCP JSON-RPC 2.0

```bash
# 初始化握手
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"1.0"}}}'

# 列出工具
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# 调用工具
curl -X POST http://127.0.0.1:8000/api/mcp/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"k8s.rule_scan","arguments":{"text":"apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true"}}}'
```

### 标准 A2A 协议

```bash
# 发现所有 Agent
curl http://127.0.0.1:8000/a2a/.well-known/agent-card.json

# 查看单个 Agent 卡片
curl http://127.0.0.1:8000/a2a/dockerfile-agent/.well-known/agent-card.json

# 通过 A2A 发送任务
curl -X POST http://127.0.0.1:8000/a2a/supervisor/tasks/send \
  -H "Content-Type: application/json" \
  -d @examples/multi-agent-request.json
```

### 多 Agent 分析（REST API）

```bash
curl -X POST http://127.0.0.1:8000/api/multi-agent/analyze \
  -H "Content-Type: application/json" \
  -d @examples/multi-agent-request.json
```

### 上传文件进行多 Agent 分析

```bash
curl -X POST http://127.0.0.1:8000/api/multi-agent/analyze-files \
  -F "image=nginx:latest" \
  -F "dockerfile=@examples/vulnerable-dockerfile/Dockerfile" \
  -F "k8s_yaml=@examples/vulnerable-k8s-yaml/deployment.yaml" \
  -F "terraform=@examples/terraform/main.tf" \
  -F "cloud_config=@examples/cloud/aws-risky-config.json" \
  -F "runtime_events_json=$(cat examples/runtime/edr-events.json)"
```

### 接收 Falco / eBPF 运行时事件

```bash
curl -X POST http://127.0.0.1:8000/api/kernel/events \
  -H "Content-Type: application/json" \
  --data @examples/kernel/falco-shell-event.json
```

---

## Docker 部署

```bash
docker compose -f deploy/docker-compose.yml up --build
```

---

## Kubernetes / Runtime Security 集成

### 安装 Falco eBPF

```bash
bash scripts/install_falco_ebpf.sh
```

### 安装 Tetragon eBPF

```bash
bash scripts/install_tetragon_ebpf.sh
```

相关说明文档：

```text
docs/KERNEL_RUNTIME_COLLECTION.md
docs/EDR_RUNTIME_DESIGN.md
```

> 注意：本项目不编写危险的自定义内核模块，运行时采集优先通过 Falco、Tetragon、KubeArmor 等成熟防御型组件接入。

---

## 项目结构

```text
aegis-native/
├── backend/
│   ├── agents/                 # 多 Agent 实现（标准 A2A AgentCard）
│   ├── a2a/                    # 标准 Google A2A 协议实现
│   ├── mcp/                    # 标准 MCP JSON-RPC 2.0 协议实现
│   ├── api/                    # FastAPI 路由（含 MCP + A2A 标准端点）
│   ├── scanners/               # 规则检测与事件归一化
│   ├── llm/                    # LLM Provider 适配层
│   ├── reports/                # 报告生成
│   └── models/                 # 数据库模型
│
├── examples/                   # 示例靶场文件
│   ├── vulnerable-dockerfile/
│   ├── vulnerable-k8s-yaml/
│   ├── terraform/
│   ├── cloud/
│   ├── runtime/
│   └── kernel/
│
├── deploy/                     # Docker / K8s / Runtime 部署文件
├── docs/                       # 设计文档
├── frontend/                   # React 19 前端 Dashboard
│   ├── src/
│   │   ├── components/         # Header, Footer, Hero, Features 等
│   │   │   └── ui/             # Badge, CodeBlock, FileUpload 等通用组件
│   │   ├── pages/              # Landing, Dashboard, ScanHub, Agent 等 8 个页面
│   │   └── lib/                # API 客户端层
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
├── scripts/                    # 辅助脚本
├── tests/                      # 测试用例
├── run_demo.py                 # 一键 Demo
├── requirements.txt
└── README.md
```

---

## 测试

```bash
python -m pytest -q
```

预期结果：

```text
9 passed
```

---

## Roadmap

- [x] Dockerfile 规则检测
- [x] Kubernetes YAML / RBAC 检测
- [x] Terraform / 云配置检测
- [x] Falco / eBPF 运行时事件接入
- [x] Supervisor 多 Agent 调度
- [x] 标准 MCP 协议 (JSON-RPC 2.0, 2024-11-05)
- [x] 标准 A2A 协议 (Google Agent-to-Agent)
- [x] DeepSeek / 智谱 / GPT / Ollama Provider 适配
- [x] HTML 报告生成
- [x] Web Dashboard (React 19 + TypeScript + Tailwind 4)
- [x] MCP 兼容客户端支持 (Claude Desktop, Continue, Cursor 等)
- [ ] MCP stdio Transport 支持
- [ ] A2A 流式响应 (SSE)
- [ ] PDF 报告导出
- [ ] GitHub Actions 扫描插件
- [ ] Kubernetes Admission Controller
- [ ] OPA / Kyverno 策略导出
- [ ] MITRE ATT&CK / Cloud Matrix 映射
- [ ] 多租户与权限管理

---

## 安全声明

本项目仅用于：

- 安全学习
- 防御研究
- 授权环境测试
- DevSecOps Demo
- 云原生安全治理实验

请不要将本项目用于未授权扫描、攻击、入侵、绕过检测或其他违法行为。运行时事件采集应在你拥有或被授权管理的主机、容器、集群和云环境中进行。

---

## 贡献

欢迎提交 Issue、Pull Request 或改进建议。

适合贡献的方向：

- 新增 Dockerfile / Kubernetes / Terraform 检测规则
- 增强 Runtime EDR 检测逻辑
- 对接更多 LLM Provider
- 增加 MCP stdio Transport 支持
- 增加 A2A 流式响应支持
- 完善前端 Dashboard 功能和交互
- 增强报告模板
- 增加真实靶场样例

---

## License

本项目采用 [Apache License 2.0](./LICENSE) 开源。
