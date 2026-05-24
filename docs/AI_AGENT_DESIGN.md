# AI Agent 设计说明

本项目从普通扫描平台升级为 AI Agent 风格的云原生安全治理平台。

## Agent 工作流

```text
输入资产 / 事件
  ├── Dockerfile
  ├── Kubernetes YAML / RBAC / Service
  ├── Terraform IaC
  ├── 云资源 JSON 清单
  ├── 镜像名
  └── Runtime EDR 事件
        ↓
Planner：判断应该调用哪些检测器
        ↓
Scanner：执行静态扫描、云配置扫描、运行时行为检测
        ↓
Correlator：把单点风险关联成攻击路径
        ↓
Reasoner：解释风险影响，生成优先级和修复建议
        ↓
Reporter：输出 JSON / HTML 报告
```

## 代码位置

| 模块 | 文件 |
|---|---|
| Agent 编排器 | `backend/agent/security_agent.py` |
| Agent 大脑 / LLM 兼容层 | `backend/llm/agent_brain.py` |
| 本地修复建议生成器 | `backend/llm/remediation_generator.py` |
| Agent API | `backend/api/agent.py` |

## 为什么说它是 Agent

它不是只调用单个工具，而是具备：

1. **Plan**：根据输入自动决定扫描 Dockerfile、K8s、Cloud、Terraform、Runtime 事件。
2. **Act**：调用多个 scanner 执行检测。
3. **Observe**：收集 Findings 和 Runtime Events。
4. **Correlate**：将配置风险和运行时行为关联成攻击链。
5. **Respond**：生成优先级、风险解释、修复建议和可给真实 LLM 的 Prompt。

默认是本地推理，不依赖 API Key。以后可以把 `SecurityAgentBrain` 替换为 OpenAI-compatible LLM 调用。
