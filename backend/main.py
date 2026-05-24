from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from backend.api import agent, falco, kernel, mcp_api, multi_agent, report, runtime, scan
from backend.models.database import init_db

app = FastAPI(
    title="Cloud Native Security Platform",
    description="基于 Kubernetes 的云原生安全检测与风险治理平台",
    version="1.0.0",
)

app.include_router(scan.router)
app.include_router(falco.router)
app.include_router(report.router)
app.include_router(runtime.router)
app.include_router(agent.router)
app.include_router(multi_agent.router)
app.include_router(mcp_api.router)
app.include_router(kernel.router)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="utf-8">
      <title>Cloud Native Security Platform</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background:#f6f7fb; margin:0; }
        .wrap { max-width: 980px; margin: 40px auto; background:white; padding:32px; border-radius:20px; box-shadow: 0 10px 30px rgba(15,23,42,.08); }
        code, pre { background:#f3f4f6; padding:2px 6px; border-radius:6px; }
        a { color:#2563eb; text-decoration:none; }
      </style>
    </head>
    <body><div class="wrap">
      <h1>基于 Kubernetes 的云原生安全检测与风险治理平台</h1>
      <p>已启动。你可以通过 Swagger UI 或 curl 调用扫描接口。</p>
      <ul>
        <li><a href="/docs">打开 API 文档 /docs</a></li>
        <li><a href="/api/report/html">查看 HTML 风险报告</a></li>
        <li><a href="/api/report/findings">查看 Findings JSON</a></li>
        <li><a href="/api/runtime/timeline">查看 Runtime EDR 时间线</a></li>
        <li><a href="/api/mcp/tools">查看 MCP 工具</a></li>
      </ul>
      <h2>示例命令</h2>
      <pre>curl -X POST http://127.0.0.1:8000/api/scan/image -H "Content-Type: application/json" -d '{"image":"nginx:latest"}'</pre>
      <pre>curl -X POST http://127.0.0.1:8000/api/scan/dockerfile -F "file=@examples/vulnerable-dockerfile/Dockerfile"</pre>
      <pre>curl -X POST http://127.0.0.1:8000/api/scan/k8s-yaml -F "file=@examples/vulnerable-k8s-yaml/deployment.yaml"</pre>
    </div></body></html>
    """
