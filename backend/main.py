from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api import agent, falco, kernel, mcp_api, multi_agent, report, runtime, scan
from backend.models.database import init_db

app = FastAPI(
    title="Cloud Native Security Platform",
    description="基于 Kubernetes 的云原生安全检测与风险治理平台",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(falco.router)
app.include_router(report.router)
app.include_router(runtime.router)
app.include_router(agent.router)
app.include_router(multi_agent.router)
app.include_router(mcp_api.router)
app.include_router(kernel.router)

FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str = ""):
        path = os.path.join(FRONTEND_DIST, full_path) if full_path else os.path.join(FRONTEND_DIST, "index.html")
        if os.path.isfile(path):
            return FileResponse(path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/")
def api_index():
    return {
        "name": "AegisNative API",
        "version": "1.0.0",
        "endpoints": {
            "scan": "/api/scan/",
            "runtime": "/api/runtime/",
            "agent": "/api/agent/",
            "multi_agent": "/api/multi-agent/",
            "mcp": "/api/mcp/",
            "report": "/api/report/",
            "kernel": "/api/kernel/",
            "falco": "/api/falco/",
        },
    }
