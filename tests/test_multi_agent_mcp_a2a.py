import json
from pathlib import Path

from backend.agents import SecuritySupervisorAgent
from backend.mcp import LocalMCPClient
from backend.scanners.kernel_event_normalizer import normalize_kernel_event


def test_mcp_lists_security_tools():
    tools = LocalMCPClient().list_tools()
    names = {t["name"] for t in tools}
    assert "dockerfile.rule_scan" in names
    assert "kernel.normalize_events" in names
    assert "image.trivy_scan" in names


def test_supervisor_multi_agent_transcript():
    payload = json.loads(Path("examples/multi-agent-request.json").read_text(encoding="utf-8"))
    result = SecuritySupervisorAgent().analyze(payload)
    assert result["architecture"] == "multi-agent-supervisor-a2a-mcp"
    assert len(result["a2a_agent_cards"]) >= 8
    assert len(result["a2a_transcript"]["messages"]) >= 6
    assert result["summary"]["total"] > 0
    assert result["attack_paths"]


def test_kernel_falco_event_normalization():
    event = json.loads(Path("examples/kernel/falco-shell-event.json").read_text(encoding="utf-8"))
    normalized = normalize_kernel_event(event)
    assert normalized["collector"] == "falco-ebpf"
    assert normalized["process_name"] == "bash"
    assert normalized["namespace"] == "default"
