from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _get(d: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    cur: Any = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def _falco_to_runtime(event: Dict[str, Any]) -> Dict[str, Any]:
    fields = event.get("output_fields") or {}
    rule = event.get("rule") or "falco"
    priority = event.get("priority") or event.get("severity") or "INFO"
    proc_name = fields.get("proc.name") or fields.get("proc.exepath") or ""
    cmd = fields.get("proc.cmdline") or fields.get("proc.args") or proc_name
    evt_type = fields.get("evt.type") or event.get("event_type") or "unknown"
    fd_name = fields.get("fd.name") or ""
    return {
        "collector": "falco-ebpf",
        "event_type": evt_type,
        "severity": priority,
        "rule": rule,
        "message": event.get("output") or rule,
        "namespace": fields.get("k8s.ns.name") or fields.get("k8s.namespace.name") or "unknown",
        "pod": fields.get("k8s.pod.name") or "unknown",
        "container": fields.get("container.name") or fields.get("container.id") or "unknown",
        "process_name": str(proc_name).split("/")[-1],
        "cmdline": cmd,
        "path": fd_name,
        "dst_ip": fields.get("fd.sip") or fields.get("fd.rip") or "",
        "dst_port": str(fields.get("fd.sport") or fields.get("fd.rport") or ""),
        "raw": event,
    }


def _tetragon_to_runtime(event: Dict[str, Any]) -> Dict[str, Any]:
    process = event.get("process") or _get(event, "process_exec", "process", default={}) or {}
    pod = process.get("pod") or {}
    binary = process.get("binary") or ""
    args = process.get("arguments") or ""
    parent = process.get("parent_exec_id") or ""
    # Tetragon emits multiple event types. Map the most common ones to our EDR schema.
    if "process_exec" in event:
        event_type = "execve"
    elif "process_kprobe" in event:
        event_type = "kprobe"
    elif "process_exit" in event:
        event_type = "process_exit"
    else:
        event_type = event.get("event_type") or "unknown"
    return {
        "collector": "tetragon-ebpf",
        "event_type": event_type,
        "severity": event.get("severity") or "INFO",
        "rule": event.get("policy_name") or "tetragon-event",
        "message": event.get("message") or event_type,
        "namespace": pod.get("namespace") or _get(event, "k8s", "namespace", default="unknown"),
        "pod": pod.get("name") or _get(event, "k8s", "pod", default="unknown"),
        "container": _get(process, "docker", default="") or _get(process, "container", "name", default="unknown"),
        "process_name": str(binary).split("/")[-1],
        "cmdline": f"{binary} {args}".strip(),
        "path": _get(event, "process_kprobe", "args", 0, default="") if isinstance(_get(event, "process_kprobe", default={}), dict) else "",
        "parent": parent,
        "raw": event,
    }


def _kubearmor_to_runtime(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "collector": "kubearmor-lsm-ebpf",
        "event_type": str(event.get("Operation") or event.get("operation") or event.get("event_type") or "unknown").lower(),
        "severity": event.get("Severity") or event.get("severity") or "INFO",
        "rule": event.get("PolicyName") or event.get("policy_name") or "kubearmor-event",
        "message": event.get("Message") or event.get("message") or "KubeArmor runtime event",
        "namespace": event.get("NamespaceName") or event.get("namespace") or "unknown",
        "pod": event.get("PodName") or event.get("pod") or "unknown",
        "container": event.get("ContainerName") or event.get("container") or "unknown",
        "process_name": str(event.get("ProcessName") or event.get("process_name") or "").split("/")[-1],
        "cmdline": event.get("Data") or event.get("cmdline") or "",
        "path": event.get("Resource") or event.get("path") or "",
        "raw": event,
    }


def normalize_kernel_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if "output_fields" in event or "falco" in str(event.get("source", "")).lower() or event.get("rule"):
        return _falco_to_runtime(event)
    if "process_exec" in event or "process_kprobe" in event or event.get("node_name") or event.get("time") and event.get("process"):
        return _tetragon_to_runtime(event)
    if "PolicyName" in event or "NamespaceName" in event or "Operation" in event:
        return _kubearmor_to_runtime(event)
    normalized = dict(event)
    normalized.setdefault("collector", "generic-kernel-event")
    normalized.setdefault("event_type", event.get("type") or event.get("evt.type") or "unknown")
    return normalized


def normalize_kernel_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_kernel_event(event) for event in events]
