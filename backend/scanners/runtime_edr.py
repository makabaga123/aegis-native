from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from backend.scanners.common import make_finding, normalize_severity, sort_findings

SHELLS = {"sh", "bash", "zsh", "ash", "dash", "ksh"}
PKG_MANAGERS = {"apt", "apt-get", "apk", "yum", "dnf", "pacman", "pip", "npm", "gem"}
NETWORK_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet", "ssh", "curl", "wget"}
CRYPTO_MINER_NAMES = {"xmrig", "minerd", "kinsing", "kdevtmpfsi", "kinsing2"}
SENSITIVE_PATHS = ("/etc/shadow", "/etc/passwd", "/root/.ssh", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/kubelet")
WRITE_SYSTEM_PATHS = ("/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/", "/lib64/")
K8S_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


def _field(event: Dict[str, Any], *names: str, default: str = "") -> str:
    fields = event.get("output_fields") or {}
    for name in names:
        if name in event and event[name] is not None:
            return str(event[name])
        if name in fields and fields[name] is not None:
            return str(fields[name])
    return default


def _target(event: Dict[str, Any]) -> str:
    ns = _field(event, "namespace", "k8s.ns.name", "k8s.namespace.name", default="unknown")
    pod = _field(event, "pod", "k8s.pod.name", default="unknown")
    container = _field(event, "container", "container.name", "container_id", default="unknown")
    return f"{ns}/{pod}/{container}"


def _event_type(event: Dict[str, Any]) -> str:
    return _field(event, "event_type", "type", "evt.type", default="unknown").lower()


def _cmd(event: Dict[str, Any]) -> str:
    return _field(event, "cmdline", "process_cmd", "proc.cmdline", "command", default="")


def _proc_name(event: Dict[str, Any]) -> str:
    proc = _field(event, "process_name", "proc.name", "exe", default="")
    if proc:
        return proc.split("/")[-1]
    cmd = _cmd(event).strip()
    return cmd.split()[0].split("/")[-1] if cmd else ""


def _path(event: Dict[str, Any]) -> str:
    return _field(event, "path", "file_path", "fd.name", "evt.arg.filename", default="")


def _dst(event: Dict[str, Any]) -> str:
    return _field(event, "dst", "dst_ip", "fd.sip", "remote_ip", "destination_ip", default="")


def _add(findings: List[Dict[str, Any]], event: Dict[str, Any], *, rule_id: str, severity: str, title: str, description: str, evidence: str, fix: str) -> None:
    findings.append(make_finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        fix=fix,
        source="runtime-edr-agent",
        target=_target(event),
        category="Runtime EDR",
        extra={"event": event},
    ))


def analyze_runtime_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze one normalized container/runtime event with EDR-like behavioral rules.

    The function accepts lightweight JSON events from eBPF/Falco/KubeArmor-like sources.
    It does not require kernel access, so it is suitable for local demo and webhook testing.
    """
    findings: List[Dict[str, Any]] = []
    etype = _event_type(event)
    cmd = _cmd(event)
    proc = _proc_name(event).lower()
    path = _path(event)
    dst = _dst(event)
    msg = event.get("message") or event.get("output") or ""
    evidence_base = f"event_type={etype}; proc={proc}; cmd={cmd}; path={path}; dst={dst}; message={msg}"

    if etype in {"execve", "exec", "process_start"}:
        if proc in SHELLS:
            _add(findings, event,
                rule_id="EDR001",
                severity="HIGH",
                title="容器内启动交互式 Shell",
                description="生产容器中异常启动 shell 往往意味着 WebShell、命令执行漏洞或人工入侵排查行为。",
                evidence=evidence_base,
                fix="确认是否为授权操作；排查 Web/RCE 漏洞；禁用不必要 shell；使用只读根文件系统和最小权限用户。",
            )
        if proc in PKG_MANAGERS:
            _add(findings, event,
                rule_id="EDR002",
                severity="MEDIUM",
                title="运行时执行包管理器",
                description="容器运行后安装软件会破坏镜像不可变性，也可能是攻击者下载工具的行为。",
                evidence=evidence_base,
                fix="禁止生产容器运行包管理器；把依赖固化到镜像构建阶段；通过准入策略限制可执行程序。",
            )
        if proc in NETWORK_TOOLS and re.search(r"(?i)(\|\s*(sh|bash)|/bin/(sh|bash)|http://|https://)", cmd):
            _add(findings, event,
                rule_id="EDR003",
                severity="HIGH",
                title="运行时执行下载或远程脚本行为",
                description="curl/wget/nc/socat 等工具在运行时出现，可能用于下载恶意脚本、反连或横向移动。",
                evidence=evidence_base,
                fix="核查下载源和命令来源；限制出站网络；移除不必要工具；使用 NetworkPolicy 和运行时策略阻断。",
            )
        if proc in CRYPTO_MINER_NAMES or re.search(r"(?i)(xmrig|stratum\+tcp|cryptonight|mining)", cmd):
            _add(findings, event,
                rule_id="EDR004",
                severity="CRITICAL",
                title="疑似挖矿进程或挖矿连接",
                description="容器内出现常见挖矿进程或矿池协议，通常代表工作负载已被入侵。",
                evidence=evidence_base,
                fix="立即隔离 Pod/Node；保留镜像和日志证据；轮换凭据；排查入口漏洞和横向移动痕迹。",
            )

    if etype in {"open", "openat", "file_open", "read"}:
        if any(path.startswith(sp) for sp in SENSITIVE_PATHS) or path == K8S_TOKEN_PATH:
            sev = "CRITICAL" if "docker.sock" in path or path == K8S_TOKEN_PATH else "HIGH"
            _add(findings, event,
                rule_id="EDR005",
                severity=sev,
                title="容器访问敏感宿主机或凭据文件",
                description="访问 docker.sock、ServiceAccount Token、宿主机 kubelet 目录或系统敏感文件，可能导致提权、逃逸或集群 API 滥用。",
                evidence=evidence_base,
                fix="排查访问进程；关闭不必要 hostPath；禁用 SA Token 自动挂载；禁止挂载 docker.sock；最小化 RBAC 权限。",
            )

    if etype in {"write", "file_write", "rename", "unlink"}:
        if any(path.startswith(sp) for sp in WRITE_SYSTEM_PATHS):
            _add(findings, event,
                rule_id="EDR006",
                severity="HIGH",
                title="容器修改系统关键路径",
                description="运行时修改 /etc、/usr/bin 等路径可能代表持久化、篡改或恶意工具落地。",
                evidence=evidence_base,
                fix="启用 readOnlyRootFilesystem；检查镜像完整性；隔离工作负载并比对文件变更。",
            )

    if etype in {"connect", "network_connect", "dns", "egress"}:
        port = _field(event, "dst_port", "fd.sport", "remote_port", default="")
        if re.search(r"(?i)(stratum|tor|onion|pastebin|ngrok|telegram|discord)", f"{dst} {cmd} {msg}") or port in {"4444", "5555", "6666", "1337"}:
            _add(findings, event,
                rule_id="EDR007",
                severity="HIGH",
                title="疑似异常外联或 C2 通信",
                description="命中可疑域名、隧道服务、矿池协议或常见反连端口，可能是反弹 shell、C2 或数据外传。",
                evidence=evidence_base + f"; port={port}",
                fix="核查目标 IP/域名；阻断异常出站；为命名空间配置默认拒绝的 NetworkPolicy；检查进程树和凭据泄露。",
            )

    if event.get("privileged") is True or re.search(r"(?i)(cap_sys_admin|privileged|setns|mount\s)", evidence_base):
        _add(findings, event,
            rule_id="EDR008",
            severity="CRITICAL",
            title="运行时出现提权/命名空间/挂载相关行为",
            description="特权、SYS_ADMIN、setns、mount 等行为与容器逃逸攻击链高度相关。",
            evidence=evidence_base,
            fix="隔离工作负载；关闭 privileged 和 SYS_ADMIN；审计 hostPath；使用 Pod Security Restricted 与运行时策略阻断。",
        )

    if not findings and normalize_severity(str(event.get("severity") or event.get("priority") or "INFO")) in {"CRITICAL", "HIGH"}:
        _add(findings, event,
            rule_id="EDR000",
            severity=str(event.get("severity") or event.get("priority")),
            title="外部运行时安全工具高危告警",
            description="外部 EDR/eBPF/Falco/KubeArmor 类工具上报了高危事件，平台将其归一化纳入风险治理。",
            evidence=evidence_base,
            fix="查看原始事件上下文，确认是否需要隔离 Pod、阻断网络、轮换凭据或回滚镜像。",
        )
    return findings


def analyze_runtime_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for event in events:
        findings.extend(analyze_runtime_event(event))
    return sort_findings(findings)
