from __future__ import annotations

import re
from typing import Any, Dict, List

from backend.scanners.common import make_finding, sort_findings

SECRET_PATTERN = re.compile(
    r"(?i)(AKIA[0-9A-Z]{12,}|password\s*=|passwd\s*=|secret\s*=|token\s*=|api[_-]?key\s*=|private[_-]?key)",
)

DANGEROUS_TOOLS = ["curl", "wget", "nc", "netcat", "nmap", "openssh-server", "ssh", "telnet", "socat"]


def _clean_lines(text: str) -> List[tuple[int, str]]:
    result: List[tuple[int, str]] = []
    continued = ""
    start_line = 0
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if continued:
            continued += " " + line.rstrip("\\").strip()
        else:
            continued = line.rstrip("\\").strip()
            start_line = idx
        if not line.endswith("\\"):
            result.append((start_line, continued))
            continued = ""
            start_line = 0
    if continued:
        result.append((start_line, continued))
    return result


def scan_dockerfile_text(text: str, target: str = "Dockerfile") -> List[Dict[str, Any]]:
    """扫描 Dockerfile 内容并返回统一 Finding 列表。"""
    findings: List[Dict[str, Any]] = []
    lines = _clean_lines(text)
    has_user = False
    has_non_root_user = False
    has_healthcheck = False

    for line_no, line in lines:
        upper = line.upper()

        from_match = re.match(r"^FROM\s+([^\s]+)", line, re.IGNORECASE)
        if from_match:
            image = from_match.group(1)
            if image.endswith(":latest") or ":" not in image.split("@", 1)[0]:
                findings.append(make_finding(
                    rule_id="DF001",
                    severity="MEDIUM",
                    title="基础镜像版本未固定或使用 latest",
                    description="latest 标签会导致构建结果不可控，也会让漏洞复现和修复变困难。",
                    evidence=f"Line {line_no}: {line}",
                    fix="使用固定版本标签，例如 nginx:1.25-alpine，并定期升级基础镜像。",
                    source="custom-dockerfile",
                    target=target,
                    category="Dockerfile",
                ))

        if upper.startswith("USER "):
            has_user = True
            user_value = line.split(maxsplit=1)[1].strip()
            if user_value in {"root", "0"}:
                findings.append(make_finding(
                    rule_id="DF002",
                    severity="HIGH",
                    title="容器显式使用 root 用户运行",
                    description="容器内 root 用户会扩大攻击影响面，配合危险挂载或特权模式时会增加逃逸风险。",
                    evidence=f"Line {line_no}: {line}",
                    fix="创建普通用户并使用 USER appuser 运行应用。",
                    source="custom-dockerfile",
                    target=target,
                    category="Dockerfile",
                ))
            else:
                has_non_root_user = True

        if upper.startswith("ADD "):
            findings.append(make_finding(
                rule_id="DF003",
                severity="MEDIUM",
                title="Dockerfile 使用 ADD 指令",
                description="ADD 会自动解压本地压缩包，也可能拉取远程资源，可控性弱于 COPY。",
                evidence=f"Line {line_no}: {line}",
                fix="除非确实需要自动解压能力，否则建议使用 COPY。",
                source="custom-dockerfile",
                target=target,
                category="Dockerfile",
            ))

        if SECRET_PATTERN.search(line):
            findings.append(make_finding(
                rule_id="DF004",
                severity="CRITICAL",
                title="Dockerfile 中疑似出现明文凭据",
                description="密钥写入 Dockerfile 会进入镜像构建上下文或镜像层，容易造成凭据泄露。",
                evidence=f"Line {line_no}: {line[:120]}",
                fix="删除明文凭据，改用 Secret 管理、CI/CD 变量或运行时挂载。",
                source="custom-dockerfile",
                target=target,
                category="Dockerfile",
            ))

        if upper.startswith("RUN "):
            lowered = line.lower()
            if "curl" in lowered and "|" in lowered and ("sh" in lowered or "bash" in lowered):
                findings.append(make_finding(
                    rule_id="DF005",
                    severity="HIGH",
                    title="使用 curl/wget 管道执行脚本",
                    description="远程脚本直接管道给 shell 执行，容易引入供应链风险。",
                    evidence=f"Line {line_no}: {line}",
                    fix="下载后校验哈希或签名，再以固定版本安装。",
                    source="custom-dockerfile",
                    target=target,
                    category="Dockerfile",
                ))
            if "apt-get update" in lowered and "/var/lib/apt/lists" not in lowered:
                findings.append(make_finding(
                    rule_id="DF006",
                    severity="LOW",
                    title="apt 缓存未清理",
                    description="未清理包管理缓存会让镜像变大，增加不必要攻击面。",
                    evidence=f"Line {line_no}: {line}",
                    fix="在同一 RUN 层中追加 rm -rf /var/lib/apt/lists/*。",
                    source="custom-dockerfile",
                    target=target,
                    category="Dockerfile",
                ))
            if re.search(r"apt(-get)?\s+install", lowered):
                installed = [tool for tool in DANGEROUS_TOOLS if re.search(rf"\b{re.escape(tool)}\b", lowered)]
                if installed:
                    findings.append(make_finding(
                        rule_id="DF007",
                        severity="MEDIUM",
                        title="镜像中安装了高风险运维工具",
                        description="攻击者进入容器后可利用 curl、wget、nc、ssh 等工具进行下载、探测或横向移动。",
                        evidence=f"Line {line_no}: {line}",
                        fix="生产镜像尽量最小化，只保留运行应用必需组件。",
                        source="custom-dockerfile",
                        target=target,
                        category="Dockerfile",
                        extra={"tools": installed},
                    ))
            if re.search(r"chmod\s+777", lowered):
                findings.append(make_finding(
                    rule_id="DF008",
                    severity="MEDIUM",
                    title="使用 chmod 777 赋予过宽权限",
                    description="777 权限会让任意用户可读写执行文件，增加持久化和篡改风险。",
                    evidence=f"Line {line_no}: {line}",
                    fix="按最小权限原则设置文件权限，例如 755 或 640。",
                    source="custom-dockerfile",
                    target=target,
                    category="Dockerfile",
                ))

        if upper.startswith("EXPOSE ") and re.search(r"\b22\b", line):
            findings.append(make_finding(
                rule_id="DF009",
                severity="MEDIUM",
                title="镜像暴露 SSH 端口",
                description="容器通常不需要运行 SSH 服务，暴露 22 端口会增加暴力破解和横向移动面。",
                evidence=f"Line {line_no}: {line}",
                fix="删除 SSH 服务和 EXPOSE 22，使用 kubectl exec 或日志系统进行运维。",
                source="custom-dockerfile",
                target=target,
                category="Dockerfile",
            ))

        if upper.startswith("HEALTHCHECK"):
            has_healthcheck = True

    if not has_user:
        findings.append(make_finding(
            rule_id="DF010",
            severity="HIGH",
            title="Dockerfile 未指定非 root 用户",
            description="未设置 USER 时，镜像默认可能以 root 身份运行。",
            evidence="No USER instruction found",
            fix="创建低权限用户，并添加 USER appuser。",
            source="custom-dockerfile",
            target=target,
            category="Dockerfile",
        ))
    elif has_user and not has_non_root_user:
        # 已经通过 DF002 报告 root；这里不重复加缺失 USER。
        pass

    if not has_healthcheck:
        findings.append(make_finding(
            rule_id="DF011",
            severity="LOW",
            title="Dockerfile 未配置 HEALTHCHECK",
            description="缺少健康检查会降低运行时可观测性和自动恢复能力。",
            evidence="No HEALTHCHECK instruction found",
            fix="根据应用端口或健康接口添加 HEALTHCHECK。",
            source="custom-dockerfile",
            target=target,
            category="Dockerfile",
        ))

    return sort_findings(findings)


def scan_dockerfile_path(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return scan_dockerfile_text(f.read(), target=path)
