from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Dict, List

from backend.scanners.common import make_finding, normalize_severity, sort_findings


def _image_tag_findings(image: str) -> List[Dict[str, Any]]:
    image_without_digest = image.split("@", 1)[0]
    if image_without_digest.endswith(":latest") or ":" not in image_without_digest.rsplit("/", 1)[-1]:
        return [make_finding(
            rule_id="IMG001",
            severity="MEDIUM",
            title="镜像版本未固定或使用 latest",
            description="latest 或缺失 tag 会导致部署结果不稳定，不利于漏洞复现、回滚和治理。",
            evidence=f"image={image}",
            fix="使用固定版本 tag 或 digest，例如 nginx:1.25-alpine 或 nginx@sha256:...。",
            source="custom-image",
            target=image,
            category="Image",
        )]
    return []


def scan_image_with_trivy(image: str, timeout: int = 300) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(_image_tag_findings(image))

    if not shutil.which("trivy"):
        findings.append(make_finding(
            rule_id="TRIVY000",
            severity="INFO",
            title="当前环境未安装 Trivy，已跳过真实镜像漏洞扫描",
            description="平台代码已经集成 Trivy 调用，但本机没有 trivy 命令，因此无法获取真实 CVE 结果。",
            evidence="trivy command not found",
            fix="安装 Trivy 后重新扫描：trivy image --format json nginx:latest。",
            source="trivy",
            target=image,
            category="Image",
        ))
        return sort_findings(findings)

    cmd = ["trivy", "image", "--format", "json", "--quiet", image]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        findings.append(make_finding(
            rule_id="TRIVYTIMEOUT",
            severity="HIGH",
            title="Trivy 镜像扫描超时",
            description="镜像拉取或漏洞库查询耗时过长，扫描未完成。",
            evidence=" ".join(cmd),
            fix="检查网络、镜像仓库访问权限和 Trivy 缓存；必要时提高超时时间。",
            source="trivy",
            target=image,
            category="Image",
        ))
        return sort_findings(findings)

    if completed.returncode not in (0, 1):
        findings.append(make_finding(
            rule_id="TRIVYERROR",
            severity="HIGH",
            title="Trivy 镜像扫描执行失败",
            description="Trivy 命令返回异常，可能是镜像不存在、网络失败或认证失败。",
            evidence=completed.stderr[-500:] or completed.stdout[-500:],
            fix="确认镜像名称、网络连通性和私有仓库认证配置。",
            source="trivy",
            target=image,
            category="Image",
        ))
        return sort_findings(findings)

    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        findings.append(make_finding(
            rule_id="TRIVYJSON",
            severity="HIGH",
            title="Trivy 输出 JSON 解析失败",
            description="平台无法解析 Trivy 输出，可能是版本或输出格式异常。",
            evidence=str(exc),
            fix="确认 trivy image --format json 能正常输出 JSON。",
            source="trivy",
            target=image,
            category="Image",
        ))
        return sort_findings(findings)

    for result in data.get("Results", []) or []:
        target = result.get("Target", image)
        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN-CVE")
            severity = normalize_severity(vuln.get("Severity"))
            pkg = vuln.get("PkgName", "unknown-package")
            installed = vuln.get("InstalledVersion", "unknown")
            fixed = vuln.get("FixedVersion") or "暂无 fixed version"
            title = vuln.get("Title") or vuln.get("Description", "")[:80] or vuln_id
            findings.append(make_finding(
                rule_id=vuln_id,
                severity=severity,
                title=f"镜像漏洞：{vuln_id} / {pkg}",
                description=title,
                evidence=f"target={target}, package={pkg}, installed={installed}, fixed={fixed}",
                fix=f"升级 {pkg} 至 {fixed}；如果无修复版本，考虑更换基础镜像、降级暴露面或等待上游补丁。",
                source="trivy",
                target=target,
                category="Image",
                extra={"package": pkg, "installed_version": installed, "fixed_version": fixed},
            ))
        for misconf in result.get("Misconfigurations", []) or []:
            findings.append(make_finding(
                rule_id=misconf.get("ID", "TRIVY-MISCONF"),
                severity=normalize_severity(misconf.get("Severity")),
                title=f"Trivy 配置风险：{misconf.get('Title', 'misconfiguration')}",
                description=misconf.get("Description", "Trivy detected misconfiguration."),
                evidence=misconf.get("Message", target),
                fix=misconf.get("Resolution", "参考 Trivy 输出修复该错误配置。"),
                source="trivy",
                target=target,
                category="Image",
                extra=misconf,
            ))

    return sort_findings(findings)
