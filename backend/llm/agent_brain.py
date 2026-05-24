from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from backend.scanners.common import SEVERITY_WEIGHT, normalize_severity, summarize_findings


class SecurityAgentBrain:
    """LLM-compatible reasoning layer for the security agent.

    Default mode is local deterministic reasoning so the project can run without API keys.
    If you later want a real LLM, keep this interface and replace/extend _call_external_llm().
    """

    def __init__(self, mode: str | None = None) -> None:
        self.mode = mode or os.getenv("AGENT_LLM_MODE", "local")

    def plan(self, inputs: Dict[str, Any]) -> List[Dict[str, str]]:
        plan: List[Dict[str, str]] = []
        mapping = [
            ("image", "image_scan", "调用 Trivy 进行镜像 CVE/Secret/配置扫描"),
            ("dockerfile_text", "dockerfile_scan", "检测 Dockerfile 中的 root、latest、ADD、Secret、危险工具等风险"),
            ("k8s_yaml_text", "k8s_yaml_scan", "检测 K8s Workload、Pod Security、hostPath、RBAC、Service 暴露等风险"),
            ("terraform_text", "terraform_iac_scan", "检测 Terraform 安全组、IAM、公开存储、硬编码云凭据等风险"),
            ("cloud_config_text", "cloud_config_scan", "检测云资源清单中的公网暴露、公开 Bucket、IAM 过权和未加密"),
            ("runtime_events", "runtime_edr_scan", "基于运行时进程、文件、网络事件进行 EDR 风格行为检测"),
        ]
        for key, detector, reason in mapping:
            value = inputs.get(key)
            if value:
                plan.append({"detector": detector, "reason": reason})
        if not plan:
            plan.append({"detector": "no_input", "reason": "没有可分析的资产输入"})
        return plan

    def correlate_attack_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_rule = {str(f.get("rule_id")): f for f in findings}
        titles = "\n".join(str(f.get("title", "")) + " " + str(f.get("evidence", "")) for f in findings).lower()
        paths: List[Dict[str, Any]] = []

        has_privileged = any(r.startswith("K8S007") or r == "EDR008" for r in by_rule)
        has_hostpath = any(r.startswith("K8S005") or "docker.sock" in str(f.get("evidence", "")) for r, f in by_rule.items())
        has_shell = any(r in {"EDR001"} or "shell" in str(f.get("title", "")).lower() for r, f in by_rule.items())
        has_token = any("serviceaccount" in str(f.get("evidence", "")).lower() or "token" in str(f.get("title", "")).lower() for f in findings)
        has_public_cloud = any(str(f.get("rule_id", "")).startswith(("CLOUD001", "TF001")) for f in findings)
        has_iam = any(str(f.get("rule_id", "")).startswith(("CLOUD004", "TF003")) for f in findings)

        if has_privileged and has_hostpath:
            paths.append({
                "name": "容器逃逸高危链路",
                "risk": "CRITICAL",
                "story": "Workload 同时存在 privileged/SYS_ADMIN 与 hostPath/docker.sock 访问，攻击者进入容器后可能触达宿主机或容器运行时。",
                "kill_chain": ["初始进入容器", "获取高权限容器上下文", "访问宿主机文件/运行时 Socket", "逃逸或控制节点"],
                "actions": ["立即下线特权配置", "移除 hostPath/docker.sock", "轮换节点和集群凭据", "审计该节点上其他 Pod"],
            })
        if has_shell and (has_token or has_iam):
            paths.append({
                "name": "容器入侵到集群/云权限滥用链路",
                "risk": "HIGH",
                "story": "运行时出现 shell，同时存在 Token/IAM 权限风险，攻击者可能从容器内调用 K8s API 或云 API 横向移动。",
                "kill_chain": ["WebShell/RCE", "读取 Token 或云凭据", "枚举 API 权限", "横向移动或数据访问"],
                "actions": ["隔离 Pod", "禁用 SA Token 自动挂载", "收紧 RBAC/IAM", "轮换相关凭据"],
            })
        if has_public_cloud and has_iam:
            paths.append({
                "name": "公网暴露 + 云权限过宽链路",
                "risk": "HIGH",
                "story": "云侧存在公网入口，同时 IAM 权限过宽，外部攻击面和凭据滥用影响面都偏大。",
                "kill_chain": ["公网扫描发现入口", "利用弱口令/漏洞", "获取云凭据", "扩大云资源控制范围"],
                "actions": ["收敛公网 CIDR", "关闭无必要公网服务", "最小化 IAM Action/Resource", "启用云审计和异常登录告警"],
            })
        if "xmrig" in titles or "stratum" in titles:
            paths.append({
                "name": "疑似挖矿入侵链路",
                "risk": "CRITICAL",
                "story": "运行时命中挖矿进程或矿池连接，说明工作负载大概率已经被入侵并被滥用计算资源。",
                "kill_chain": ["初始漏洞利用", "下载挖矿程序", "连接矿池", "持续消耗计算资源"],
                "actions": ["立即隔离", "保留证据", "回滚镜像", "排查入口漏洞", "设置资源限制和 egress 策略"],
            })
        return paths

    def prioritize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        def score(f: Dict[str, Any]) -> int:
            base = SEVERITY_WEIGHT.get(normalize_severity(f.get("severity")), 0)
            rule_id = str(f.get("rule_id", ""))
            bonus = 0
            if rule_id.startswith(("K8S007", "K8S005", "EDR004", "EDR008", "CLOUD003", "TF002")):
                bonus += 5
            if f.get("category") in {"Runtime EDR", "Runtime"}:
                bonus += 3
            return base + bonus

        ranked = sorted(findings, key=score, reverse=True)
        actions: List[Dict[str, Any]] = []
        seen = set()
        for item in ranked:
            key = item.get("rule_id")
            if key in seen:
                continue
            seen.add(key)
            actions.append({
                "priority_score": score(item),
                "severity": normalize_severity(item.get("severity")),
                "title": item.get("title"),
                "target": item.get("target"),
                "action": item.get("remediation") or item.get("fix"),
                "rule_id": key,
            })
            if len(actions) >= 10:
                break
        return actions

    def executive_summary(self, findings: List[Dict[str, Any]], attack_paths: List[Dict[str, Any]]) -> str:
        summary = summarize_findings(findings)
        counts = summary["counts"]
        if not findings:
            return "本次 Agent 未发现明确风险。建议继续接入真实 Trivy、Falco/eBPF 和云资源清单进行持续检测。"
        top = []
        if counts.get("CRITICAL", 0):
            top.append(f"Critical {counts['CRITICAL']} 个")
        if counts.get("HIGH", 0):
            top.append(f"High {counts['HIGH']} 个")
        chain_text = f"，并关联出 {len(attack_paths)} 条攻击路径" if attack_paths else ""
        return f"本次 AI Agent 共发现 {summary['total']} 个风险，其中 {'、'.join(top) or '以中低风险为主'}，总风险等级为 {summary['risk_level']}{chain_text}。建议优先处理运行时告警、特权容器、hostPath/docker.sock、公开云入口和硬编码凭据。"

    def explain_finding(self, finding: Dict[str, Any]) -> Dict[str, str]:
        return {
            "risk_explanation": finding.get("description", ""),
            "business_impact": self._impact(finding),
            "remediation": finding.get("remediation") or finding.get("fix") or "按最小权限和最小暴露面原则修复。",
        }

    def _impact(self, finding: Dict[str, Any]) -> str:
        category = finding.get("category")
        severity = normalize_severity(finding.get("severity"))
        if category in {"Runtime EDR", "Runtime"}:
            return "这不是单纯配置问题，而是运行阶段已经出现可疑行为，优先级应高于普通静态扫描结果。"
        if severity == "CRITICAL":
            return "可能导致容器逃逸、凭据泄露、云账号接管或关键数据暴露，需要立即处理。"
        if severity == "HIGH":
            return "可能被组合进攻击链，建议在上线前或最近一次变更窗口内修复。"
        return "属于安全加固项，可纳入基线治理和 CI/CD 阻断策略。"

    def as_json_prompt(self, findings: List[Dict[str, Any]], attack_paths: List[Dict[str, Any]]) -> str:
        """For interview/demo: show what would be sent to a real LLM after masking."""
        compact = [{k: f.get(k) for k in ("rule_id", "severity", "title", "target", "evidence", "category")} for f in findings[:30]]
        return json.dumps({"task": "explain_cloud_native_security_risks", "findings": compact, "attack_paths": attack_paths}, ensure_ascii=False, indent=2)
