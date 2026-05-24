from __future__ import annotations

import re
from typing import Dict, List

from backend.scanners.common import make_finding, sort_findings

SECRET_PATTERN = re.compile(r"(?i)(access_key|secret_key|password|token|private_key|api_key)\s*=\s*\"([^\"]+)\"")
PUBLIC_CIDR_PATTERN = re.compile(r'(?i)(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*("0\.0\.0\.0/0"|"::/0")[^\]]*\]')
PORT_PATTERN = re.compile(r'(?is)(from_port\s*=\s*(\d+).*?to_port\s*=\s*(\d+))')
WILDCARD_ACTION_PATTERN = re.compile(r'(?i)"Action"\s*:\s*(\[\s*)?"\*"')
PUBLIC_BUCKET_PATTERN = re.compile(r'(?i)(acl\s*=\s*"public-read"|aws_s3_bucket_public_access_block[\s\S]*?block_public_acls\s*=\s*false)')
NO_ENCRYPTION_PATTERN = re.compile(r'(?i)(encrypted\s*=\s*false|server_side_encryption_configuration\s*=\s*\[\s*\])')


def scan_terraform_text(text: str, target: str = "terraform") -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []

    for match in PUBLIC_CIDR_PATTERN.finditer(text):
        window = text[max(0, match.start()-250): match.end()+250]
        ports = PORT_PATTERN.findall(window)
        risky_port = any(int(p[1]) in {22, 3389, 2375, 2376, 5432, 3306, 6379, 6443, 10250} or int(p[2]) in {22, 3389, 2375, 2376, 5432, 3306, 6379, 6443, 10250} for p in ports)
        findings.append(make_finding(
            rule_id="TF001",
            severity="CRITICAL" if risky_port else "HIGH",
            title="Terraform 安全组向公网开放",
            description="安全组/防火墙规则允许 0.0.0.0/0 或 ::/0 访问，管理端口和数据库端口尤其危险。",
            evidence=match.group(0),
            fix="限制 cidr_blocks；使用堡垒机/VPN；把数据库和控制面端口放入私有网络。",
            source="terraform-agent",
            target=target,
            category="Cloud IaC",
        ))

    for match in SECRET_PATTERN.finditer(text):
        findings.append(make_finding(
            rule_id="TF002",
            severity="CRITICAL",
            title="Terraform 中疑似硬编码云凭据",
            description="凭据写入 IaC 会进入 Git 历史、CI 日志和状态文件，容易导致云账号接管。",
            evidence=f"{match.group(1)}=[MASKED_SECRET]",
            fix="立即轮换凭据；改用环境变量、OIDC、云原生 Secret 管理或短期角色凭证。",
            source="terraform-agent",
            target=target,
            category="Cloud IaC",
        ))

    if WILDCARD_ACTION_PATTERN.search(text):
        findings.append(make_finding(
            rule_id="TF003",
            severity="HIGH",
            title="Terraform IAM Policy 使用通配符 Action",
            description="IAM Action 为 * 代表权限过宽，凭据泄露后影响面扩大。",
            evidence="Action=\"*\"",
            fix="按最小权限列出必要 Action，并限制 Resource 与 Condition。",
            source="terraform-agent",
            target=target,
            category="Cloud IaC",
        ))

    if PUBLIC_BUCKET_PATTERN.search(text):
        findings.append(make_finding(
            rule_id="TF004",
            severity="CRITICAL",
            title="Terraform 对象存储可能公开访问",
            description="公开 Bucket 可能造成数据泄露或被攻击者写入恶意内容。",
            evidence="public-read or public access block disabled",
            fix="启用 block public access；删除 public-read ACL；用最小权限 bucket policy。",
            source="terraform-agent",
            target=target,
            category="Cloud IaC",
        ))

    if NO_ENCRYPTION_PATTERN.search(text):
        findings.append(make_finding(
            rule_id="TF005",
            severity="MEDIUM",
            title="Terraform 资源未启用加密",
            description="存储或数据库未加密会增加敏感数据泄露后的影响范围。",
            evidence="encrypted=false or SSE disabled",
            fix="启用 KMS/SSE；确保快照、备份和日志同样加密。",
            source="terraform-agent",
            target=target,
            category="Cloud IaC",
        ))

    return sort_findings(findings)


def scan_terraform_path(path: str) -> List[Dict[str, object]]:
    with open(path, "r", encoding="utf-8") as f:
        return scan_terraform_text(f.read(), target=path)
