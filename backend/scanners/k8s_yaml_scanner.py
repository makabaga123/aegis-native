from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from backend.scanners.common import make_finding, sort_findings

HOSTPATH_CRITICAL_PATHS = {"/", "/etc", "/proc", "/sys", "/var/run/docker.sock", "/var/lib/kubelet"}
SECRET_NAME_PATTERN = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")


def _resource_name(resource: Dict[str, Any]) -> str:
    kind = resource.get("kind", "Unknown")
    name = resource.get("metadata", {}).get("name", "noname")
    namespace = resource.get("metadata", {}).get("namespace", "default")
    return f"{kind}/{namespace}/{name}"


def _pod_specs(resource: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    kind = resource.get("kind")
    if kind == "Pod":
        yield _resource_name(resource), resource.get("spec", {}) or {}
    elif kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController"}:
        spec = (((resource.get("spec") or {}).get("template") or {}).get("spec") or {})
        yield _resource_name(resource), spec
    elif kind == "Job":
        spec = (((resource.get("spec") or {}).get("template") or {}).get("spec") or {})
        yield _resource_name(resource), spec
    elif kind == "CronJob":
        spec = (((((resource.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {})
        yield _resource_name(resource), spec


def _all_containers(pod_spec: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for group in ("containers", "initContainers", "ephemeralContainers"):
        for container in pod_spec.get(group, []) or []:
            yield group, container


def _add(findings: List[Dict[str, Any]], **kwargs: Any) -> None:
    findings.append(make_finding(**kwargs))


def scan_k8s_yaml_text(text: str, target: str = "k8s-yaml") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        resources = [doc for doc in yaml.safe_load_all(text) if isinstance(doc, dict)]
    except yaml.YAMLError as exc:
        return [make_finding(
            rule_id="K8S000",
            severity="HIGH",
            title="Kubernetes YAML 解析失败",
            description="YAML 格式错误会导致部署失败，也可能掩盖安全配置问题。",
            evidence=str(exc),
            fix="检查缩进、冒号、列表格式和多文档分隔符。",
            source="custom-k8s-yaml",
            target=target,
            category="Kubernetes",
        )]

    has_network_policy = any((r.get("kind") == "NetworkPolicy") for r in resources)
    has_workload = any((r.get("kind") in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}) for r in resources)
    if has_workload and not has_network_policy:
        _add(findings,
            rule_id="K8S020",
            severity="MEDIUM",
            title="未发现 NetworkPolicy 网络隔离策略",
            description="命名空间内缺少 NetworkPolicy 时，Pod 之间和出站流量通常更容易横向移动。",
            evidence=f"{target}: no NetworkPolicy in submitted manifests",
            fix="为业务命名空间配置默认拒绝入站/出站的 NetworkPolicy，再按需放通必要流量。",
            source="custom-k8s-yaml",
            target=target,
            category="Kubernetes",
        )

    for resource in resources:
        res_target = _resource_name(resource)
        kind = resource.get("kind")

        if kind == "Namespace":
            labels = (resource.get("metadata") or {}).get("labels") or {}
            enforce = labels.get("pod-security.kubernetes.io/enforce")
            if enforce not in {"restricted", "baseline"}:
                _add(findings,
                    rule_id="K8S021",
                    severity="MEDIUM",
                    title="Namespace 未配置 Pod Security Admission 基线",
                    description="缺少 Pod Security enforce 标签时，危险 Pod 配置更容易进入集群。",
                    evidence=f"{res_target}: pod-security.kubernetes.io/enforce={enforce}",
                    fix="为生产命名空间设置 pod-security.kubernetes.io/enforce=restricted，无法一次到位时至少使用 baseline。",
                    source="custom-k8s-yaml",
                    target=res_target,
                    category="Kubernetes",
                )
            continue

        if kind in {"Role", "ClusterRole"}:
            for idx, rule in enumerate((resource.get("rules") or [])):
                verbs = {str(v).lower() for v in (rule.get("verbs") or [])}
                api_resources = {str(r).lower() for r in (rule.get("resources") or [])}
                if "*" in verbs or "*" in api_resources:
                    _add(findings,
                        rule_id="K8S022",
                        severity="HIGH",
                        title="RBAC 权限使用通配符",
                        description="Role/ClusterRole 使用 * verbs 或 * resources，容易造成权限过宽和横向移动。",
                        evidence=f"{res_target}: rules[{idx}] verbs={list(verbs)} resources={list(api_resources)}",
                        fix="按最小权限列出必要 verbs/resources，并限制 namespace 范围。",
                        source="custom-k8s-yaml",
                        target=res_target,
                        category="Kubernetes RBAC",
                    )
                if "secrets" in api_resources and ({"get", "list", "watch"} & verbs or "*" in verbs):
                    _add(findings,
                        rule_id="K8S023",
                        severity="HIGH",
                        title="RBAC 允许读取 Secret",
                        description="读取 Secret 的权限一旦被 Pod Token 滥用，会导致凭据泄露和横向移动。",
                        evidence=f"{res_target}: rules[{idx}] can read secrets",
                        fix="只给确实需要的控制器读取指定 Secret；避免给普通工作负载 list/watch secrets。",
                        source="custom-k8s-yaml",
                        target=res_target,
                        category="Kubernetes RBAC",
                    )
                if "pods/exec" in api_resources and ({"create", "*"} & verbs):
                    _add(findings,
                        rule_id="K8S024",
                        severity="HIGH",
                        title="RBAC 允许 pod exec",
                        description="pods/exec create 权限可进入容器执行命令，常被用于横向移动或人工持久化。",
                        evidence=f"{res_target}: rules[{idx}] can create pods/exec",
                        fix="严格限制 pods/exec 权限，只授予运维 break-glass 角色并开启审计。",
                        source="custom-k8s-yaml",
                        target=res_target,
                        category="Kubernetes RBAC",
                    )
            continue

        if kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = resource.get("roleRef") or {}
            subjects = resource.get("subjects") or []
            role_name = str(role_ref.get("name", ""))
            if role_name == "cluster-admin" or any(str(s.get("name", "")) in {"system:masters", "default"} for s in subjects):
                _add(findings,
                    rule_id="K8S025",
                    severity="CRITICAL",
                    title="RBAC 绑定高危集群管理员权限",
                    description="cluster-admin 或默认 ServiceAccount 被绑定高权限，会显著扩大容器入侵后的集群控制面风险。",
                    evidence=f"{res_target}: roleRef={role_name}; subjects={subjects}",
                    fix="避免把 cluster-admin 绑定给工作负载或默认账号；使用按 namespace/资源拆分的最小权限角色。",
                    source="custom-k8s-yaml",
                    target=res_target,
                    category="Kubernetes RBAC",
                )
            continue

        if kind == "Service":
            spec = resource.get("spec") or {}
            svc_type = spec.get("type")
            ports = spec.get("ports") or []
            if svc_type in {"NodePort", "LoadBalancer"}:
                _add(findings,
                    rule_id="K8S026",
                    severity="HIGH" if svc_type == "LoadBalancer" else "MEDIUM",
                    title=f"Service 使用 {svc_type} 暴露服务",
                    description="NodePort/LoadBalancer 会扩大外部攻击面，若暴露管理端口风险更高。",
                    evidence=f"{res_target}: type={svc_type}; ports={ports}",
                    fix="确认是否必须公网暴露；优先使用 Ingress + WAF/认证；管理端口只允许内网/VPN。",
                    source="custom-k8s-yaml",
                    target=res_target,
                    category="Kubernetes Exposure",
                )
            continue

        if kind == "Secret":
            if resource.get("stringData"):
                _add(findings,
                    rule_id="K8S013",
                    severity="CRITICAL",
                    title="Secret 使用 stringData 存储明文敏感信息",
                    description="stringData 中的内容是明文，提交到 Git 仓库后会直接泄露。",
                    evidence=f"{res_target}: stringData keys={list(resource.get('stringData', {}).keys())}",
                    fix="不要把 Secret 明文提交到仓库，使用 External Secrets、Sealed Secrets 或密钥管理服务。",
                    source="custom-k8s-yaml",
                    target=res_target,
                    category="Kubernetes",
                )
            continue

        for pod_target, pod_spec in _pod_specs(resource):
            if pod_spec.get("hostNetwork") is True:
                _add(findings,
                    rule_id="K8S001",
                    severity="HIGH",
                    title="Pod 启用了 hostNetwork",
                    description="共享宿主机网络命名空间会扩大攻击面，可能绕过部分网络隔离策略。",
                    evidence=f"{pod_target}: spec.hostNetwork=true",
                    fix="除非必须绑定宿主机网络，否则删除 hostNetwork: true。",
                    source="custom-k8s-yaml",
                    target=pod_target,
                    category="Kubernetes",
                )
            if pod_spec.get("hostPID") is True:
                _add(findings,
                    rule_id="K8S002",
                    severity="HIGH",
                    title="Pod 启用了 hostPID",
                    description="共享宿主机 PID 命名空间后，容器可能查看宿主机进程信息。",
                    evidence=f"{pod_target}: spec.hostPID=true",
                    fix="删除 hostPID: true，并使用标准容器隔离。",
                    source="custom-k8s-yaml",
                    target=pod_target,
                    category="Kubernetes",
                )
            if pod_spec.get("hostIPC") is True:
                _add(findings,
                    rule_id="K8S003",
                    severity="HIGH",
                    title="Pod 启用了 hostIPC",
                    description="共享宿主机 IPC 命名空间会增加进程间通信数据泄露风险。",
                    evidence=f"{pod_target}: spec.hostIPC=true",
                    fix="删除 hostIPC: true。",
                    source="custom-k8s-yaml",
                    target=pod_target,
                    category="Kubernetes",
                )
            if pod_spec.get("automountServiceAccountToken") is True:
                _add(findings,
                    rule_id="K8S004",
                    severity="MEDIUM",
                    title="Pod 显式自动挂载 ServiceAccount Token",
                    description="Token 被容器内攻击者获取后，可能被用于访问 Kubernetes API。",
                    evidence=f"{pod_target}: automountServiceAccountToken=true",
                    fix="不需要访问 API 的工作负载设置 automountServiceAccountToken: false。",
                    source="custom-k8s-yaml",
                    target=pod_target,
                    category="Kubernetes",
                )

            volumes = pod_spec.get("volumes", []) or []
            for volume in volumes:
                if "hostPath" in volume:
                    path = (volume.get("hostPath") or {}).get("path", "")
                    severity = "CRITICAL" if path in HOSTPATH_CRITICAL_PATHS or path.startswith("/var/run") else "HIGH"
                    _add(findings,
                        rule_id="K8S005",
                        severity=severity,
                        title="Pod 使用 hostPath 挂载宿主机路径",
                        description="hostPath 会让容器访问宿主机文件系统，挂载敏感路径时可能导致容器逃逸或凭据泄露。",
                        evidence=f"{pod_target}: volume {volume.get('name')} hostPath={path}",
                        fix="尽量改用 PVC、ConfigMap 或 Secret；禁止挂载 /、/etc、/proc、/sys、docker.sock 等敏感路径。",
                        source="custom-k8s-yaml",
                        target=pod_target,
                        category="Kubernetes",
                    )

            pod_security = pod_spec.get("securityContext", {}) or {}
            pod_run_as_non_root = pod_security.get("runAsNonRoot")

            for group, container in _all_containers(pod_spec):
                cname = container.get("name", "noname")
                ctarget = f"{pod_target}:{group}/{cname}"
                image = container.get("image", "")
                security = container.get("securityContext", {}) or {}

                if image.endswith(":latest") or (image and ":" not in image.split("@", 1)[0]):
                    _add(findings,
                        rule_id="K8S006",
                        severity="MEDIUM",
                        title="容器镜像使用 latest 或未固定版本",
                        description="未固定镜像版本会导致部署结果不可预测，不利于漏洞追踪和回滚。",
                        evidence=f"{ctarget}: image={image}",
                        fix="使用固定镜像版本或 digest，例如 nginx:1.25-alpine 或 image@sha256:...。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                if security.get("privileged") is True:
                    _add(findings,
                        rule_id="K8S007",
                        severity="CRITICAL",
                        title="容器启用了 privileged 特权模式",
                        description="特权容器拥有接近宿主机的权限，可能绕过容器隔离机制，是容器逃逸高危配置。",
                        evidence=f"{ctarget}: securityContext.privileged=true",
                        fix="删除 privileged: true，改用最小 capabilities。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                if security.get("allowPrivilegeEscalation") is True:
                    _add(findings,
                        rule_id="K8S008",
                        severity="HIGH",
                        title="容器允许权限提升",
                        description="allowPrivilegeEscalation=true 允许进程获得比父进程更高的权限。",
                        evidence=f"{ctarget}: allowPrivilegeEscalation=true",
                        fix="设置 allowPrivilegeEscalation: false。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                capabilities = ((security.get("capabilities") or {}).get("add") or [])
                cap_upper = {str(cap).upper() for cap in capabilities}
                if "SYS_ADMIN" in cap_upper or "ALL" in cap_upper:
                    _add(findings,
                        rule_id="K8S009",
                        severity="CRITICAL",
                        title="容器添加了高危 Linux Capability",
                        description="SYS_ADMIN 或 ALL 权限过大，常见于容器逃逸和内核攻击链。",
                        evidence=f"{ctarget}: capabilities.add={capabilities}",
                        fix="删除 SYS_ADMIN/ALL，只保留业务必须的 capability，并优先 drop ALL。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                if security.get("runAsUser") == 0:
                    _add(findings,
                        rule_id="K8S010",
                        severity="HIGH",
                        title="容器以 root 用户运行",
                        description="root 用户运行会扩大入侵后的影响面。",
                        evidence=f"{ctarget}: runAsUser=0",
                        fix="设置 runAsNonRoot: true，并使用非 0 UID。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )
                elif security.get("runAsNonRoot") is not True and pod_run_as_non_root is not True:
                    _add(findings,
                        rule_id="K8S011",
                        severity="MEDIUM",
                        title="未设置 runAsNonRoot",
                        description="缺少 runAsNonRoot 时，容器可能以 root 用户运行。",
                        evidence=f"{ctarget}: runAsNonRoot not true",
                        fix="在 Pod 或容器 securityContext 中设置 runAsNonRoot: true。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                if security.get("readOnlyRootFilesystem") is not True:
                    _add(findings,
                        rule_id="K8S012",
                        severity="MEDIUM",
                        title="未启用只读根文件系统",
                        description="可写根文件系统会让攻击者更容易落地恶意文件或修改程序。",
                        evidence=f"{ctarget}: readOnlyRootFilesystem not true",
                        fix="设置 readOnlyRootFilesystem: true，并将必要写入路径挂载为独立卷。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                resources = container.get("resources", {}) or {}
                limits = resources.get("limits") or {}
                requests = resources.get("requests") or {}
                if not limits or not requests:
                    _add(findings,
                        rule_id="K8S014",
                        severity="LOW",
                        title="容器未完整设置资源请求和限制",
                        description="缺少 CPU/Memory requests 或 limits 可能导致资源争抢或拒绝服务风险。",
                        evidence=f"{ctarget}: resources={resources}",
                        fix="为容器设置合理的 resources.requests 和 resources.limits。",
                        source="custom-k8s-yaml",
                        target=ctarget,
                        category="Kubernetes",
                    )

                for env in container.get("env", []) or []:
                    name = env.get("name", "")
                    if SECRET_NAME_PATTERN.search(name) and "value" in env:
                        _add(findings,
                            rule_id="K8S015",
                            severity="CRITICAL",
                            title="环境变量中疑似硬编码敏感信息",
                            description="明文敏感信息写在 YAML 中会被 Git、CI/CD 日志或集群 API 暴露。",
                            evidence=f"{ctarget}: env {name}=***",
                            fix="改用 Secret 引用 valueFrom.secretKeyRef，并避免把 Secret 明文提交到仓库。",
                            source="custom-k8s-yaml",
                            target=ctarget,
                            category="Kubernetes",
                        )

    return sort_findings(findings)


def scan_k8s_yaml_path(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return scan_k8s_yaml_text(f.read(), target=path)
