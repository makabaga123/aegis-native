# 新增云安全检测模块

除了 Docker/Kubernetes，本项目补充了云安全和 IaC 检测能力。

## 已补充模块

| 模块 | 作用 | 文件 |
|---|---|---|
| Terraform IaC 检测 | 检测公网安全组、公开 Bucket、IAM `*` 权限、硬编码凭据、未加密 | `backend/scanners/terraform_scanner.py` |
| 云资源清单检测 | 检测 JSON 导出的 AWS/Azure/GCP 风险配置 | `backend/scanners/cloud_config_scanner.py` |
| K8s RBAC 检测 | 检测 `*` 权限、读取 Secret、pods/exec、cluster-admin 绑定 | `backend/scanners/k8s_yaml_scanner.py` |
| K8s 暴露面检测 | 检测 NodePort、LoadBalancer | `backend/scanners/k8s_yaml_scanner.py` |
| K8s 网络隔离检测 | 检测提交清单中是否缺少 NetworkPolicy | `backend/scanners/k8s_yaml_scanner.py` |
| Runtime EDR | 检测运行时进程、文件、网络、提权行为 | `backend/scanners/runtime_edr.py` |

## 还可以继续扩展

后续可以接入：

- Cloud Custodian：真实云账号策略扫描和治理；
- Prowler / ScoutSuite：AWS/GCP/Azure CIS Benchmark；
- kube-bench：Kubernetes CIS Benchmark；
- kube-hunter：K8s 攻击面探测；
- KubeArmor：运行时策略阻断；
- OPA Gatekeeper / Kyverno：准入控制；
- SBOM / SLSA / Cosign：供应链安全检测。
