# Runtime EDR 风格检测设计

传统 Docker/Kubernetes 安全不只做部署前扫描，还需要运行时检测。这个项目新增了 EDR 风格的运行时行为检测模块。

## 支持的事件类型

平台可以接收类似 Falco、KubeArmor、eBPF Agent、容器审计日志的 JSON 事件。

支持字段示例：

```json
{
  "event_type": "execve",
  "namespace": "default",
  "pod": "web-xxx",
  "container": "web",
  "process_name": "bash",
  "cmdline": "bash -i"
}
```

## 检测规则

| 规则 | 检测内容 |
|---|---|
| EDR001 | 容器内启动 shell |
| EDR002 | 运行时执行 apt/yum/apk/pip/npm 等包管理器 |
| EDR003 | curl/wget/nc/socat 下载脚本或远程执行 |
| EDR004 | 疑似挖矿进程或矿池连接 |
| EDR005 | 访问 ServiceAccount Token、docker.sock、/etc/shadow 等敏感文件 |
| EDR006 | 修改 /etc、/usr/bin 等系统关键路径 |
| EDR007 | 疑似异常外联、C2、隧道或反弹端口 |
| EDR008 | privileged、SYS_ADMIN、setns、mount 等逃逸相关行为 |

## API

```text
POST /api/runtime/events
POST /api/runtime/events/batch
GET  /api/runtime/timeline
```

测试：

```bash
curl -X POST http://127.0.0.1:8000/api/runtime/events/batch \
  -H "Content-Type: application/json" \
  --data-binary @examples/runtime/edr-events.json
```
