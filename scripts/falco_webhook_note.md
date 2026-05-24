# Falco Webhook 接入说明

平台接口：

```text
POST http://<platform-host>:8000/api/falco/events
```

生产环境建议使用 falcosidekick，把 Falco 事件转发到该 HTTP endpoint。

本地测试：

```bash
curl -X POST "http://127.0.0.1:8000/api/falco/events" \
  -H "Content-Type: application/json" \
  --data-binary @examples/falco-event.json
```
