# Tetragon eBPF Runtime Collection

This project does not ship a custom kernel module. For a safe defensive setup,
use Tetragon as the kernel-level eBPF sensor and send exported JSON events to:

```bash
POST /api/kernel/events
POST /api/kernel/events/batch
```

The platform normalizes Tetragon `process_exec`, `process_kprobe`, and related
events into the Runtime EDR schema, then applies behavior detections such as:

- shell in container
- runtime package manager
- curl/wget remote script
- crypto miner process
- sensitive file or ServiceAccount token access
- system path modification
- suspicious egress / C2-like behavior
- setns/mount/CAP_SYS_ADMIN/privileged behavior
