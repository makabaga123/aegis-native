# Runtime Kernel-Level Collection

This project adds a runtime security input path similar to EDR/CWPP systems.

## Defensive design

The platform itself does not compile or insert a custom kernel module. Instead, it consumes JSON events from established runtime security sensors:

- Falco eBPF driver
- Tetragon eBPF
- KubeArmor LSM/eBPF style events
- generic process/file/network event JSON

## Endpoints

```text
POST /api/kernel/events
POST /api/kernel/events/batch
```

## Install Falco eBPF

```bash
PLATFORM_URL="http://security-platform.default.svc.cluster.local:8000/api/kernel/events" \
  ./scripts/install_falco_ebpf.sh
```

## Install Tetragon eBPF

```bash
./scripts/install_tetragon_ebpf.sh
```

## Detection examples

The RuntimeEDRAgent can detect:

- container shell execution
- runtime package manager execution
- curl/wget remote script execution
- crypto-mining process or stratum connection
- ServiceAccount token access
- docker.sock access
- sensitive host path access
- writes under `/etc`, `/usr/bin`, `/bin`
- suspicious egress or C2-like traffic
- privileged / `CAP_SYS_ADMIN` / `setns` / `mount` behavior

## Test with sample events

```bash
curl -X POST http://127.0.0.1:8000/api/kernel/events \
  -H 'Content-Type: application/json' \
  --data @examples/kernel/falco-shell-event.json
```
