#!/usr/bin/env bash
set -euo pipefail

# Defensive runtime collector: Falco with eBPF driver.
# Usage:
#   PLATFORM_URL="http://security-platform.default.svc.cluster.local:8000/api/kernel/events" ./scripts/install_falco_ebpf.sh

PLATFORM_URL="${PLATFORM_URL:-http://security-platform.default.svc.cluster.local:8000/api/kernel/events}"
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf \
  --set falco.json_output=true \
  --set falco.http_output.enabled=true \
  --set falco.http_output.url="$PLATFORM_URL"

echo "Falco eBPF runtime sensor installed. Webhook: $PLATFORM_URL"
