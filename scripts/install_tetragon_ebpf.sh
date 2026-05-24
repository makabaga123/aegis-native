#!/usr/bin/env bash
set -euo pipefail

# Defensive runtime collector: Tetragon eBPF process/network/file visibility.
# Tetragon events can be exported and posted to /api/kernel/events/batch.
helm repo add cilium https://helm.cilium.io
helm repo update
helm upgrade --install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.exportAllowList='{event_set=PROCESS_EXEC,event_set=PROCESS_EXIT,event_set=PROCESS_KPROBE}'

echo "Tetragon eBPF sensor installed. Use tetragon CLI/exporter to send JSON events to /api/kernel/events/batch."
