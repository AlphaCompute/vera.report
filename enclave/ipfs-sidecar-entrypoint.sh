#!/bin/bash
# Kubo sidecar for the API ECS task. Not part of the enclave image.
# The node is disposable and only ever holds ciphertext; the S3 archive is the
# source of truth. Kubo stays offline with its RPC API on loopback, and only
# the add/cat/rm proxy is reachable by the API container.

set -euo pipefail

if [ ! -f "$IPFS_PATH/config" ]; then ipfs init --empty-repo >/dev/null; fi
ipfs config Addresses.API /ip4/127.0.0.1/tcp/5001
ipfs config --json Addresses.Gateway '[]'
ipfs config --json Addresses.Swarm '[]'
ipfs config --json Addresses.Announce '[]'
ipfs config --json AutoConf.Enabled false
ipfs config --json Bootstrap '[]'
ipfs config --json DNS.Resolvers '{}'
ipfs config --json Routing.DelegatedRouters '[]'
ipfs config --json Ipns.DelegatedPublishers '[]'
ipfs config Routing.Type none
ipfs config --json Provide.Enabled false
# AutoConf is off, so an unresolved "auto" placeholder would stop the daemon.
if ipfs config show | grep -q '"auto"'; then echo "Kubo config still contains auto values" >&2; exit 1; fi

pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
ipfs daemon --offline >/dev/null 2>&1 & pids+=("$!")
ready=0
for attempt in $(seq 1 30); do
  if node -e 'fetch("http://127.0.0.1:5001/api/v0/version", {method:"POST",signal:AbortSignal.timeout(1000)}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))' >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "IPFS failed readiness" >&2; exit 1; }
node /app/dist/ipfs-proxy.js & pids+=("$!")
# Either process exiting stops the container so ECS replaces the task.
wait -n "${pids[@]}"
exit 1
