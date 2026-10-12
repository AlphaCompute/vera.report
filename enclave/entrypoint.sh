#!/bin/bash
# Enclave init script
# Bridges vsock (port 5000) → TCP localhost:5000
# then starts the Node.js crypto server

set -e

# Docker local mode never impersonates real Nitro hardware.
if [ "${ENCLAVE_LOCAL_IPFS_TEST:-0}" = "1" ] && [ -e /dev/nsm ]; then
  echo "Local IPFS test mode is forbidden on Nitro" >&2; exit 1
fi
if [ "$(id -u)" = "0" ]; then
  if [ "${ENCLAVE_LOCAL_IPFS_TEST:-0}" != "1" ]; then ip link set lo up; fi
  mkdir -p "${IPFS_PATH:-/app/ipfs}"
  if [ -c /dev/nsm ]; then
    # Seed kernel randomness from NSM before starting any cryptographic service.
    timeout 15 /app/bin/vera-nsm-seed
    chown enclave:enclave /dev/nsm
    chmod 0600 /dev/nsm
    if [ "${ENCLAVE_IPFS_ENABLED:-0}" = "1" ]; then
      # Enclave memory is the only storage. Bound the disposable Kubo repo.
      [[ "${ENCLAVE_IPFS_REPO_MIB:-}" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid ENCLAVE_IPFS_REPO_MIB" >&2; exit 1; }
      mount -t tmpfs -o "size=${ENCLAVE_IPFS_REPO_MIB}m,mode=0700,nosuid,nodev,noexec" tmpfs "${IPFS_PATH:-/app/ipfs}"
    fi
  fi
  chown enclave:enclave "${IPFS_PATH:-/app/ipfs}"
  exec setpriv --reuid=enclave --regid=enclave --init-groups --no-new-privs "$0" "$@"
fi

pids=() optional=()
cleanup() { for pid in "${optional[@]}" "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
# Optional (confidential-case) services run under this supervisor instead of
# joining the fail-together set below: their failure must never stop legacy
# crypto. A child that exits is restarted with exponential backoff; a run that
# lasted SUPERVISOR_STABLE_SECONDS resets it. After SUPERVISOR_MAX_FAILURES
# consecutive quick failures the service stays down until the enclave restarts.
supervise() {
  local name="$1" delay="${SUPERVISOR_INITIAL_DELAY:-5}" failures=0 child started
  shift
  trap 'kill "$child" 2>/dev/null; exit 0' TERM INT
  while :; do
    started=$SECONDS
    "$@" & child=$!
    wait "$child" || true
    if [ $((SECONDS - started)) -ge "${SUPERVISOR_STABLE_SECONDS:-600}" ]; then failures=0; delay="${SUPERVISOR_INITIAL_DELAY:-5}"; fi
    failures=$((failures + 1))
    if [ "$failures" -ge "${SUPERVISOR_MAX_FAILURES:-8}" ]; then
      echo "Optional service $name stopped after $failures failures; legacy services continue" >&2
      while :; do sleep 3600 & child=$!; wait "$child"; done
    fi
    echo "Optional service $name exited; restarting in $delay s" >&2
    sleep "$delay" & child=$!; wait "$child"
    delay=$((delay * 2 > ${SUPERVISOR_MAX_DELAY:-300} ? ${SUPERVISOR_MAX_DELAY:-300} : delay * 2))
  done
}
if [ "${ENCLAVE_IPFS_ENABLED:-0}" = "1" ]; then
  # Same offline lockdown as the API task sidecar (ipfs-sidecar-entrypoint.sh).
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
  ipfs daemon --offline > /dev/null 2>&1 & pids+=("$!")
  ready=0
  for attempt in $(seq 1 30); do
    if node -e 'fetch("http://127.0.0.1:5001/api/v0/version", {method:"POST",signal:AbortSignal.timeout(1000)}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))' >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "IPFS failed readiness" >&2; exit 1; }
  node /app/dist/ipfs-proxy.js & pids+=("$!")
  if [ "${ENCLAVE_LOCAL_IPFS_TEST:-0}" != "1" ]; then
    socat -T 900 VSOCK-LISTEN:5002,fork,max-children=1,reuseaddr TCP:127.0.0.1:5002 & pids+=("$!")
  fi
fi
if [ "${ENCLAVE_LOCAL_IPFS_TEST:-0}" != "1" ]; then
  socat -T 5 VSOCK-LISTEN:5000,fork,max-children=16,reuseaddr TCP:127.0.0.1:5000 & pids+=("$!")
fi
node /app/dist/server.js & pids+=("$!")
if [ "${ENCLAVE_LOCAL_IPFS_TEST:-0}" != "1" ]; then
  socat -T 20 VSOCK-LISTEN:5003,fork,max-children=16,reuseaddr TCP:127.0.0.1:5003 & pids+=("$!")
  node /app/dist/channel-server.js & pids+=("$!")
  # Only measured image configuration may enable these processes. The API's
  # environment flag cannot change the enclave process set. Enabling requires
  # a newly built, measured and reviewed EIF and release manifest.
  if [ "$(node -p 'require("/app/confidential-config.json").enabled === true')" = "true" ]; then
    # Inbound attested sessions and outbound ciphertext storage RPC to CID 3.
    # The server verifies the release manifest against its own NSM measurements.
    # Supervised, never in the fail-together set: see supervise() above.
    supervise session-bridge socat -T 30 VSOCK-LISTEN:5004,fork,max-children=16,reuseaddr TCP:127.0.0.1:5004 & optional+=("$!")
    supervise storage-bridge socat -T 60 TCP-LISTEN:5005,bind=127.0.0.1,fork,max-children=32,reuseaddr VSOCK-CONNECT:3:5005 & optional+=("$!")
    supervise confidential-server node /app/dist/confidential-server.js & optional+=("$!")
  fi
fi
# Any failed legacy child stops the bundle; do not leave apparently healthy
# crypto running after its storage/transport has died.
wait -n "${pids[@]}"
exit 1
