#!/bin/bash
# Isolated Nitro acceptance only; ordinary production builds never select this.
set -euo pipefail
if [ ! -c /dev/nsm ]; then
  echo 'Recipient acceptance requires Nitro NSM' >&2
  exit 1
fi
if [ "$(id -u)" = 0 ]; then
  ip link set lo up
  timeout 15 /app/bin/vera-nsm-seed
  chown enclave:enclave /dev/nsm
  chmod 0600 /dev/nsm
  exec setpriv --reuid=enclave --regid=enclave --init-groups --no-new-privs "$0" "$@"
fi
pids=()
cleanup() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
# Parent forwards opaque TLS bytes to KMS. The enclave client authenticates
# the fixed AWS hostname and public root chain; this relay is not trusted.
socat -T 20 TCP-LISTEN:8000,bind=127.0.0.1,fork,max-children=16,reuseaddr VSOCK-CONNECT:3:8000 & pids+=("$!")
socat -T 20 VSOCK-LISTEN:5003,fork,max-children=16,reuseaddr TCP:127.0.0.1:5003 & pids+=("$!")
node /app/dist/recipient-acceptance-server.js & pids+=("$!")
wait -n "${pids[@]}"
exit 1
