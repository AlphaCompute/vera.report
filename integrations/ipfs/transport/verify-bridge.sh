#!/bin/bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: verify-bridge.sh <built-verification-image-id>' >&2; exit 2; }
[[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'Use the immutable local image ID' >&2; exit 2; }
[[ -S /run/vera-enclave/ipfs-vsock.sock ]] || { echo 'Approved host relay socket missing' >&2; exit 1; }
name="vera-ipfs-transport-check-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
# No ports, Docker socket, devices, host network, AWS credentials or app env.
docker create --name "$name" --network bridge --user 1001:1001 \
  --cap-drop ALL --security-opt no-new-privileges --read-only --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --mount type=bind,src=/run/vera-enclave,dst=/run/vera-enclave,readonly "$1" >/dev/null
docker inspect "$name" --format '{{json .HostConfig}}' | jq -e \
  '.NetworkMode == "bridge" and (.PortBindings == null or .PortBindings == {}) and .Privileged == false and .ReadonlyRootfs == true and (.CapDrop | index("ALL") != null)' >/dev/null
docker start -a "$name"
[[ "$(docker inspect "$name" --format '{{.State.ExitCode}}')" == 0 ]]

# Verify a failing workload also stops the TLS supervisor and relay container.
docker rm "$name" >/dev/null
docker create --name "$name" --network bridge --user 1001:1001 \
  --cap-drop ALL --security-opt no-new-privileges --read-only --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --env VERA_TRANSPORT_CHECK=child-failure \
  --mount type=bind,src=/run/vera-enclave,dst=/run/vera-enclave,readonly "$1" >/dev/null
docker start -a "$name" || true
[[ "$(docker inspect "$name" --format '{{.State.ExitCode}}')" == 42 ]]
