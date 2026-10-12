#!/bin/bash
set -euo pipefail
# Installed by an operator only on the approved host; no automatic activation.
[[ "${VERA_IPFS_TRANSPORT_ENABLED:-0}" == 1 ]] || exit 78
[[ "${VERA_IPFS_ENCLAVE_CID:-}" =~ ^[0-9]+$ ]] && (( VERA_IPFS_ENCLAVE_CID > 3 ))
[[ "${VERA_IPFS_ENCLAVE_ID:-}" =~ ^i-[a-z0-9]+-enc[a-z0-9]+$ ]]
[[ "${VERA_IPFS_ENCLAVE_PCR0:-}" =~ ^[0-9a-f]{96}$ ]]
nitro-cli describe-enclaves | jq -e --arg id "$VERA_IPFS_ENCLAVE_ID" --argjson cid "$VERA_IPFS_ENCLAVE_CID" --arg pcr "$VERA_IPFS_ENCLAVE_PCR0" \
  'any(.[]; .EnclaveID == $id and .EnclaveCID == $cid and .State == "RUNNING" and .Flags == "NONE" and .Measurements.PCR0 == $pcr)' >/dev/null
install -d -o root -g 1001 -m 0750 /run/vera-enclave
# socat removes only its own socket when the supervised process exits. A stale
# pathname fails closed: operators must investigate before removing that path.
exec socat -T 900 UNIX-LISTEN:/run/vera-enclave/ipfs-vsock.sock,fork,max-children=1,mode=0600,user=1001,group=1001 "VSOCK-CONNECT:${VERA_IPFS_ENCLAVE_CID}:5002"
