#!/usr/bin/env bash
#
# Hardware smoke test for the VERA Nitro Enclave.
#
# The unit suite in tests/ covers everything that can be checked off hardware:
# framing, crypto, RPC routing. It cannot cover the parts that only exist on a
# Nitro instance, and those are precisely where this enclave has failed before:
#
#   - the container needs /dev/vsock to bind the socat listener and /dev/nsm to
#     attest. A permissions change that looks harmless in review (running as a
#     non-root user, say) breaks both at runtime and is invisible to plan, to
#     typecheck and to jest. That is why PR #439 is on hold.
#   - --debug-mode produces all-zero PCRs, so an enclave that boots in debug
#     proves nothing about attestation. This script refuses debug builds.
#
# Run on a Nitro-capable instance (m5.xlarge or larger, EnclaveOptions enabled)
# with nitro-cli, docker and socat installed, and the allocator running.
#
#   ./smoke-test.sh            # build, boot, exercise, tear down
#   KEEP_ENCLAVE=1 ./smoke-test.sh   # leave it running for manual poking
#
# Exits non-zero on the first failure. Safe to run in a loop.

set -euo pipefail

ENCLAVE_NAME="vera-enclave"
EIF_FILE="${ENCLAVE_NAME}.eif"
ENCLAVE_CID=16
VSOCK_PORT=5000
BRIDGE_PORT="${BRIDGE_PORT:-15000}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MB="${MEMORY_MB:-512}"
KEEP_ENCLAVE="${KEEP_ENCLAVE:-0}"

cd "$(dirname "$0")"

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

BRIDGE_PID=""
ENCLAVE_ID=""

cleanup() {
  local code=$?
  [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
  if [ -n "$ENCLAVE_ID" ] && [ "$KEEP_ENCLAVE" != "1" ]; then
    printf '\n==> Terminating enclave %s\n' "$ENCLAVE_ID"
    nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" >/dev/null 2>&1 || true
  elif [ -n "$ENCLAVE_ID" ]; then
    printf '\n==> KEEP_ENCLAVE=1, leaving %s running\n' "$ENCLAVE_ID"
  fi
  exit $code
}
trap cleanup EXIT INT TERM

# ─── Preconditions ───────────────────────────────────────────────────────────
step "Preconditions"

for bin in nitro-cli docker socat jq node; do
  command -v "$bin" >/dev/null 2>&1 || fail "$bin not on PATH"
done
pass "nitro-cli, docker, socat, jq, node present"

[ -e /dev/nitro_enclaves ] || fail "/dev/nitro_enclaves missing; not a Nitro-enabled instance, or the driver is not loaded"
pass "/dev/nitro_enclaves present"

if ! systemctl is-active --quiet nitro-enclaves-allocator 2>/dev/null; then
  printf '  note: nitro-enclaves-allocator is not active; run-enclave may fail to reserve memory\n'
fi

# ─── Build ───────────────────────────────────────────────────────────────────
step "Building EIF"

docker build -q -t "$ENCLAVE_NAME" . >/dev/null || fail "docker build failed"
pass "docker image built"

nitro-cli build-enclave \
  --docker-dir . \
  --docker-uri "$ENCLAVE_NAME" \
  --output-file "$EIF_FILE" > build-output.json 2>&1 || {
    cat build-output.json
    fail "nitro-cli build-enclave failed"
  }
pass "EIF built: $EIF_FILE"

# ─── Measurements ────────────────────────────────────────────────────────────
step "PCR measurements"

MEASUREMENTS=$(nitro-cli describe-eif --eif-path "$EIF_FILE" | jq -r '.Measurements')
PCR0=$(echo "$MEASUREMENTS" | jq -r '.PCR0')
PCR1=$(echo "$MEASUREMENTS" | jq -r '.PCR1')
PCR2=$(echo "$MEASUREMENTS" | jq -r '.PCR2')

printf '  PCR0 %s\n  PCR1 %s\n  PCR2 %s\n' "$PCR0" "$PCR1" "$PCR2"

for name in PCR0 PCR1 PCR2; do
  value="${!name}"
  [ -n "$value" ] && [ "$value" != "null" ] || fail "$name absent from describe-eif"
  [ "${#value}" -eq 96 ] || fail "$name is ${#value} hex chars, expected 96 (SHA-384)"
  # An all-zero PCR is what --debug-mode yields. Such an enclave cannot attest,
  # so a KMS policy keyed on it would either never match or, worse, match a
  # value an attacker can also produce.
  [ "$value" != "$(printf '0%.0s' {1..96})" ] || fail "$name is all zeroes; this is a debug build and cannot attest"
done
pass "three well-formed, non-zero SHA-384 measurements"

printf '  reminder: PCR0 here must match enclave_pcr0_hash in terraform-prod/modules/security/kms.tf\n'
printf '  and Phase 3 moves the KMS condition to PCR3 + PCR8 per AWS guidance.\n'

# ─── Boot ────────────────────────────────────────────────────────────────────
step "Booting enclave (production mode, no --debug-mode)"

EXISTING=$(nitro-cli describe-enclaves | jq -r ".[] | select(.EnclaveCID == ${ENCLAVE_CID}) | .EnclaveID" 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
  printf '  terminating pre-existing enclave %s\n' "$EXISTING"
  nitro-cli terminate-enclave --enclave-id "$EXISTING" >/dev/null
fi

nitro-cli run-enclave \
  --eif-path "$EIF_FILE" \
  --cpu-count "$CPU_COUNT" \
  --memory "$MEMORY_MB" \
  --enclave-cid "$ENCLAVE_CID" > run-output.json 2>&1 || {
    cat run-output.json
    fail "run-enclave failed. E26/E27 usually means the allocator has too little memory reserved; E39/E36/E11 point at an expired or missing signing certificate"
  }

ENCLAVE_ID=$(jq -r '.EnclaveID' run-output.json)
[ -n "$ENCLAVE_ID" ] && [ "$ENCLAVE_ID" != "null" ] || fail "could not read EnclaveID from run-enclave output"
pass "enclave running: $ENCLAVE_ID"

STATE=$(nitro-cli describe-enclaves | jq -r ".[] | select(.EnclaveID == \"${ENCLAVE_ID}\") | .State")
[ "$STATE" = "RUNNING" ] || fail "enclave state is $STATE, expected RUNNING"
pass "state RUNNING"

# ─── Connectivity ────────────────────────────────────────────────────────────
step "vsock connectivity"

# Bridge host TCP to the enclave's vsock port. If entrypoint.sh could not bind
# VSOCK-LISTEN inside the enclave (the /dev/vsock permission failure #439 would
# introduce), every request below times out even though the enclave is RUNNING.
socat "TCP-LISTEN:${BRIDGE_PORT},reuseaddr,fork" "VSOCK-CONNECT:${ENCLAVE_CID}:${VSOCK_PORT}" &
BRIDGE_PID=$!
sleep 3

kill -0 "$BRIDGE_PID" 2>/dev/null || fail "socat bridge died immediately"
pass "bridge up on 127.0.0.1:${BRIDGE_PORT}"

HEALTH=$(node smoke-client.mjs "$BRIDGE_PORT" health) \
  || fail "health request failed. The enclave is RUNNING but not answering on vsock, which is what a /dev/vsock permission regression looks like. Check: nitro-cli console --enclave-id $ENCLAVE_ID"
pass "health answered over vsock"

echo "$HEALTH" | jq -e '.status == "healthy"' >/dev/null || fail "health did not report healthy: $HEALTH"
pass "status healthy"

for field in pcr0 pcr1 pcr2; do
  echo "$HEALTH" | jq -e "has(\"$field\")" >/dev/null || fail "health missing $field"
done
pass "health reports attestation fields"

# ─── Crypto round trip ───────────────────────────────────────────────────────
step "Crypto round trip inside the enclave"

PLAINTEXT="smoke-test-$(date +%s)-$RANDOM"

SEALED=$(node smoke-client.mjs "$BRIDGE_PORT" encrypt \
  "$(jq -nc --arg p "$PLAINTEXT" '{plaintext:$p, keyDerivationSecret:"smoke-test-secret", iterations:1000}')") \
  || fail "encrypt failed"
pass "encrypt returned"

OPENED=$(node smoke-client.mjs "$BRIDGE_PORT" decrypt \
  "$(echo "$SEALED" | jq -c '. + {keyDerivationSecret:"smoke-test-secret", iterations:1000}')") \
  || fail "decrypt failed"

[ "$(echo "$OPENED" | jq -r '.')" = "$PLAINTEXT" ] || fail "round trip mismatch: got $OPENED, expected $PLAINTEXT"
pass "decrypt returned the original plaintext"

RANDOM_HEX=$(node smoke-client.mjs "$BRIDGE_PORT" generateRandom '{"length":32}') || fail "generateRandom failed"
[ "$(echo "$RANDOM_HEX" | jq -r '.' | wc -c)" -eq 65 ] || fail "generateRandom returned the wrong length"
pass "generateRandom returned 32 bytes"

node smoke-client.mjs "$BRIDGE_PORT" definitelyNotAMethod >/dev/null 2>&1 \
  && fail "unknown method should have produced an RPC error" || true
pass "unknown method rejected"

# ─── Summary ─────────────────────────────────────────────────────────────────
step "Result"
printf '  \033[32mAll checks passed.\033[0m\n\n'
printf '  Record these measurements for the KMS key policy:\n'
printf '    PCR0 %s\n    PCR1 %s\n    PCR2 %s\n\n' "$PCR0" "$PCR1" "$PCR2"
printf '  Console output, if you want it:\n    nitro-cli console --enclave-id %s\n\n' "$ENCLAVE_ID"
