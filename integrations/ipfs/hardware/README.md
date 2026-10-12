# VERA Nitro IPFS durability probe

Current staging and production use the enclave transport; this directory remains the isolated durability/host-loss acceptance harness. Start with [storage configuration](../README.md) and [the documentation index](../../../docs/README.md). Do not use dated probe results as acceptance of the current release.

This is a prepared hardware acceptance procedure, **not a record of a successful hardware run**. It uses the repository's real `localIpfs` and `ciphertextArchive` services, an actual Nitro enclave, and real AWS S3. It creates random test-only bytes, encrypts them with a new AES-256-GCM key, and never creates application reports or loads production keys. No substitute S3 server or simulated enclave is supported.

Record hardware, fresh-enclave and host-loss recovery results against the tested revision in its issue or PR. Historical September captures have been removed from the documentation tree.

## Scope and approval boundary

Run only on an explicitly approved, dedicated **VERA test EC2 instance and VERA test instance role**. Supply that instance's ID to `--expected-instance-id`; the probe checks it against the local EC2 hardware identity before opening the bridge. Historical shared builders and the live VERA API/enclave host are not approved test capacity. Fargate cannot run Nitro enclaves. Do not grant this test archive to a shared builder merely because that builder was used for an earlier canary.

One dedicated VERA test enclave at a time is enough for enclave replacement. A second separately approved VERA test host is needed for host-loss recovery. This procedure does not create another multi-enclave product topology. Provisioning, role grants, starting/stopping EC2 instances, and running the following hardware commands require an approved test environment. The probe itself never changes EC2 state, starts/stops enclaves, changes allocators, or deletes S3 data.

The production local-IPFS guard remains unchanged. Only this isolated probe process uses `NODE_ENV=test`. It is not a production configuration recommendation.

## Prerequisites and inventory

Use the reviewed revision of this repository, Node.js 22+, npm, Docker, `nitro-cli`, `socat`, AWS CLI v2, and `jq` on the approved VERA Nitro host. Install repository dependencies, including development tools, with `npm ci --include=dev --legacy-peer-deps`. The probe needs `ts-node`, TypeScript, the root `tsconfig.json`, both real storage service files, and `src/utils/evidenceLimits.ts`; it now loads them before any hardware or storage operation. It uses the source package's explicit TypeScript configuration regardless of the calling directory. Do not source an application `.env`, copy a production key, or inherit production application credentials. Use the approved VERA test role through the usual AWS credential chain. S3 must use the real AWS endpoint; custom endpoint environment variables are rejected. The SDK ignores configured endpoint overrides for the probe.

The separately reviewed test archive must exist before the store phase. It needs private access, encryption, versioning, and TLS enforcement; the VERA test role needs only `s3:PutObject` and `s3:GetObject` on its `ciphertext/v1/*` prefix. Host-loss verification additionally needs read-only `ec2:DescribeInstances`. The operator's read-only identity must be able to inspect archive configuration if the instance role cannot. Do not broaden the role to delete objects or administer the bucket.

Run command blocks with Bash and stop on any failed command. Set these shell variables from the approved test environment, with paths outside the checkout. Do not use an existing application artifact directory. Keep the shell in the repository root.

```bash
set -euo pipefail
: "${VERA_TEST_INSTANCE_ID:?approved VERA test instance ID required}"
: "${VERA_TEST_ACCOUNT_ID:?approved account ID required}"
: "${VERA_TEST_REGION:?approved region required}"
: "${VERA_TEST_BUCKET:?provisioned VERA test archive required}"
: "${VERA_TEST_OUTPUT:?new absolute artifact directory required}"
: "${VERA_TEST_PRIVATE:?new absolute private directory outside checkout required}"
umask 077
mkdir -m 700 "$VERA_TEST_OUTPUT"
# Its parent must exist; the store command creates VERA_TEST_PRIVATE itself.
cat /sys/devices/virtual/dmi/id/board_asset_tag
aws sts get-caller-identity --region "$VERA_TEST_REGION"
nitro-cli describe-enclaves | tee "$VERA_TEST_OUTPUT/inventory-before.json"
systemctl status nitro-enclaves-allocator.service --no-pager
cat /etc/nitro_enclaves/allocator.yaml
lscpu
free -m

```

Confirm the hardware identity is exactly the approved VERA test instance. Review the inventory and allocator's existing reserved CPU/memory against all active enclaves. **Do not restart or change the allocator when any active workload uses it.** If capacity is insufficient, stop here and obtain dedicated VERA test capacity; do not evict another enclave. Choose an unused enclave CID and loopback TCP port. Save only the test enclave's inventory when publishing; unrelated enclave inventory can stay private.

Verify the archive separately from an approved operator workstation/identity that already has these read-only bucket-configuration permissions. These commands are **not** part of the narrow test instance role. Set the approved bucket name on that workstation; do not copy operator credentials onto the test host or expand its role to make this block succeed.

```bash
set -euo pipefail
: "${VERA_TEST_BUCKET:?approved provisioned VERA test archive required}"
aws s3api get-bucket-location --bucket "$VERA_TEST_BUCKET"
aws s3api get-bucket-versioning --bucket "$VERA_TEST_BUCKET"
aws s3api get-bucket-encryption --bucket "$VERA_TEST_BUCKET"
aws s3api get-public-access-block --bucket "$VERA_TEST_BUCKET"
aws s3api get-bucket-policy --bucket "$VERA_TEST_BUCKET"
```

## Build the IPFS-enabled measured image

These commands build the repository's enclave image, then add only `ENCLAVE_IPFS_ENABLED=1` in a wrapper. Nitro `run-enclave` does not support Docker environment overrides, so the flag must be present in the measured image. `ENCLAVE_LOCAL_IPFS_TEST` must remain unset. Build on matching host architecture; inspect and retain image IDs, EIF hash, and build measurements.

```bash
set -euo pipefail
# A full checkout: derive the exact revision and require it to be clean.
# A verified git-archive package: set VERA_TEST_REVISION from its recorded commit.
if [ -e .git ]; then
  VERA_TEST_REVISION=$(git rev-parse HEAD)
  test -z "$(git status --porcelain)" || exit 1
else
  : "${VERA_TEST_REVISION:?verified archive commit required}"
fi
VERA_TEST_BASE_IMAGE="vera-enclave-hardware-base:$VERA_TEST_REVISION"
VERA_TEST_IMAGE="vera-enclave-ipfs-hardware:$VERA_TEST_REVISION"
docker build -t "$VERA_TEST_BASE_IMAGE" -f enclave/Dockerfile enclave
docker build --build-arg "VERA_ENCLAVE_IMAGE=$VERA_TEST_BASE_IMAGE" \
  -t "$VERA_TEST_IMAGE" -f integrations/ipfs/hardware/Dockerfile integrations/ipfs/hardware
docker image inspect "$VERA_TEST_IMAGE" \
  --format '{{json .Config.Env}}' > "$VERA_TEST_OUTPUT/image-environment.json"
docker image inspect "$VERA_TEST_IMAGE" \
  --format '{{.Id}}' > "$VERA_TEST_OUTPUT/image-id.txt"
jq -e 'index("ENCLAVE_IPFS_ENABLED=1") != null and index("ENCLAVE_LOCAL_IPFS_TEST=1") == null' \
  "$VERA_TEST_OUTPUT/image-environment.json"
nitro-cli build-enclave --docker-uri "$VERA_TEST_IMAGE" \
  --output-file "$VERA_TEST_OUTPUT/vera-ipfs-test.eif" > "$VERA_TEST_OUTPUT/build.json"
sha256sum "$VERA_TEST_OUTPUT/vera-ipfs-test.eif" > "$VERA_TEST_OUTPUT/eif.sha256"
nitro-cli describe-eif --eif-path "$VERA_TEST_OUTPUT/vera-ipfs-test.eif" \
  > "$VERA_TEST_OUTPUT/eif-description.json"
VERA_TEST_PCR0=$(jq -er '.Measurements.PCR0' "$VERA_TEST_OUTPUT/build.json")
test "$VERA_TEST_PCR0" = "$(jq -er '.Measurements.PCR0' "$VERA_TEST_OUTPUT/eif-description.json")"
```

For a source bundle without `.git`, the operator must generate `git archive` from the exact committed SHA and compare its SHA-256 checksum locally and on the test host before extraction. Pass the full Git commit SHA as `--source-revision` below, not the archive checksum. The evidence labels archive provenance as operator-declared and records dirty-checkout state as unknown; it does not pretend Git verified the extracted files. A full checkout validates the supplied revision against Git. Missing provenance or dependencies fail before hardware or S3 work.

Record/review PCR0 from the build before running; do not accept a measurement copied only from the running enclave. These are parent-observed measurement checks, not independent verification of an NSM attestation document. The build uses the repository's pinned base images and lockfile; operating-system package repositories remain build inputs. No successful build or hardware measurement is claimed until these commands actually complete.

## Start one named test enclave

Supply reviewed CPU/memory values supported by the existing allocator and image size, and an unused CID. Allow the EIF's required memory overhead; do not assume that a previous 2 GiB allocation fits this image. The dedicated test allocator currently reserves 3072 MiB and two CPUs. This is a capacity ceiling, not evidence that the built EIF fits. Screen the measured EIF size against the four-times-size memory recommendation in the [AWS Nitro example](https://github.com/aws-samples/aws-nitro-enclaves-llm); actual startup and workload memory still need validation. Stop if the budget does not fit; do not resize a live allocator. The run deliberately omits `--debug-mode`.

```bash
set -euo pipefail
: "${VERA_TEST_CPUS:?reviewed available CPU count required}"
: "${VERA_TEST_MEMORY_MIB:?reviewed available enclave memory required}"
: "${VERA_TEST_CID:?unused enclave CID required}"
VERA_TEST_EIF_BYTES=$(stat -c %s "$VERA_TEST_OUTPUT/vera-ipfs-test.eif")
# Conservative image-size screen; it does not prove runtime headroom.
test "$((4 * VERA_TEST_EIF_BYTES))" -le "$((VERA_TEST_MEMORY_MIB * 1024 * 1024))" || exit 1
VERA_TEST_NAME="vera-ipfs-hardware-$(date -u +%Y%m%dT%H%M%SZ)"
nitro-cli describe-enclaves > "$VERA_TEST_OUTPUT/inventory-pre-run.json"
jq -e --argjson cid "$VERA_TEST_CID" \
  'all(.[]; .EnclaveCID != $cid)' "$VERA_TEST_OUTPUT/inventory-pre-run.json" || exit 1
nitro-cli run-enclave --eif-path "$VERA_TEST_OUTPUT/vera-ipfs-test.eif" \
  --cpu-count "$VERA_TEST_CPUS" --memory "$VERA_TEST_MEMORY_MIB" \
  --enclave-cid "$VERA_TEST_CID" --enclave-name "$VERA_TEST_NAME" \
  > "$VERA_TEST_OUTPUT/run.json"
VERA_TEST_ENCLAVE_ID=$(jq -er '.EnclaveID' "$VERA_TEST_OUTPUT/run.json")
```

Do not use `enclave/smoke-test.sh` for this procedure: its existing-CID cleanup and bridge behavior are unsuitable for a host that may have unrelated workloads. Never use `terminate-enclave --all`.

## Phase 1: accept ciphertext only after the S3 write

```bash
set -euo pipefail
node integrations/ipfs/hardware/probe.cjs store \
  --source-revision "$VERA_TEST_REVISION" \
  --expected-instance-id "$VERA_TEST_INSTANCE_ID" \
  --enclave-id "$VERA_TEST_ENCLAVE_ID" --enclave-cid "$VERA_TEST_CID" \
  --expected-pcr0 "$VERA_TEST_PCR0" \
  --private-dir "$VERA_TEST_PRIVATE" --evidence "$VERA_TEST_OUTPUT/store.json" \
  --bucket "$VERA_TEST_BUCKET" --region "$VERA_TEST_REGION" \
  --account-id "$VERA_TEST_ACCOUNT_ID" --size-mib 1
```

The probe creates its own loopback-only TCP-to-vsock 5002 bridge. It verifies a named, running, non-debug test enclave; checks health and rejection of administrative routes; calls the real `storeLocalCiphertext`; verifies a read and authenticated decryption; and rejects a wrong key. The adapter must receive S3's successful write acknowledgement before the manifest marks the probe accepted. Default size is 1 MiB; a separately approved run can use up to 256 MiB. The overall deadline is 20 minutes. This is not a throughput or concurrency benchmark.

`VERA_TEST_PRIVATE/state.json` contains the one-use key, IV, authentication tag, and expected digests. `ciphertext.bin` contains only encrypted test bytes. The directory is mode 0700 and files are 0600; plaintext is never written to disk. Privately back up the directory off the source host before recovery. Never publish it, send it to an artifact collector, or store it with the public evidence. The manifest permits retrying recovery; a failed store cannot be relabeled as accepted. Generated bytes are test probes, not sample application records.

## Phase 2: replace the enclave, then recover

After a successful store, stop **only the exact test enclave created above**, first checking its ID, CID, and name against the saved run. Use this same guarded cleanup for later test enclaves, with their own saved variables.

```bash
set -euo pipefail
nitro-cli describe-enclaves > "$VERA_TEST_OUTPUT/inventory-pre-stop.json"
jq -e --arg id "$VERA_TEST_ENCLAVE_ID" --arg name "$VERA_TEST_NAME" --argjson cid "$VERA_TEST_CID" \
  'any(.[]; .EnclaveID == $id and .EnclaveName == $name and .EnclaveCID == $cid and (.EnclaveName | startswith("vera-ipfs-hardware-")))' \
  "$VERA_TEST_OUTPUT/inventory-pre-stop.json" || exit 1
nitro-cli terminate-enclave --enclave-id "$VERA_TEST_ENCLAVE_ID"
```

Start a new named enclave from the same EIF using the previous inventory and run procedure, writing a new run file and retaining the old one. Its IPFS repository must be empty: no snapshot, copied blocks, or data mount. Use the new enclave ID in the recovery command; the harness refuses the original ID or changed PCR0.

```bash
set -euo pipefail
node integrations/ipfs/hardware/probe.cjs recover \
  --source-revision "$VERA_TEST_REVISION" \
  --expected-instance-id "$VERA_TEST_INSTANCE_ID" \
  --enclave-id "$VERA_TEST_ENCLAVE_ID" --enclave-cid "$VERA_TEST_CID" \
  --expected-pcr0 "$VERA_TEST_PCR0" \
  --private-dir "$VERA_TEST_PRIVATE" --evidence "$VERA_TEST_OUTPUT/recover-enclave.json" \
  --bucket "$VERA_TEST_BUCKET" --region "$VERA_TEST_REGION" \
  --account-id "$VERA_TEST_ACCOUNT_ID" --recovery-kind enclave
```

The harness first requires the CID to be absent from a healthy new enclave. It then calls the real `readLocalCiphertext`, which retrieves S3 ciphertext, reconstructs the CID by adding it to Kubo, and rejects a mismatch. The harness verifies the digest and AES-GCM plaintext result and checks that Kubo now serves the recovered CID. Merely reading the source enclave is not successful recovery evidence.

For **host-loss recovery**, use a second explicitly approved VERA test EC2 host, the same EIF/PCR0, and the privately transferred state. Change `VERA_TEST_INSTANCE_ID` to that approved host and run a fresh empty enclave. The source test host must already be stopped or terminated through the separately authorized test operation. Run the same command with a fresh evidence file and `--recovery-kind host`. The harness requires a different instance and independently reads the source instance's stopped/terminated status. It does not stop that instance. If no second approved VERA host or source-stop approval exists, report host recovery as **not executed**; same-host restart does not satisfy it.

## Evidence, cleanup, and remaining acceptance

Publish only reviewed `store.json`, `recover-enclave.json`, `recover-host.json` when actually produced, the source revision, image ID, EIF hash, and build measurements. The probe evidence contains no plaintext, decryption key, IV, tag, or plaintext digest. Account resource IDs and the test bucket/CID remain infrastructure metadata; review their audience before publication. Source revision and dirty-checkout state are recorded. Failed operations produce no success evidence file; safe validation messages are shown, external error details are withheld.

The process terminates only its own socat process group on normal exit, error, or interruption. Following SIGKILL/host crash, inspect the exact residual process before manual cleanup; do not kill all socat processes. Use the guarded exact-ID enclave cleanup above, preserve recovery evidence and private key material until acceptance is complete, and have the test-archive owner perform separately approved object/version retention cleanup. Do not delete an entire bucket or reset allocator configuration as part of this probe.

This validates the ciphertext archive/rehydration path only when executed successfully. It does not establish cryptographic attestation verification, encryption inside the enclave (this probe encrypts on the test parent), full application recovery, historical CID migration, production networking, archive-corruption handling, load acceptance, or production activation. Current Terraform supplies the restricted host-to-vsock transport; an isolated hardware run must still verify its own application-reachable path. Host loopback alone is not container loopback. The production guard and application behavior are untouched.

## Application service acceptance

Use `--storage-layer application` with the same `store` and `recover` commands to exercise the real `EvidenceStorageService.uploadEncryptedFile`, `readCiphertext`, and `retrieveVaultCiphertext` functions. All dedicated-host, measured-enclave, real-AWS, new-enclave and host-loss checks above still apply. The default remains the adapter probe. DevOps owns the hardware/transport/archive run; the application owner reviews the service behavior and remaining route/database integration before production activation.

Use a **new private directory and new evidence filenames** (for example, `application-private`, `application-store.json`, and `application-recover-host.json`); do not reuse adapter state. Application state has version 2 and a storage-layer marker; the command rejects mixing state types. Its mode-0600 `state.json` holds only a new test key, application-generated IV/tag/salt, CID, expected digests and test context. No plaintext is written, no application record is created, and no production key or Pinata credential is accepted. Privately retain this state before losing the source host, just like adapter state. The application mode does not need or write `ciphertext.bin`.

The application mode additionally needs these tracked sources beyond the adapter-only bundle:

- `integrations/ipfs/hardware/application.cjs`
- `src/services/evidenceStorage.ts`
- `src/services/evidenceStorageCipher.ts`
- `src/services/evidenceStorageError.ts`
- `src/utils/logger.ts`

Install dependencies before running; the entry point loads the real service before any hardware/storage operation. Keep `PINATA_JWT` unset and do not load `.env`. The process explicitly selects the local backend before importing the application singleton; the service has no other backend. The hardware image and transport are unchanged.

The application encrypts random test-only bytes with its real scrypt/AES-256-GCM implementation. The upload must finish its S3 write before state is accepted. The first recovery call is the real vault decrypt method itself, so a healthy empty enclave must fetch archived ciphertext and rehydrate Kubo through that path. Both phases compare the actual S3 object with the application's returned ciphertext, verify authenticated plaintext recovery, require authentication errors for a wrong key and altered tag, confirm the service exposes no unencrypted JSON upload, and check that the unchanged production activation guard still rejects a read. No substitute service, intercepted network response, or fabricated application record is used.

This is **application storage-service acceptance**, not complete end-to-end application acceptance. It does not run HTTP handlers, persist database envelopes, exercise wallets, or move encryption into the enclave. The unused `retrieveEncryptedFile` encrypted-CID method, whose CID envelope never matched what `uploadEncryptedFile` returned, has been removed; `retrieveVaultCiphertext` takes the original CID directly.
