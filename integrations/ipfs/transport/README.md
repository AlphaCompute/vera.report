# VERA container-to-enclave IPFS transport

This optional transport preserves the API's ECS `bridge` network and existing
loopback-only IPFS adapter:

```
API container 127.0.0.1:15002
  -> read-only-mounted /run/vera-enclave/ipfs-vsock.sock
  -> supervised host Unix-to-vsock relay
  -> explicitly verified enclave CID:5002
```

The backend Docker entrypoint starts the relay only when
`VERA_IPFS_TRANSPORT_ENABLED=1` and `RUN_MODE=api`. It defaults to disabled.
Startup requires the enclave's real `/health` response before starting the TLS
supervisor and workload. Transport bytes stream with backpressure, one active
connection, and a 900-second absolute connection deadline. One additional downstream
may wait paused for the active pair to close; queue time counts toward the same
absolute deadline. Errors close both
ends. SIGTERM/SIGINT close the listener and terminate the workload through the
existing supervisor. The bridge never interprets or logs application bodies.

No application adapter, crypto logic, production Terraform, provider selection,
public listener, published container port or IAM permission changes here.
Production accepts `IPFS_STORAGE_BACKEND=local-enclave` only with the S3
ciphertext archive and an explicit `ENCLAVE_IPFS_URL`. Current staging and production both configure the enclave transport in `terraform-prod/` (see Production below). A sidecar deployment instead keeps `VERA_IPFS_TRANSPORT_ENABLED=0`. Do not bypass that guard by changing `NODE_ENV`. The existing crypto socket/port 5000 is separate;
this transport opens only IPFS port 5002. No Kubo administrative API, gateway,
Docker socket, Nitro device or privileged container is exposed.

## Local checks

From the repository root, with Node.js 22 or later:

```sh
node --test integrations/ipfs/transport/relay.test.cjs
bash -n integrations/ipfs/transport/host-relay.sh
bash -n integrations/ipfs/transport/verify-bridge.sh
```

The socket tests use real Unix and TCP sockets and random test-only bytes. They
exercise an 8 MiB backpressured transfer, half-close handling, reset propagation,
connection limits, deadline enforcement and startup validation. They do not
claim hardware, application-storage or recovery acceptance.

## Production

The current staging and production API hosts use the generated Terraform relay, not the manual test-host installation below. With `ipfs_enclave_transport = true`,
`terraform-prod/modules/compute/templates/api-user-data.sh` installs a
relay (`vera-ipfs-transport.service`) that selects the running non-debug enclave
on CID 16 against the pinned PCR0. Each accepted connection rechecks its exact
EnclaveID, PCR0 and flags before opening vsock; replacing an enclave requires
restarting the relay. Pinned setup is an enabled `vera-enclave-setup.service`
oneshot on every host boot, with failed setup retried. It starts the relay only
after verifying the enclave and crypto bridge, then requires IPFS readiness.
The unpinned development boot remains a first-launch path.

Offline regression tests execute the generated guards and setup against mocked
Nitro/systemd commands, including host-reboot replay and replacement rejection.
Real host reboot, enclave replacement, resource exhaustion and S3 refill still
require deployed acceptance. These host lifecycle checks do not replace client
attestation or protect against a malicious host changing the relay itself.

## Install only on the approved dedicated VERA test host

Prerequisites: reviewed checkout, Linux systemd, `nitro-cli`, `jq`, `socat`,
Docker, and a running measured IPFS-enabled non-debug VERA test enclave from the
[hardware procedure](../hardware/README.md). That procedure remains responsible
for actual adapter/S3 acknowledgement and recovery acceptance. Do not install on
the production API host as part of this verification.

Use the hardware procedure's actual `VERA_TEST_ENCLAVE_ID`, `VERA_TEST_CID` and
independently retained build PCR0. A CID by itself is not an identity check.
Have the authorized operator install the reviewed files:

```sh
sudo install -d -m 0755 /usr/local/libexec
sudo install -m 0755 integrations/ipfs/transport/host-relay.sh /usr/local/libexec/vera-ipfs-host-relay
sudo install -m 0644 integrations/ipfs/transport/vera-ipfs-transport.service /etc/systemd/system/vera-ipfs-transport.service
```

Create `/etc/vera-ipfs-transport.env`, owned by root and mode `0600`, containing
these nonsecret fields with the verified values:

```
VERA_IPFS_TRANSPORT_ENABLED=1
VERA_IPFS_ENCLAVE_ID=<actual approved test enclave ID>
VERA_IPFS_ENCLAVE_CID=<actual approved test CID>
VERA_IPFS_ENCLAVE_PCR0=<96-character lowercase measured PCR0>
```

These are placeholders, not an executable configuration. The unit defaults to
disabled when no activation is supplied. The launcher checks the exact ID, CID,
PCR0, `RUNNING` state and `NONE` flags before creating its socket. This is a
launch-time operator check, not cryptographic peer attestation on each request.
Restarting an enclave requires a fresh verified ID/configuration and relay
restart. Do not replace a running enclave at the same CID behind a live relay.

```sh
sudo systemctl daemon-reload
sudo systemctl start vera-ipfs-transport.service
sudo systemctl is-active vera-ipfs-transport.service
sudo stat -c '%U %G %a %n' /run/vera-enclave /run/vera-enclave/ipfs-vsock.sock
```

Expected directory ownership is root/group 1001, mode `0750`; the socket is
UID/GID 1001, mode `0600`. The unit is not automatically enabled at boot. It
supervises only its own relay process group. It never starts/stops an enclave or
changes the allocator. A stale socket fails closed; inspect the owning process
before removing that exact pathname. Never delete the directory or crypto socket.

## Real bridge-container verification

On that same approved test host, from the reviewed checkout:

```sh
docker build --target base -t vera-ipfs-transport-base .
docker build -f integrations/ipfs/transport/Dockerfile -t vera-ipfs-transport-check .
VERA_TRANSPORT_IMAGE_ID=$(docker image inspect vera-ipfs-transport-check --format '{{.Id}}')
sudo bash integrations/ipfs/transport/verify-bridge.sh "$VERA_TRANSPORT_IMAGE_ID"
```

The harness uses the API image's actual base, UID, relay and TLS supervisor,
without launching application workers. It supplies no AWS/app credentials. It
checks bridge networking, no published ports, non-root UID, read-only socket
mount and root filesystem, no added capabilities, real enclave health,
administrative-route denial, malformed-CID rejection, a 1 MiB encrypted
add/read/authenticated-decryption roundtrip, and absence of relay access on the
container's non-loopback address or Kubo ports. It checks coordinated successful
shutdown and propagation of a failing workload's exit status. Test ciphertext
remains in the disposable enclave; no production records or keys are used.
Record commit/image IDs, host/enclave identities, PCRs, command status and the
sanitized acceptance JSON. This is transport acceptance, not durable archive,
host-loss recovery, migration, concurrency-capacity or production approval.

After verification:

```sh
sudo systemctl stop vera-ipfs-transport.service
```

Stopping closes only this Unix/vsock relay. The container harness removes only
its own named containers. Retain hardware recovery evidence and follow the
hardware runbook's separately scoped cleanup for its enclave/storage.

## Release and replacement checklist

For each transport/image change, after hardware and application acceptance, review a pinned IPFS-enabled EIF
and its measurements/memory, supervised host relay provisioning, the optional
backend transport flag, real archive bucket/task-role scope, existing-CID
migration and rollback. The existing API read-only `/run/vera-enclave` mount is
sufficient; keep ECS bridge mode and existing API port mappings. Do not attach
an extra bridge-mode sidecar expecting to share API loopback. Keep crypto
activation and its existing TCP-versus-Unix client mismatch separate.

### Combined confidential boot

With `confidential_cases_enabled`, the API launch template gzip-compresses its
single rendered shell script before base64 encoding it; with the flag off the
payload stays plain base64 and byte-identical. Linux cloud-init recognizes both
formats; a Terraform precondition rejects payloads over EC2's 16 KiB raw limit.
The `enclave_boot_config` output preserves the readable script and reports the
actual encoded payload and its byte count separately.

When confidential cases are enabled, each persistent enclave boot queues
`vera-confidential-gate.service` once the enclave is verified. The gate closes
the confidential bridges, re-fetches/verifies the pinned release manifest and
legal identity policy, rechecks the running enclave and only then recreates
volatile readiness and starts the bridges. A verification failure retries the
gate alone: the enclave, crypto bridge and IPFS transport keep running.
Previously enabled bridge units cannot start without that boot's readiness
marker; stopping or failing the gate, or the enclave setup it is bound to,
removes it and stops the bridges. This lifecycle validation complements the
enclave's own cryptographic checks and still requires a real host reboot
acceptance test.

References: [EC2 user-data limit](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
and [cloud-init user-data formats](https://cloudinit.readthedocs.io/topics/format.html).
