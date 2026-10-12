# IPFS ciphertext storage

`IPFS_STORAGE_BACKEND=local-enclave` is the only supported backend. The Pinata client is removed; unset/other values fail validation and storage calls. Historical `pinataHash` and `pinataSalt` fields do not select a provider.

Cloud provisioning and hosted environment configuration are outside this source repository. The [transport guide](transport/README.md) describes the application bridge; the local harnesses below use synthetic data.

## Durability and trust

The image builds pinned Kubo 0.43.1. `ENCLAVE_IPFS_ENABLED=1` starts Kubo on enclave loopback and the narrow HTTP/vsock bridge on port 5002; crypto RPC and confidential channels are separate interfaces. No public gateway, peers or broad Kubo administration API are exposed.

S3 is the durable ciphertext source of truth. Enclave memory and task-local Kubo storage are disposable. With the archive configured, an upload succeeds only after archive acknowledgement. Recovery re-adds archived bytes and must reproduce the requested CID before returning them. Production requires `IPFS_CIPHERTEXT_ARCHIVE_BUCKET` and an explicit `ENCLAVE_IPFS_URL`; test endpoint overrides are forbidden there. The explicit CID import profile is defined in `enclave/src/ipfs-proxy.ts` and covered by the proxy tests and archive recovery harnesses.

Legacy intake still handles plaintext and encryption on the host before storage. Co-locating Kubo in the enclave does not establish enclave-confined legacy keys or confidential reporting acceptance.

## Local enclave bridge

From the repository root, with root dependencies and Docker installed:

```sh
docker compose -f integrations/ipfs/docker-compose.yml build
node integrations/ipfs/smoke-test.cjs
node integrations/ipfs/archive-smoke-test.cjs
```

The first harness uses the real application storage/encryption service, validates authenticated reads and restart behavior, and rejects administrative routes and malformed CIDs. The archive harness uses LocalStack, destroys the first Kubo tmpfs and verifies exact-CID recovery on a fresh node, wrong-key/corruption rejection and cleanup of only its dedicated services.

A non-production API uses `ENCLAVE_IPFS_URL=http://127.0.0.1:15002` with the local bridge. Explicit local enclave mode is forbidden when `/dev/nsm` exists. Only the narrow bridge is published on host loopback; Kubo RPC and gateway ports are not published. A Docker volume is not evidence of Nitro persistence.

## API task sidecar (self-hosted backend)

The sidecar remains a supported local/legacy deployment harness. The sidecar uses the same Kubo build and proxy (`enclave/Dockerfile`, target `ipfs-sidecar`) and the same S3 archive contract.

```sh
docker build --target ipfs-sidecar -t vera-ipfs enclave
node integrations/ipfs/sidecar-smoke-test.cjs
```

The test runs two sidecars and versioned LocalStack S3, exercises add/read, fresh-node recovery, deletion of all archive versions and production test-endpoint refusal. Build and manage images yourself; no publishing workflow is included.

| Layout | API URL | Sidecar binding | Required constraint |
| --- | --- | --- | --- |
| `awsvpc` task | `http://127.0.0.1:15002` | `127.0.0.1` | Containers share task loopback, including Kubo RPC |
| EC2 `bridge` task | `http://ipfs:15002` | `0.0.0.0`, no port mappings | API links to `ipfs`; Kubo RPC remains on sidecar loopback |
| Enclave transport | `http://127.0.0.1:15002` | API-local relay to host Unix socket/vsock | `VERA_IPFS_TRANSPORT_ENABLED=1`; no competing sidecar listener |

With a sidecar, keep `VERA_IPFS_TRANSPORT_ENABLED=0` and require the `ipfs` container to be healthy before the API starts. Healthcheck: `node /app/dist/ipfs-proxy.js healthcheck`. The sidecar repository is ephemeral at `/data/ipfs`, running as UID/GID 1000.

## Proxy and deletion contract

| Route | Body | Result |
| --- | --- | --- |
| `POST /add` | Ciphertext | Pinned CIDv0 root |
| `POST /cat` | CID | Ciphertext stream |
| `POST /rm` | CID | Unpin and garbage collection; repeated removal is allowed |
| `GET /healthz` or `/health` | None | 204 if Kubo responds, otherwise 503 |

Kubo is offline, with routing/providing, bootstrap peers, swarm/gateway listeners and delegated/DNS endpoints disabled. The entrypoint rejects unresolved `auto` placeholders. Other proxy routes return 404.

Legacy consent withdrawal calls `unpinLocalCiphertext`: proxy removal, then deletion of every version and delete marker for `ciphertext/v1/<cid>`. The task role needs scoped Get/Put/DeleteObject/DeleteObjectVersion and ListBucketVersions permissions. Object Lock retention would prevent this deletion. Failure remains a failure; unpinning does not prove every external copy was destroyed.

## Hardware acceptance

Use the [hardware procedure](hardware/README.md), [HTTP probe](hardware/HTTP.md) and [container transport checks](transport/README.md) on approved isolated capacity. Each release needs its own image, archive, restart and recovery evidence; record the tested revision and results in its issue or PR.
