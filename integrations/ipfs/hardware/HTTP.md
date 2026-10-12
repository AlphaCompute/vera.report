# Real HTTP storage acceptance

Scope: the retained legacy HTTP intake/storage harness. Current staging defaults to confidential intake; do not reopen plaintext intake on a deployed environment for this test. Use the approved isolated settings and [hardware guide](README.md), or the separate [confidential journey](../../../qa/e2e/README.md).

`http.cjs` exercises the real anonymous intake router, durable MongoDB records,
both evidence encryption layers, the measured Nitro IPFS service, real S3 archive,
idempotency and the actual internal-secret evidence authentication middleware.
Only a clearly labeled, randomly generated test file enters a fresh isolated
database. No production reports or credentials are used.

This is **HTTP storage acceptance**, not a successful end-to-end report workflow.
No blockchain proof is issued, scoring is unavailable, and the Auth0 administrator
browser session, Next evidence proxy and audit logging are not tested. The harness
never imports `src/index.ts` or starts notification, dissemination or bot workers.
No external message or Shroud inference is sent.

## Prerequisites

- The approved dedicated VERA test EC2 host, its machine role, and an independently
  recorded enclave ID, CID and nonzero PCR0. The running enclave name must begin
  `vera-ipfs-hardware-`, with `Flags=NONE`. The harness checks the hardware instance
  identity and AWS role before starting its own loopback-only socat bridge.
- The verified source bundle: the whole `src` directory, this harness,
  `package.json`, `package-lock.json` and `tsconfig.json`. Use actual Node.js 22+
  and install the locked dependencies, including development tools and ts-node.
  `npm ci --ignore-scripts` avoids unrelated installation scripts. Native image
  dependencies must still resolve even though this acceptance uses text/csv.
- Real MongoDB 7 or 8, freshly started and accessible only through the explicit
  `mongodb://127.0.0.1:PORT` origin. A local official `mongo:7` container is suitable;
  do not point to an existing application database. The harness creates its own
  random `vera_ipfs_http_*` database and checks it is empty before writing.
- Actual `socat`, `nitro-cli` and AWS CLI; the machine role must already have its
  dedicated `vera-ipfs-hardware-test-ACCOUNT` bucket ciphertext permissions. No
  cloud endpoint overrides or local substitutes are accepted.

Run `node integrations/ipfs/hardware/http.cjs --help` for the full command. Supply
the authorized host's exact identity and measured enclave values, the verified
full source revision and new absolute output paths. The private directory must
not already exist. Both output parents must exist, and the private directory
must be outside the checkout. The harness creates it with mode 0700 and changes
to that empty directory before importing application code so dotenv cannot load
deployment `.env` files. It removes unrelated inherited service credentials and
generates its own local envelope key and internal API secret.

The harness deliberately selects `RUN_MODE=api`, which no longer requires a
messaging credentials. The API is the default runtime; retired runtime modes are rejected.

## Checks and cleanup

1. Submit the real multipart request and require HTTP 200 with `proofStatus=not_applicable`.
2. Repeat its idempotency key and payload; require the same receipt, one report
   and one evidence manifest with the real locally wrapped encryption key.
3. Close the actual persistence connections. Read through the HTTP route again,
   forcing MongoDB reconnection and key unwrapping. Missing and incorrect internal
   secrets must return 401; the correct fresh secret must return original bytes.
4. Require the real S3 archive and enclave ciphertext digests to match and differ
   from plaintext. Require no proof or webhook delivery activity.
5. Close the HTTP server, its own bridge, and application database clients. Drop
   only the unique generated database, close the verifier client, then publish
   a capability-free acceptance result. A ten-minute process deadline also
   initiates cleanup. The external mongod container and the enclave are owned
   by the operator and are not stopped or deleted by this script.

Application logs are suppressed because they can contain tracking capabilities.
The private `recovery.json` retains the generated envelope key, wrapped evidence
manifest and expected hashes with mode 0600; it must never be published. Test
ciphertext remains in the dedicated archive and enclave; deletion needs a separate
scoped cleanup. The result JSON has no tracking ID, CID, plaintext or keys.
An interrupted host can leave its uniquely named test database behind; operator
cleanup must identify that specific run and must never delete a shared database.

Local checks without cloud access:

```sh
node --check integrations/ipfs/hardware/http.cjs
node integrations/ipfs/hardware/http.cjs --help
node --test integrations/ipfs/hardware/env-validation.test.cjs
```

These local checks do not count as hardware or HTTP acceptance. Actual execution
must finish successfully before its result is recorded as passed.
