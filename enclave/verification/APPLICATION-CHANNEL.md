# Application-channel attestation binding

This attestation/session implementation is mounted by `enclave/src/confidential-server.ts` with owner and legal dispatchers. The source distribution leaves that measured service disabled until explicitly configured. Synthetic tests exercise authorization and encrypted round trips, but do not establish acceptance of a deployed Nitro image or remove legacy custody gaps. See the [deployment runbook](../../docs/security/README.md).

## Operator hardware quote check

An authenticated profile and current isolated test environment are required; verify them for this run. Earlier recorded STS failures are historical;
historical recipient-test resources are not evidence of available capacity.

After compiling the enclave, use the operator verifier with a canonical release
manifest whose source/build provenance and digest have been independently reviewed:

```sh
node scripts/security/verify-confidential-hardware.cjs prepare REVIEWED_MANIFEST_PATH REVIEWED_MANIFEST_SHA256 NEW_CHALLENGE_PATH
node scripts/security/verify-confidential-hardware.cjs verify NEW_CHALLENGE_PATH RESPONSE_PATH
```

Preparation creates an exclusive local file containing a fresh nonce, the pinned
manifest and a 60-second deadline. Send only the returned nonce to the isolated
application-channel identity operation; capture its exact `{nonce, publicKey,
document}` response (key/document are canonical base64). This test transport must
still be provisioned inside the measured image; the verifier does not install or
launch it, and legacy attestation endpoints are not interchangeable with it.
Verification consumes the challenge even on failure and uses the fixed AWS root,
COSE signature, nonce, timestamp, non-debug PCR0/1/2 and channel-key binding.
Do not remove the `.consumed` marker to reuse a challenge. Files and the operator
clock are trusted local inputs; this is not a distributed freshness witness.

A successful receipt records manifest, source, EIF, quote and channel-key digests.
It proves acceptance of that hardware quote under the supplied reviewed policy;
it does not itself verify build provenance, owner grants, restart safety, private
storage custody or the deployed application. There is no synthetic-root bypass,
network call, case secret or production mutation in this utility. CI tests cover
challenge expiry/consumption and rejection, not a positive hardware quote.

`src/application-channel-identity.ts` generates an independent ephemeral OpenPGP
keypair for each challenge. Its only public input is a 32-byte browser nonce
encoded as lowercase hexadecimal. The native helper path is fixed; no environment
setting or request field selects the key, digest, context or helper. The measured
entrypoint must initialize the enclave's NSM-backed entropy before generating keys.

The helper receives only the nonce and SHA-256 of the exact binary public-key
packet bytes. Its NSM request has:

- `nonce`: the browser's original 32 bytes.
- `user_data`: ASCII `VERA-CONFIDENTIAL-CHANNEL-v1` followed by the 32 digest bytes.
- `public_key`: absent/null. OpenPGP packets are not a DER public key; the key is
  authenticated through the digest in `user_data` instead.

The domain differs from the old certificate-bound raw TLS channel. Do not relax
the old verifier to accept the new context. The browser verifier checks
the AWS root/certificate chain and original COSE signature, fresh nonce/time,
non-debug exact approved measurements, this exact context and the SHA-256 of the
received public-key bytes before encrypting any private material. A response from
the helper alone does not perform those browser checks. The NSM field semantics
are described in [AWS's attestation specification](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).

The helper is internal to the measured application. **Never expose an endpoint
that attests a caller-supplied digest**: that would let a host get evidence bound
to a key it controls. The TypeScript wrapper generates the key itself and returns
an internal credential object. Its private key is an ECMAScript private field;
JSON serialization contains only public evidence. Only enclave-local channel code
may call `getPrivateKey()`. Neither key nor decrypted outputs may be logged,
persisted or returned to the parent host.

The mounted channel (`enclave/src/application-channel-sessions.ts`) adds what a
per-call key alone does not: bounded session admission with anonymous and
authenticated idle expiry, per-session request-ID/digest replay rejection,
encrypted request/reply binding, participant authentication with single-use
in-session challenges, and fresh case authorization in the dispatcher. The host
relay (`src/utils/confidentialAdmission.ts`) adds per-client fairness in front
of it. Do not use this as a general decrypt API. Drop session key references on completion/expiry; managed-runtime
memory erasure remains best effort.

The Rust helper is included in the runtime image and its parser tests run with
the existing Docker Cargo test step. Compiled TypeScript tests use a fake native
response, real OpenPGP keys and encryption to verify the exact binding, fresh keys,
serialization behavior, input bounds and fail-closed errors. They do not claim
to validate a real AWS quote. Encrypted-session integration and genuine Nitro
hardware acceptance remain required before this path may carry
confidential traffic. The synthetic browser verification described below does not
substitute for those checks.

`src/confidential/attestationCbor.ts` supplies the portable parsing layer. It accepts
only Nitro's needed CBOR types, bounds input
to 16 KiB, depth to 16 and decoded items to 2,048, and rejects duplicate decoded
map keys, trailing data, invalid UTF-8 and unsafe integers. Indefinite containers
are supported; string chunks must be definite and of the same type. Protected
header/payload byte strings retain their original contents for signature checking.
An optional COSE tag 18 is allowed only around the outer array. Map keys retain
their string/integer types. Parsing is **not verification** and returns no trusted
enclave identity. Rules follow [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).
Unit tests include malformed encodings and semantic duplicate keys; the Chromium
harness checks the actual browser build as well.

`src/confidential/attestationEvidence.ts` adds structural/policy validation and
prepares the exact COSE `Sig_structure` bytes. It requires independently pinned,
nonzero PCR0/1/2 (plus any additional expected PCRs), a fresh caller challenge,
a trusted caller clock, the application protocol domain and the channel-key hash.
It rejects unsupported headers, unknown payload fields and out-of-bound certificate
bundles before expensive PKI operations. Input and policy bytes are copied before
asynchronous hashing; the returned key is the checked snapshot.

Its result is explicitly **unverified**. Certificate bytes and COSE signatures
are not trusted by this step, and it must never enable encryption or case access
on its own. Tests use a real P-384 signature to independently check the constructed
signature input, including nonminimal header encodings and indefinite payloads;
synthetic certificate placeholders intentionally remain untrusted.

## Certificate and signature verification

`src/confidential/attestation.ts` is the public verification entry point. It first
prepares the evidence and then verifies the certificate chain and ES384 signature.
Its AWS commercial Nitro G1 root and SHA-256 fingerprint are fixed in code and
checked against each other; neither the quote, an environment variable nor a
served release manifest may override them. Only after all checks pass does it
return the checked public-key snapshot and verification time. There is no fallback
identity on errors and no network lookup of certificate-supplied URLs.

The internal `attestationPki.ts` uses pinned PKIjs/ASN1js and browser WebCrypto.
It validates certificate times, root-first bundle order, the complete chain,
intermediate CA constraints, the leaf's P-384 key and signing usage, and the COSE
ES384 signature over original bytes. Certificate DER is bounded and must consume
the whole input. Duplicate extensions are rejected. This deliberately narrow
profile accepts only BasicConstraints and KeyUsage as critical extensions; any
new critical extension needs an explicit implementation/profile review. Missing
revocation values are allowed as directed by the AWS Nitro attestation procedure;
this is not a general-purpose TLS certificate verifier.

The internal PKI primitive takes an explicit root for independent synthetic tests.
Production callers must use `verifyApplicationAttestation`, which has no root
parameter, test flag or bypass. Tests use independently issued OpenSSL certificates
and Node signatures, validate intermediate chains and reject untrusted roots,
forged signatures, expired certificates and invalid usage/extensions. The
Chromium harness exercises real browser WebCrypto and confirms the production
entry point rejects that otherwise valid synthetic root.

Expected PCRs come from the release manifest compiled into the browser build,
and a nonce must be freshly generated and consumed once. Successful attestation
alone grants no case authority. Hardware acceptance with actual NSM documents
was completed under #562 (closed 2026-09-30).

## Per-case release binding

For an existing case, `verifyApprovedCaseChannel` joins owner authorization and
attestation. It accepts no caller-selected PCR map. `releaseManifest.ts` parses
the exact canonical backend manifest bytes, hashes them, verifies the owner's
release and checkpoint signatures against pinned case genesis, and requires the
approval to be active in the independently authenticated current checkpoint.
Only that manifest's PCR0/1/2 become attestation pins. A changed artifact, source,
configuration or measurement needs a different owner approval. Approving a
manifest never overrides the AWS root or makes a synthetic issuer trusted.

The draft manifest binds source repository/commit, EIF and OCI image digests,
configuration and build-provenance digests, protocol/data versions and PCR0/1/2.
Canonical field order is defined by `canonicalReleaseManifest`; incoming bytes
must already be canonical, so duplicate fields and silent JSON normalization
cannot change the approved artifact. No case identifier belongs in this public
manifest. The digest itself is absent from the manifest to avoid self-reference.

The EIF workflow checks both production and isolated acceptance artifacts before
upload: streamed EIF SHA-256, nonzero SHA-384 PCR0/1/2, describe-eif CRC and PCR
agreement, and exact Docker image ID and entrypoint. Offline tests execute the
workflow's validation code with corrupted synthetic artifacts. This detects
inconsistent build evidence; it is not an independent build, signed provenance
or evidence of a live hardware quote. The production image still contains legacy
services and is not certified as a confidential-case release by this check.

For non-PR runs, a separate `provenance` job now uses the commit-pinned official
`actions/attest` action to sign the EIF, checksum file, measurements, describe-eif
output and tool-version record. The build job retains read-only permissions;
the signing job receives OIDC/attestation permissions and executes no downloaded
artifact. The signed bundle is retained as a separate workflow artifact.
The manifest and its checksum receive a separate signed bundle, retained alongside
the EIF bundle in workflow artifacts, S3 and release assets. Nonpublishing manual
validation verifies all seven subjects with their respective explicit bundles.
Publication requires this job and repeats `gh attestation verify --bundle` for every subject
before obtaining AWS credentials, enforcing repository, signer workflow, source
and signer commit, source ref, and GitHub-hosted runners. Missing or invalid
attestations fail the gate. See the official
[artifact attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

This workflow change has only offline gate tests so far; no hosted attestation
has been generated or accepted for this branch. AlphaCompute/vera remains private,
and the organization API reports an Enterprise plan. Private attestations require
repository access to verify; public verification still needs the source/publication
work. CI provenance establishes the workflow's artifact claim, not independent
reproducibility, safe code, a running enclave, or owner consent. Browser manifest
provenance verification and permanent release-bundle distribution remain pending.

This establishes consent-to-measurement binding, **not source/build provenance**.
Publishing a manifest that claims a source commit does not prove that commit built
the image. The build must produce authenticated provenance and reproducible input
records, and the client must validate that chain before requesting owner approval.
Provenance must bind source/artifacts without including a digest of this manifest
that already contains its own provenance digest. The measured workload must pin
and validate all external configuration/model/service bytes represented by its
configuration digest. An opaque host-provided configuration hash is insufficient.

The checkpoint digest still requires a genuine freshness protocol; supplying an
old signed checkpoint and its matching digest cannot prove current authorization.
Release withdrawal, fresh-state recovery, manifest publication/provenance validation
and the contextual owner approval UI remain unfinished. Cosmetic frontend releases
remain separate from the backend manifest under the accepted website-operator trust.

## Encrypted operations and replies

`src/confidential/channelMessage.ts` implements bounded OpenPGP message envelopes.
The browser's `createApprovedChannelRequest` first performs the complete owner
approval and AWS attestation checks. It then generates an ephemeral reply key,
signs and encrypts the request to the verified enclave key. Challenge, random
request ID, exact server-key digest, reply public key and private body all sit
inside the encrypted signed message. Only ciphertext leaves the browser.

The enclave decrypts only to inspect the embedded reply key, then verifies the
original message signature against that key before returning a request body to
its caller. This proves possession of an ephemeral key, **not legal membership
or case authority**. No identity, case key or authorization may be inferred from
successfully opening a channel request. The measured dispatcher still must check
the operation's authenticated principal, owner grants, current state and release.

Replies are encrypted to the request's verified reply key and signed by the
enclave channel key. They repeat the challenge, request ID and server-key digest,
and include a digest of the exact request ciphertext. The browser rejects a reply
from another request, key or challenge. Its pending reply state is consumed once,
including on failure, and can be explicitly closed; retries require a new session.
JSON serialization of pending state includes ciphertext only, not private keys.

The wire primitives remain available internally for measured service code and
synthetic interoperability tests; they do not perform attestation on their own.
Product request creation must use `createApprovedChannelRequest`, which has no
skip-verification option. The browser harness explicitly exercises the internal
primitive against a local Node process using synthetic data; that is not a claim
that the process is a TEE. The production entry point is separately tested to
reject otherwise valid owner consent paired with an untrusted attestation root.

Each body is limited to 256 KiB, decompressed envelopes to 384 KiB and armored
ciphertext to 768 KiB. Evidence upload needs a reviewed chunk protocol before this
can support the existing file-size limits. Strings and cryptographic-library
copies cannot be guaranteed erased even though owned byte buffers are cleared.
The session layer below enforces bounded pending sessions, expiry and atomic
single-use server consumption. Enclave-local case authorization remains required
inside its measured dispatcher.
No network listener or general decrypt endpoint is mounted by this module.

## Enclave session lifecycle

`src/application-channel-sessions.ts` supplies the session service composed by `src/confidential-server.ts` (paths relative to `enclave/`).
The production constructor fixes the native identity factory and a process-local
monotonic clock. It admits at most 16 sessions and starts a 60-second deadline
before key generation. Reservations count while generation, decryption, dispatch
or response encryption is in flight. Expiry cannot free an unfinished operation's
slot and thereby bypass the work limit. Ready expired sessions are removed by a
timer as well as on subsequent operations.

Executing a request synchronously consumes its ready session before any await.
Concurrent calls, malformed ciphertext and subsequent replay cannot dispatch it
again. Expiry and shutdown signal cancellation, suppress late replies and dispose
of session identity references. Owned request/response buffers are cleared. An
operation that already committed cannot be undone by cancellation; application
handlers still need transaction and idempotency semantics for lost responses.

Dispatch is a required measured enclave-local callback; there is no default
echo or generic decrypt handler. It receives private bytes plus the authenticated
channel binding and a cancellation signal. It MUST separately authenticate the
principal and enforce case/release/current-state authorization before processing.
It cannot use the ephemeral reply key as legal identity. A stalled handler retains
its slot until it settles, preserving the bound at the cost of availability.

The internal composition helper accepts synthetic identities/clocks solely for
tests; the production constructor has no request-selected factory, clock or bypass.
Node tests cover admission races, expiry, concurrent execution, shutdown and failed
generation/dispatch. Chromium exercises the compiled session service with synthetic
keys and verifies server and client replay rejection. No real listener, production
dispatcher, Nitro execution or restart/persistence acceptance is established yet.

```sh
npm --prefix enclave run build
node --test tests/confidential-runtime/attestation-pki.test.cjs
node scripts/security/verify-confidential-browser.cjs
```

```sh
npm --prefix enclave run build
node --test tests/confidential-runtime/application-channel-identity.test.cjs
cargo test --locked --manifest-path enclave/nsm/Cargo.toml --bin vera-nsm-application-channel
```
