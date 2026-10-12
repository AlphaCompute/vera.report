# Confidential case protocol

This source distribution ships a disabled, unconfigured enclave template. See [configuration and trust boundaries](../../../docs/security/README.md). Private conversations are retired: message parsers/storage remain compatibility code, but the mounted owner/legal channels do not expose send/read-message operations.

This directory implements the shared protocol for the
[confidential-case architecture](../../../docs/security/README.md#trust-boundaries).
Owner and legal session handlers and admin listing APIs are mounted behind the
confidential-mode gate. Source integration and synthetic tests do not establish
real Nitro hardware, deployment acceptance, or the confidentiality of the live
application. The protocol and production configuration require independent review.

The enclave owns this shared protocol source. Its standard TypeScript build emits
these modules under `dist/confidential/`; the existing Docker build copies those
compiled files and the pinned OpenPGP runtime into the image. Browser consumers
import the same portable source, using OpenPGP's browser export. There is no
separate host-authorized or browser-only copy of the policy. Inclusion in an image
does not mean an endpoint invokes it, and is not proof of hardware acceptance.

Low-level key/message operations use `pgp.ts`, the protocol's single crypto
entry point. Root and enclave dependency installations are separate runtimes;
their live OpenPGP packet/key objects must not be mixed. Across runtime or bundle
boundaries serialize keys/messages and parse them with the receiving runtime.
The interoperability test exercises independent signing and decryption through
that wire boundary. Keep the root and enclave OpenPGP versions pinned together;
the browser/enclave harness checks this explicitly.

The EIF workflow requires the focused protocol suite and browser/compiled-runtime
interoperability job before image measurement and publication. The workflow's
offline regression test checks that dependency chain. This gate supplements the
existing artifact and attestation checks; it does not prove production authorization
or real-hardware confidentiality.

## Implemented boundary

`authorization.ts` provides strict owner-signed records for:

- Public listing: an opaque case identifier and an explicitly approved summary.
- Legal access grant: exact case, organization, recipient key bundle, scopes,
  key epoch, revision, validity interval, and whether future objects are included.
- Separate approval of an exact backend release-manifest digest.
- Owner-signed checkpoint listing the currently active grant and release-approval
  payload digests, revision and key epoch.

Unknown fields, protocol versions, malformed identifiers, duplicate/unknown
scopes, invalid validity intervals and invalid signatures fail closed. The admin
listing projection contains only `caseId`, `summary`, and optional `publishedAt`
and `hasAttachments` fields. The firm directory additionally carries the owner public
key and signed listing wire. Neither projection adds a revision field or
serializes the legacy report model. The signed listing does not detect identifying prose.
The submission UI requires owner review and shows a confidentiality warning.

Policy `revision` and content `objectRevision` are distinct counters. A grant's
`objectRevisionLimit: null` includes future content; a positive limit restricts
access to the approved snapshot. Adding content under a future-inclusive grant
does not require re-signing that grant; the new manifest and checkpoint still
require owner signatures. Content revisions and epochs
must come from authenticated object metadata, never an untrusted request claim.

`caseObject.ts` encrypts a bounded binary object under a fresh random AES-256
session key using the existing pinned OpenPGP.js dependency. The owner signs the
private content. Its context (case, object, scope, revision, epoch) is inside the
encrypted signed payload, and is repeated in the encrypted signed key envelope.
The envelope also binds the exact ciphertext SHA-256 digest.

The owner receives a recipient-encrypted envelope for recovery. Granting to a
legal organization encrypts only the content-key envelope to that recipient;
the evidence ciphertext is unchanged. The granted envelope additionally binds
the signed grant payload digest. Public envelope packet headers use wildcard
recipient key IDs. No application/KMS/platform recovery envelope is created.
Keys and plaintext are never logged or returned to a server by these modules.
There is no credential fallback or admin override.

`caseRanges.ts` collects up to 16 MiB of ciphertext in sequential 128 KiB ranges.
It snapshots an authenticated descriptor, requires identical object metadata and
recipient envelopes across ranges, rejects noncanonical or incorrectly sized
chunks, and checks the complete ciphertext digest. Cancellation or failure returns
no partial object. The caller supplies a fresh attested, owner-approved authorized
read for each range; the helper itself does not establish metadata freshness or
channel trust. Its result remains encrypted and must pass `openGrantedCaseObject`
with current authorization before plaintext is shown. The mounted owner and legal
channels and browser clients use these authenticated reads; persistence stores
ciphertext and untrusted metadata that the enclave verifies.

State history has one link: each owner-signed checkpoint names its predecessor in
`previousDigest` (`null` only at genesis). The owner's signature over the
checkpoint is its consent to exactly that predecessor -> successor step. The
mounted commit predicate is `cases/service.ts` `commitTransition`: the new
checkpoint must name the stored tip, raise the revision, keep or raise the key
epoch, reference only verified grant/release/listing/manifest statements, and the
store compare-and-sets the same tip digest, so two successors of one checkpoint
cannot both commit. Devices verify chains with `advanceOwnerCheckpoint`; a skipped
or spliced checkpoint fails. The draft separately signed `transition` statement
(and its `caseState.ts` verifier) carried nothing beyond `previousDigest` and was
retired; `parseStatement` rejects that kind. See the
[security model](../../../docs/security/README.md#trust-boundaries).

This is a mutation predicate, not a freshness witness. The owner decision of
2026-09-27 drops the independent recorder: freshness comes from participant
checkpoint pins (`CONFIDENTIAL-FRESHNESS-DECISION.md`).

The canonical signature payload is UTF-8 JSON of
`{protocol, ownerFingerprint, statement}` in that field order. Each statement is
strictly reconstructed in the fixed field order in `parseStatement`; array order
is preserved. Signatures are detached binary-message OpenPGP signatures. Payload
digests exclude randomized signature bytes. No user-generated JSON is signed
without schema reconstruction. This is a versioned application record format,
not a new encryption or key-exchange primitive.

`recipientKeyId` is SHA-256 of the exact OpenPGP public-key packet bytes returned
by `PublicKey.write()`, including subkeys/certifications. It is intentionally
distinct from the owner OpenPGP fingerprint. Changed recipient bundles require
new owner approval. Generate independent owner keys for each case; reusing owner
keys could link otherwise separate listings.

`recovery.ts` generates a separate pseudonymous owner keypair and a random
256-bit recovery secret per case; the case identifier is derived from the secret
(HKDF, its own label). The participant-only recovery code is just that secret
plus a checksum (`recoveryCode.ts`: 56 Crockford base32 characters in 14 groups).
The AES-256-GCM recovery package key is derived from the secret under a
different label. The package holds the owner key, its fingerprint and a verified
saved checkpoint; the case identifier and format are authenticated as additional
data, so the owner fingerprint (and with it the genesis key) is pinned by the
secret. Older `VERA-OWNER-1.` codes, which carry the locator and fingerprint in
the code, still restore and refresh in their own v1 package format. The code is
not a user password, an email reset, or a server bearer token.

Only the encrypted package may be uploaded. `recoveryCaseLocator` parses the code
locally and returns only the public case locator for routing. Never send the full
code to an API, telemetry, URL, cookie, or server-side form action. Restoring the
package reconstructs the owner key entirely on the participant device. Creation
exercises the restore path before returning a recoverable receipt.

Recovery is not proof of latest state. A restored owner always receives
`freshness: 'requires-current-state-verification'`. With an independently retained
device checkpoint, restore rejects an older revision, lower key epoch, or a fork
at the same revision. `advanceOwnerCheckpoint` enforces the same local monotonic
rule. A new device with an old export cannot prove there were no later
revocations. By owner decision (2026-09-27, `CONFIDENTIAL-FRESHNESS-DECISION.md`)
there is no independent current-state witness: owner commits refresh the stored
package, and pin-less restores are reported as `unconfirmed` (accepted residual). Do not fill the authorization layer's trusted-current digest directly
from an unverified restored snapshot.

`refreshOwnerRecovery` advances the encrypted checkpoint snapshot using the same
participant code, with a fresh encryption nonce. The caller must atomically save
the new package and device pin; this module has no persistence and cannot enforce
that transaction. Keep an offline copy of the encrypted package as well as the
code. A code alone cannot restore ciphertext the operator has deleted. Possession
of both artifacts confers owner access; a combined downloaded recovery file must
be labeled and handled as a private credential. The browser implements encrypted
device workspaces, offline export and restore confirmation; those features do not
turn a saved snapshot into independent proof of the latest state.

`accessRequest.ts` encrypts a firm's signed request directly to the case owner.
The organization identifier, case linkage, purpose and exact requested scopes are
inside the ciphertext. Recipient key IDs are hidden in the outer OpenPGP packet.
The owner decrypts a bounded message, selects a key from an already authenticated
local organization roster, and verifies the original signed message before
returning anything to the UI. It never uses request-supplied keys or sends unverified
request text to a directory lookup. Current whitelist approval, exact firm key,
owner/case binding, and request validity are required. An eligible request is not
an access grant and never causes an owner signature automatically.

Owner inbox consumers use `openDeliveredLegalAccessRequest` to additionally check
that the verified inner request matches the current delivery record's case,
request ID, organization, recipient key and expiry. Only a pending record is
eligible. Metadata is snapshotted before asynchronous verification; no private
request is returned on a mismatch. The record's lifecycle status still needs an
authenticated current-state source. This helper cannot make an operator's stale
`pending` row trustworthy or replace the separate owner grant action.

Request bounds are a 1,000-character purpose, a maximum 30-day validity,
16 KiB armored ciphertext and 256 pinned organization entries per verification. The
mounted service delivers requests through `cases/service.ts` `submitAccessRequest`
(participant proof, guarded insert with per-firm and per-case quotas, permanent
request-ID tombstones). Directory keys must be verified
independently; an operator-controlled replacement directory cannot be trusted just
because it returns `approved: true`.

`enrollmentProof.ts` lets a firm browser sign a recipient-bound invitation
challenge without uploading its private key. The compiled enclave verifies that
proof during enrollment. The separate [legal service core](../legal/README.md)
implements JWT verification and atomic invitation-consumption orchestration;
the mounted service uses the transactional MongoDB adapter. Deployment still
requires live IdP configuration and independently verified firm-key registration.

## Required caller guarantees

All authorization records except the explicitly public listing contain private
relationship metadata. **Encrypt them before persistence or transport.** Signing
alone does not hide them. This layer has no persistence or network API.

The owner fingerprint/public key must come from authenticated genesis/recovery,
not from the same server record being verified. Firm identity/key bindings need
independent verification, and enrollment requires proof of key possession.

`authorizeCaseRead` requires a pinned `checkpointDigest`. This must represent
current state from a trusted device checkpoint or authenticated freshness witness.
Reading that digest from the same untrusted database as an old checkpoint would
defeat rollback protection. This module does not implement the witness, cross-device
freshness, atomic commits or conflict resolution. Missing checkpoints have no default.

The enclave handler must authenticate active org membership, prove the
recipient possesses the approved key, use its own measured release identity and
authenticated object metadata, and establish trusted time. Never populate those
values directly from untrusted request claims. Validate fresh, channel-bound
attestation before releasing private keys/data. This module cannot attest to where
its own JavaScript is running.

Expired/revoked grants and withdrawn releases fail in the official read path.
A recipient with a previously delivered key/envelope can retain the disclosed
contents. These checks do not revoke downloaded keys, erase exported evidence,
or prevent a recipient from processing its own copy outside Vera.

## Limits and remaining work

- The [application-channel identity helper](../../verification/APPLICATION-CHANNEL.md)
  generates a fresh enclave-side key and binds its exact public bytes to a
  nonce/domain-specific NSM request. The browser verifier checks the pinned AWS
  root, signature and expected policy. Authorized encrypted session handlers are
  mounted behind the confidential-mode gate. Source integration and synthetic
  tests do not establish genuine Nitro hardware or deployment acceptance.
- Whole-buffer objects are capped at 8 MiB, with bounded parsing/decompression.
  New evidence uses `caseChunks.ts`: 512 KiB chunks, at most 256 MiB per file and
  per upload, and at most 16 files per upload.
- Owned byte buffers are cleared where practical, but JavaScript strings, GC,
  cryptographic-library copies and browser memory cannot be guaranteed erased.
- Sizes are padded to buckets inside the encryption (`padding.ts`; objects,
  chunks, messages and channel bodies; architecture hole 12). Buckets hide exact
  sizes only: object counts, approximate sizes, network timing and application
  routing remain visible.
- Invitation/login clients, member authorization, recovery workspaces, request
  deduplication, grants and release-approval UI are implemented. Private conversation UI and mounted message operations are retired; retained message formats are compatibility only.
  Their live identity, storage, restart, logging and backup acceptance must still
  satisfy the [architecture launch requirements](../../../docs/security/README.md#verification).
- Freshness uses participant checkpoint pins. An independent monotonic-state
  witness is deliberately excluded by the
  [accepted freshness decision](../../../docs/security/README.md#recovery-and-release-approval),
  with residual rollback risk on a new device that has no independent pin.
- Legacy readers reject confidential identifiers. This isolation does not migrate
  historical reports or establish deployment acceptance or third-party review.

## Verification

Run the real-crypto tampering and authorization tests:

```sh
npm run build:enclave
npm test -- --runInBand --testPathPatterns=tests/unit/confidential/
npm run typecheck
```

The independent Chromium harness compiles the enclave package and builds the browser dependency graph using the
repository's Next-bundled webpack, verifies selection of OpenPGP's browser entry,
and executes owner encryption, grant, recovery, authorized open, and rejected
admin/substituted-key/unapproved-release attempts inside a real browser. It also
creates an encrypted legal request, verifies it on the owner device, and uses its
scope in the separately signed owner grant. Recovery testing
restores an exported package in a separate browser context with no original keys,
opens the original evidence, and rejects an incorrect recovery code. It uses
the compiled enclave policy to verify browser-generated owner consent and reject
a mismatched release, without giving that verifier any participant private key.
This is local runtime interoperability, not execution on Nitro hardware. It uses
synthetic data, a temporary bundle and a loopback-only server; it does not open
the live app or call external services. It does not prove Safari/Firefox or TEE
compatibility.

```sh
npm ci --prefix qa --ignore-scripts
npm ci --prefix enclave --ignore-scripts
cd qa && npx playwright install chromium && cd ..
node scripts/security/verify-confidential-browser.cjs
```

## Case inventory, messages, participant proofs and firm-key binding

- `authorization.ts` `manifest` statements are the owner-signed object inventory;
  checkpoints hash-chain via `previousDigest` and name the current `listingDigest`
  and `manifestDigest`. `authorizeCaseRead` takes object ID and ciphertext digest
  from the request and checks them against the manifest.
- `caseMessage.ts`: compatibility parser/crypto for historical signed owner<->organization messages, bound to case, organization, direction and a per-sender sequence. Its presence does not expose a current conversation API.
- `participantRequest.ts`: the only operation proof format (owner and legal
  organization): key possession over audience, role, case, organization, operation,
  exact request body digest, the carrying channel and a single-use service challenge.
- `firmKeyBinding.ts`: the organization's self-signed key submission (proof of key
  possession plus its optional public profile), approved through the onboarding
  authority's signed registration. Nothing is published on the firm's website.
- `../cases/service.ts`: signature-authorized ciphertext relay (publish, CAS
  transitions, directory projection, requests, grant-gated envelopes and
  recovery package; historical message helpers are not dispatched). The owner and legal channels mount it with sealed storage;
  `src/services/confidentialCaseStore.ts` supplies the transactional MongoDB adapter.

## Import convention (browser + enclave)

Modules in this directory import siblings with `.ts` specifiers. The enclave
build rewrites them to `.js` (`rewriteRelativeImportExtensions`), and the Next.js
Turbopack build resolves the `.ts` sources directly, so pages can import this
exact protocol source. `.js` specifiers here break the production frontend build.
