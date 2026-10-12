# Private legal enrollment and identity

Configure your own legal identity policy and approval worker. Deployment acceptance remains environment-specific; see [key approval](../../../docs/security/README.md#authorization-and-legal-access) and [deployment](../../../docs/security/README.md). Report access still requires participant key possession and the reporter's grant; private conversations are retired.

The mounted enclave server composes `cases/legalChannel.ts` with the sealed case service.
Its `legal.directory` operation verifies current signed membership and returns the
owner-approved listing projection through the attested channel. The earlier
unmounted `legal.directory.list` implementation and its isolated test were retired.
Directory behavior is covered by `tests/confidential-runtime/legal-channel.test.cjs`
and `tests/unit/confidential/legalChannel.test.ts`. This source wiring does not
establish deployed Auth0 or Nitro acceptance.

## Approved-domain onboarding

VERA approves the organization and its exact work-email domain. The Auth0 Action
requires a verified email at that domain; matching a domain alone never grants
membership or access to a report. Firms do not publish a website key file.

The first lawyer submits a signed public key/profile through
`legal.submit-organization-key`; onboarding approval registers that key.
`legal.organization-key` returns the approved binding through the attested channel.
The private key stays on the lawyer's device. The onboarding authority is trusted
to vouch for this initial recipient identity; browser users also trust the
website's delivered code.

An enrolled steward uses `legal.firm-invite-member` to add Auth0 membership for
a colleague at the approved domain and shares the portal's join link. After sign-in,
the colleague requests approval for their device. The steward
compares the device code before approving it. `legal.device-enroll` verifies both
the organization authorization and approved device proof before issuing a bounded
membership lease; a saved approved device can renew without another VERA invitation.
Removing a device blocks renewal. Replacing the organization key requires approval
and new reporter grants; it does not transfer access to existing encrypted drops.

## Case-operation identity and key possession

Firm case operations use the same proof format as owner operations:
`confidential/participantRequest.ts` (`vera-participant-request/v2`, role
`organization`). The mounted dispatcher (next section) verifies the `legal:case`
token, loads the enrolled member and approved organization rows, recomputes the
organization key ID, and has the case service verify the proof against that key,
never a request-selected one. The proof binds audience, case, organization,
operation, exact body bytes, the carrying channel's nonce and server key ID, and
an enclave-issued single-use challenge that is consumed only after the signature
verifies. Membership is rechecked after the operation.

A separate draft proof, `vera-legal-operation/v1` (`operationProof.ts`), and the
never-mounted modules built on it (`operationAuthority.ts`, `caseRead.ts`,
`accessRequests.ts`) were retired; the mounted service performs their reads and
request delivery. The current bindings are described above; see also the
[security model](../../../docs/security/README.md#authorization-and-legal-access).

Proof verification establishes the legal principal and key possession only. It
returns no case key, object or owner-grant authority. The case service still
enforces the owner's exact grant and scopes, the approved release and the current
checkpoint for every private read or write. Granting an Auth0 scope alone never
grants private case access.

## Mounted firm-side case channel (`cases/legalChannel.ts`)

`createLegalCaseDispatcher` is mounted in `confidential-server.ts` beside the owner
dispatcher. Operations are routed by prefix: `case.*` goes to the owner side,
`legal.*` to the firm side. All requests and replies are JSON inside the attested
channel. This is the contract the legal portal uses:

| Request | Reply |
| --- | --- |
| `{operation:'legal.challenge'}` | `{challenge, expiresAt}` |
| `{operation:'legal.release-approvals', caseId}` | `{releases}` (public owner-signed approvals) |
| `{operation:'legal.directory', accessToken, after: caseId\|null, limit: 1..20}` | `{listings:[{caseId, summary, publishedAt?, hasAttachments?, ownerPublicKey, listing}], next}` |
| `{operation:'legal.membership', accessToken}` | `{enrolled:false, lapsed}` or `{enrolled:true, lapsed:false, organizationId, recipientKeyId, leaseExpiresAt, members}` |
| `{operation:'legal.enrollment-challenge', accessToken, body: base64({token})}` | the `EnrollmentChallenge` |
| `{operation:'legal.enroll', accessToken, body: base64({token, proof})}` | `{organizationId, subject, recipientKeyId}` |
| `{operation:'legal.setup-status', accessToken, body: base64({organizationId})}` | `{complete, missing, custody, holders, custodyAttestedAt, terms, termsVersion}` |
| `{operation:'legal.setup-record', accessToken, body: base64({organizationId, kind, statement})}` | the same status after storing the statement |
| `{operation:'legal.<op>', accessToken, proof, body: base64}` | the case-service result, `{error:'locked'}`, `{error:'release-not-approved'}`, for `open-case`, `read-state-keys` and `unlock-case` `{error:'not-granted'}`, or `{error:'setup-incomplete', missing}` |

`legal.membership` needs `legal:directory` and answers only for the signed-in
subject. A missing row is `enrolled:false`; an inactive or expired lease is
`lapsed:true`. A row that exists but fails the full membership verification is
denied, so a tampered host row never reads as a valid or missing membership.
`members` is the host's `countMembers` result for the verified organization key
(active, unexpired). It feeds the firm onboarding checklist only and never
authorizes anything; a host can misreport it. If the count fails, `members` is
`null` and the rest of the status is still returned.

In a directory row, `ownerPublicKey` is the armored case-owner key and `listing` is
the owner-signed listing statement. The firm verifies both itself and encrypts
access requests to that key. Rows never include checkpoints, grants, manifests or
relationships. Enrollment needs the `legal:enroll` scope and goes through
`createLegalEnrollmentRedeemer`, which covers the member side of `enrollment.ts`
and needs no admin policy. The invitation token travels only inside the encrypted
body. `commitEnrollment` is one Mongo transaction: it consumes the invitation,
rechecks the organization binding and upserts the member. Invitations are not
issued over this channel. `not-granted` is also returned when the case or its
manifest is missing. Before the proof is checked, a verified member can use it to
learn whether a case ID exists.

**Enforced organization setup** (`cases/legalSetup.ts`, statements in
`confidential/firmSetup.ts`). When the firm store is mounted (always, in
`confidential-server.ts`), `request-access`, `read-state-keys`, `unlock-case`,
`open-case` answer
`{error:'setup-incomplete', missing}` (`missing` ⊆ `['terms']`), before
the proof is checked or anything is stored, until:

- `terms`: the organization row holds a `vera-legal-onboarding-terms/v1`
  acknowledgement signed by that key for the current terms version and SHA-256
  digest. The terms text is part of the measured image.

Second-key-holder custody is optional. Status still reports two distinct verified
enrolled holders or a genuine `vera-legal-key-custody/v1` attestation, but absence
of either cannot block report operations. Both statements bind the organization ID
and exact key ID, so a key replacement needs new statements. `withdraw-request`
and `request-status` are not gated.
`legal.setup-record` needs `legal:case` membership and stores a statement only if
the registered key signed it (`getOrganizationSetup`/`putOrganizationSetup`, kept
with `confidential_legal_organizations`). Host rows are verified on every read; a
withheld or invalid terms statement reads as missing (fails closed). A complete result
is cached in enclave memory for one minute per organization key, so a statement
removed by the host can still pass for up to a minute. Independent membership
and report-grant checks still apply on each operation. The
custody attestation is still the key holder's word that a different person holds
the copy; it is not a proof of a second person. Setup is an onboarding
precondition, not an access authority: grants, releases and checkpoints decide
every read.

`<op>` is one of `request-access`, `withdraw-request`, `request-status`, `request-status-batch`,
`read-state-keys`, `unlock-case` or `open-case`.
Private conversations are retired: `legal.read-messages`, `legal.send-message` and
`case.send-message` are not dispatched, even for existing grants with a `messages`
scope. Legacy signed records and encrypted message storage remain readable by
the compatibility layer; this change does not delete historical ciphertext.
`read-state-keys` returns the state-key envelopes only to an organization with a
current grant (active, same key epoch) whenever the case is unlocked, and
`{error:'not-granted'}` otherwise; "no access" versus "update waiting" before a
grant comes from `request-status`. A locked case's grants are sealed, so the
stored list is served; the sealed store pads every stored list with decoy
envelopes (same format, size and hidden recipient) to 16, 32, 64 or 128 and
shuffles it, so its length does not reveal how many parties hold access, and it
cannot change while the case is locked. A firm whose grant ended without a re-key
can therefore still open its own envelope while the case is locked; `unlock-case`
then checks the grant, refuses and drops the key, and answers
`{error:'not-granted'}` (a key that does not open the sealed state, or a bad
proof, is still refused without an answer).
`request-status` takes `{caseId, requestIds}` (0 to 16 of the organization's own
request IDs) and answers only about the verified organization's own requests and
access: `{access, requests}`. `access` is the organization's own current access
(`active`, `expired`, `revoked`, `key-changed`, `none`, or `unknown` while the case
key is not in memory and the sealed grants cannot be read) with its end date
(`null` = until revoked), scopes, whether contact details are shared and
`releaseApproved`; it is read only from owner-signed grants in a checkpoint that is
not from the future. Each request carries its outcome (`requested` with the
request's `expiresAt`, `approved`, `declined`, `expired`, `withdrawn` or
`unknown`). Request rows are host-held and matched through their routing
commitments (request, organization and recipient key), so they are informational
and never grant anything; a request sent under an earlier organization key reads
`unknown`. A decline carries no time or reason. `approved` comes from an
owner-signed grant whose `grantId` is the request ID; the host's `approved` row
marker is only shown while the case is locked. The portal verifies access by
opening the report; no key is handed over to show a status. Other organizations'
requests, grants and history are never returned. `proof` is the v2
participant proof (`signParticipantRequest`: role `organization`, audience
`vera-confidential-cases`, operation without the `legal.` prefix, and the nonce and
server key ID of the same session that carries the request), signed with the firm
key. Get the single-use challenge on the same attested session first. Any other failure is a generic
channel error. Request bodies are capped at 64 KiB and the whole frame at 192 KiB.
Replies are capped at 4 KiB for writes and 240 KiB for reads, including the
directory. The mounted `open-case` operation supports `mode: "index"` and
`mode: "range"`. Index bodies include `caseId` and `minimumCheckpoint` (null on
first read); range bodies additionally bind `objectId`, `offset`, `length` and the
exact `checkpointDigest`. Each range is at most 128 KiB, uses a fresh session and
participant proof, and rechecks grant, release, expiry, checkpoint and membership.
Mongo projects only the requested ciphertext bytes. The browser collects and
hash-checks the complete object before local decryption; failed or inconsistent
ranges never yield partial plaintext. A mounted-stack test covers a 400 KiB file,
a mismatched checkpoint and removed membership. Upload/storage bounds and real
DocumentDB behavior still require acceptance.

`request-status-batch` takes `{cases:[{caseId,requestId}]}` with 1–256 unique cases;
`requestId:null` checks access without a saved request. One organization-scoped
participant proof (`caseId` and `organizationId` both name the verified organization)
binds the entire body. The encrypted reply is `{statuses:[{caseId,status}]}` in the
same order, where `status` is the existing `{access,requests}` result. A missing or
unverifiable case instead returns `{caseId,error:'unavailable'}`; it is never
reported as denied access. All grant and request-routing checks are shared with
the single-case operation, and membership is rechecked before the batch reply.
The existing 64 KiB body / 240 KiB reply limits still apply.

The legal board waits for its directory and shared request list, then checks each
target once in batches of at most 256. Search is local; Refresh starts one new pass.
Locked cases remain unknown until an explicit access check or report open, with
no automatic per-report unlocks. Ship this operation in a measured enclave release
and deploy the matching frontend manifest; older enclaves can reject it. On a batch availability failure, the client tries sequential per-report status reads. If any succeeds, it remembers batch unavailability for that session. Cancellation stops the pass; three failed initial probes stop an outage from multiplying across the board. A transport failure is not evidence of denied report access. See `lib/confidential/firmCase.ts` and its status-client regressions.

The token must carry `legal:directory` for the directory and `legal:case` for the
case operations. The `OrganizationContext` handed to the case service is never read
from request fields. The enclave builds it from:

1. the verified token subject and `org_id`;
2. the enrolled member row for that pair (`active`, `revision`, `organizationId`,
   `recipientKeyId`);
3. the organization row, which must be approved, name the same provider
   organization and the member's `recipientKeyId`, and hold a public key whose
   key ID the enclave recomputes.

After the operation, membership is read again. If the revision, organization, key
or token expiry changed, the reply is suppressed. A write that already committed
is not rolled back. Case authorization (grant, scopes, release, checkpoint) is
still done by the case service.

**Measured identity policy.** The enclave reads `/app/confidential-config.json`
from its image and verifies its bytes against the release manifest's configuration
digest. `legalIdentityPolicySha256` pins the canonical policy (issuer, audience,
clientId, jwks). Null disables legal operations; the host cannot enable them.
A changed policy or JWKS requires a newly measured release and owner approval.
The runtime still validates every token and firm key-possession proof.

**Remaining membership boundary.** Membership and organization rows still come
from the host. Firm-key proofs and owner grants protect private contents, but
these rows do not by themselves establish authentic, rollback-safe membership.
Do not count the measured identity policy as solving member revocation or
case/organization relationship privacy.

Tests: `tests/unit/confidential/legalChannel.test.ts` covers real JWTs, firm keys
and sealed storage over synthetic sessions.
`tests/integration/services/confidentialMountedStack.test.ts` sends firm calls
through the host relay, the frame server, the storage RPC and MongoDB.

## Private ciphertext range reads and request delivery

Both run in the mounted case service (`cases/service.ts`) behind the firm
dispatcher above. `openCase` joins the verified organization context to the
owner-grant predicate (`authorizeCaseRead`): object scope, key epoch, revision and
ciphertext digest come from the owner-signed manifest, never from request fields;
the grant must name the firm and key and include the scope; the owner must have
approved this exact measured release. Range mode binds `objectId`, `offset`,
`length` and the exact `checkpointDigest`; `readGrantedObjects` reads only at the
checked checkpoint and returns only that firm's recipient envelope, and the state
is re-read after the read so a racing revocation or expiry suppresses the reply.
`caseRanges.ts` collects at most 16 MiB in 128 KiB ranges and checks the full
ciphertext digest before any local decryption; no partial object is returned.

`submitAccessRequest` stores only the owner-encrypted request (literal plaintext
and extra packets are refused) through a guarded insert with per-firm and per-case
quotas and permanent request-ID tombstones. No grant or key envelope is created
by delivery. Tests: `tests/unit/confidential/legalChannel.test.ts` and
`tests/integration/services/confidentialMountedStack.test.ts`.

## Identity boundary

`identity.ts` uses pinned JOSE 6.1.3 to verify real RS256 JWT signatures, issuer,
audience, authorized client (`azp`), organization (`org_id`), scope, issuance and
expiry. It accepts Auth0's default `typ: JWT` profile with a known `kid`; it does
not accept ID tokens addressed to the frontend, machine-to-machine subjects,
unsigned tokens, token-supplied key URLs, legacy admin roles, or an unverified
host session assertion. Token lifetime and age are limited to five minutes.

Enrollment uses separate verifier configurations for the onboarding-admin and
legal applications. Their API audiences and client IDs must differ. The admin
application needs `legal:invite` and the configured internal organization; the
legal application needs `legal:enroll` and the invited firm organization. Reading
the directory uses `legal:directory`, not any administrator-role inheritance.

Both profiles require the signed `https://vera.app/legal-assurance` claim, with
different values. Legal members require `approved-member-verified-email`, issued
after verified-email, approved organization, exact domain and legal-member role
checks. They may use email-code sign-in or a valid Auth0 session without MFA.
Onboarding administrators use the separate `createOnboardingAdminIdentityVerifier`
and still require `mfa-verified-email`, issued only after fresh allowed MFA.
Neither profile accepts the other's assurance; legal scopes cannot authorize
`legal:invite`. Refresh grants receive no assurance. Never derive these claims
from user-editable metadata. Missing assurance fails closed.

Removing member MFA is an explicit security-policy change: mailbox or Auth0-session
compromise can now authenticate an approved member without a second factor.
It does not confer firm-key possession, independent key/device approval, or a
reporter's grant. Deploy the matching Action and measured enclave together;
older enclaves reject the new member assurance rather than treating it as MFA.

JWKS is supplied from trusted startup configuration. The eventual refresh path
must authenticate the issuer's TLS inside the enclave or use independently pinned
keys. A JWKS returned by an untrusted parent without authentication is not safe.
No token field chooses a network URL, issuer, audience, key set or clock.

These checks follow [Auth0 access-token validation](https://auth0.com/docs/secure/tokens/access-tokens/validate-access-tokens)
and [organization-token validation](https://auth0.com/docs/manage-users/organizations/using-tokens).
Auth0/cloud operators still have legal-account authentication metadata; these
tokens must never contain whistleblower identity or private case content.

## Invitation and firm-key binding

`enrollment.ts` requires a registered, currently approved organization and an
independently authenticated firm public-key bundle. The invitation binds the
exact provider subject, provider organization, opaque Vera organization ID and
recipient-key digest. It uses a random 256-bit token, stores only its digest,
expires within seven days, and carries a per-invitation random challenge.

The intended user signs in, obtains that challenge and signs it using the firm's
private key via the shared `enrollmentProof.ts` browser module. The enclave verifies
the proof against the registered key, rechecks expiry, and calls the store's atomic
consume-and-enroll operation. Forwarded links, other organizations, substituted
keys, reused proofs and expired tokens fail. No private key crosses this flow.
Return values contain membership identifiers only; there is no case-key, case-grant,
release-approval or recovery capability attached to enrollment.

This service assumes the firm's public key has already been independently
verified. Staff must confirm its Key ID with an authorized representative over a
trusted phone or in-person channel and independently verify the recipient in Auth0.
The browser does not prefill recipients from candidate database rows. No website
publication is required. Setting `approved: true` in an operator-controlled database
or verifying a candidate's self-signature does not establish the firm's identity. Replacing
the registered key invalidates existing invitations and still requires new owner
grants for cases. Login reset does not recover firm private keys.

Initial candidate submissions are restricted to unregistered organizations. The
`legal.replace-organization-key` operation requires current enrollment and a fresh,
channel-bound current-key proof. Its storage write compares the previous key ID to
prevent an intervening registration from accepting a stale replacement. Same-key
signed profile updates remain separate. See `docs/security/README.md#authorization-and-legal-access`.

## Persistence and live integration requirements

`EnrollmentStore` has no default adapter. Implement a transaction that compares
invitation ID, version, token digest and pending state; rechecks expiry and the
current organization/key binding; inserts membership and consumes the invitation
as one operation. A failed commit must not be reported as enrollment. Preserve
current-state authenticity across restart/restore. The in-memory store in the
runtime tests is test-only and must not become a production fallback.

Issue/redeem operations must be mounted only inside the approved enclave behind
the attested application channel. Add request/body limits, quotas, safe error
responses, member-status checks, invitation withdrawal, and storage recovery.
The caller should build the private enrollment URL with a fragment, clear it
after local parsing, and keep raw invitation tokens out of logs/analytics and
referrers. Invitation delivery remains a separate, explicit onboarding action.

Acceptance retries after a lost response should check authenticated enrollment
status; never reopen a consumed invitation. Membership departure, device-key
distribution, firm-controlled recovery and key rotation remain separate work.
An organization member who already retained plaintext or keys cannot be made to
forget them by removing a login.

## Verification

The integration test runs the compiled enclave code using native ESM JOSE,
real synthetic issuer signatures and real firm key-possession proofs. It exercises
audience/client isolation, expiry, assurance, key substitution, replay and concurrent
redemption. It makes no identity-provider or network calls.

```sh
npm --prefix enclave run build
node --test tests/confidential-runtime/legal-enrollment.test.cjs
node scripts/security/verify-confidential-browser.cjs
```

The browser harness also creates a firm enrollment proof in Chromium and verifies
it in the compiled enclave runtime. These are local checks, not Nitro attestation
or hosted/deployed acceptance.


`request-status` requires current legal membership and a participant signature
bound to the case and secret request ID. The sealed store blinds firm/request
identifiers before a bounded host lookup. It returns only request state and expiry,
including after enclave restart without a case key. This is advisory delivery
state from an untrusted host, never proof of owner approval or a substitute for
current signed grants. A missing row means delivery is unconfirmed, not that the
request was never received. Content access always uses `open-case` authorization.
