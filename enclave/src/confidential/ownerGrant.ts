import type { PrivateKey } from './pgp.ts';
import { issuedNotAfter } from './clockSkew.ts';
import { MAX_GRANT_LIFETIME_MS, grantCoversObject, signOwnerStatement, verifyOwnerStatement } from './authorization.ts';
import type { AccessGrant, CaseCheckpoint, CaseManifest, CaseScope, ManifestEntry, OwnerTrust } from './authorization.ts';
import { openDeliveredLegalAccessRequest } from './accessRequest.ts';
import type { DeliveredLegalAccessRequest, TrustedLegalOrganization } from './accessRequest.ts';
import { grantCaseObject, grantCaseObjectEnvelope } from './caseObject.ts';
import type { OwnedCaseObject } from './caseObject.ts';
import { wrapCaseStateKey } from './caseStateKey.ts';
import type { CaseStateKey } from './caseStateKey.ts';
import type { PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';

export type OwnerGrantDecision = {
  grantId: string; scopes: CaseScope[]; objectRevisionLimit: number | null;
  /** `null` = until revoked; otherwise at most MAX_GRANT_LIFETIME_MS ahead. */
  expiresAt: number | null;
  /** Manifest objects of a granted scope to leave out ("only some files"). */
  excludedObjectIds?: string[];
};
type GrantObjects = readonly ((OwnedCaseObject | { ownerEnvelope: string }) & { objectId: string })[];
type CommonInput = {
  trust: OwnerTrust; owner: PrivateKey; checkpoint: string; checkpointDigest: string;
  manifest: string; release: string; releaseDigest: string; now: number;
  /** Owner key envelopes; ciphertext is optional (the signed manifest supplies its digest). */
  objects: GrantObjects;
  /** Sealed storage: the owner's current state key and the pinned public keys of
   * firms that already hold grants. The key is re-wrapped to owner + all of them +
   * this firm; adding or re-issuing a grant never rotates it. */
  sealedState?: { state: CaseStateKey; currentRecipients: readonly PublicKey[] };
  /** Current grants (wires) of the SAME organization that this decision replaces,
   * for example when the owner approves a renewal request with new choices. */
  replacedGrants?: readonly string[];
  /** Current grants (wires) of the SAME organization and key to keep but re-sign
   * with this decision's expiry, for example contact sharing, which must end
   * when report access ends. Content, scope and file selection are unchanged. */
  realignedGrants?: readonly string[];
};

function invalid(): never { throw new Error('Cannot prepare confidential access grant'); }
function expiry(value: unknown, now: number): number | null {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= now || value - now > MAX_GRANT_LIFETIME_MS) invalid();
  return value;
}

/** Owner-browser operation, called only after an explicit Allow decision. The
 * roster and current checkpoint digest must be independently authenticated.
 * Returns a prepared commit; does not send it, update a local pin or claim access
 * was granted. Retain these exact bytes for network retries. Private statements
 * belong inside the attested channel and encrypted persistence, never logs.
 * Grants of other organizations are always preserved; `replacedGrants` may only
 * name current grants of the requesting organization.
 */
export async function prepareOwnerGrant(input: CommonInput & {
  delivery: DeliveredLegalAccessRequest; directory: readonly TrustedLegalOrganization[]; decision: OwnerGrantDecision;
}) {
  try {
    if (!input || !input.decision || !Array.isArray(input.decision.scopes) || !Array.isArray(input.objects) ||
        input.objects.length > 256 || !Number.isSafeInteger(input.now) || input.now <= 0) invalid();
    // Snapshot all caller-controlled selection and wire data before any await.
    const delivery = { ...input.delivery }, directory = input.directory.map(item => ({ ...item }));
    const decision = snapshotDecision(input.decision);
    const request = await openDeliveredLegalAccessRequest(delivery, input.trust.caseId, input.owner, directory, input.now);
    if (decision.scopes.some(scope => !request.scopes.includes(scope)) ||
        (request.objectRevisionLimit !== null && (decision.objectRevisionLimit === null ||
          decision.objectRevisionLimit > request.objectRevisionLimit))) invalid();
    const recipient = directory.find(item => item.organizationId === request.organizationId)!;
    return await prepareGrantCommit({ ...input, decision }, { organizationId: request.organizationId,
      recipientKeyId: request.recipientKeyId, publicKey: recipient.publicKey });
  } catch { return invalid(); }
}

/** Explicit owner-initiated grant, separate from the request-limited path.
 * The caller must verify an approved roster entry (authority-signed registration);
 * contact sharing callers additionally require an existing report grant. */
export async function prepareDirectGrant(input: CommonInput & {
  organization: { organizationId: string; publicKey: PublicKey }; decision: OwnerGrantDecision;
}) {
  try {
    if (!input || !input.decision || !Array.isArray(input.decision.scopes) || !Array.isArray(input.objects) ||
        input.objects.length > 256 || !Number.isSafeInteger(input.now) || input.now <= 0 ||
        !input.organization || input.organization.publicKey.isPrivate()) invalid();
    const decision = snapshotDecision(input.decision);
    const organization = { ...input.organization };
    return await prepareGrantCommit({ ...input, decision }, { organizationId: organization.organizationId,
      recipientKeyId: await caseRecipientKeyId(organization.publicKey), publicKey: organization.publicKey });
  } catch { return invalid(); }
}

function snapshotDecision(input: OwnerGrantDecision): OwnerGrantDecision {
  const decision = { ...input, scopes: [...input.scopes],
    ...(input.excludedObjectIds ? { excludedObjectIds: [...input.excludedObjectIds].sort() } : {}) };
  if (!decision.scopes.length || new Set(decision.scopes).size !== decision.scopes.length ||
      (decision.excludedObjectIds && (!decision.excludedObjectIds.length ||
        new Set(decision.excludedObjectIds).size !== decision.excludedObjectIds.length))) invalid();
  return decision;
}

/** Recipient key envelopes for every current-epoch manifest object a grant
 * covers. Each envelope is bound to that grant's digest, so a re-issued grant
 * (renewal, replacement) always needs fresh envelopes. */
async function wrapCovered(input: {
  trust: OwnerTrust; owner: PrivateKey; manifest: string; release: string; releaseDigest: string; now: number;
  objects: GrantObjects; checkpoint: string; checkpointDigest: string; keyEpoch: number;
  entries: readonly ManifestEntry[]; grant: string; statement: AccessGrant;
  recipient: { organizationId: string; recipientKeyId: string; publicKey: PublicKey };
}) {
  const objects = new Map(input.objects.map(item => [item.objectId, item]));
  if (objects.size !== input.objects.length) invalid();
  const envelopes: { objectId: string; recipientKeyId: string; envelope: string }[] = [];
  for (const entry of input.entries) {
    if (entry.keyEpoch !== input.keyEpoch || !grantCoversObject(input.statement, entry)) continue;
    const object = objects.get(entry.objectId);
    if (!object) invalid();
    const objectContext = { caseId: input.trust.caseId, objectId: entry.objectId,
      scope: entry.scope, objectRevision: entry.objectRevision, keyEpoch: entry.keyEpoch };
    const authorization = { trust: input.trust, grant: input.grant, checkpoint: input.checkpoint, checkpointDigest: input.checkpointDigest,
      manifest: input.manifest, release: input.release,
      request: { ...entry, organizationId: input.recipient.organizationId, recipientKeyId: input.recipient.recipientKeyId,
        releaseDigest: input.releaseDigest, now: input.now } };
    const recipientEnvelope = 'ciphertext' in object!
      ? (await grantCaseObject(object as OwnedCaseObject, objectContext, input.owner, input.recipient.publicKey, authorization)).recipientEnvelope
      : await grantCaseObjectEnvelope(object!.ownerEnvelope, objectContext, input.owner, input.recipient.publicKey, authorization);
    envelopes.push({ objectId: entry.objectId, recipientKeyId: input.recipient.recipientKeyId, envelope: recipientEnvelope });
  }
  return envelopes;
}

async function verifiedState(input: Pick<CommonInput, 'trust' | 'checkpoint' | 'checkpointDigest' | 'manifest' | 'release' | 'releaseDigest' | 'now'>) {
  const [previous, manifest, release] = await Promise.all([
    verifyOwnerStatement(input.checkpoint, input.trust), verifyOwnerStatement(input.manifest, input.trust),
    verifyOwnerStatement(input.release, input.trust),
  ]);
  if (previous.statement.kind !== 'checkpoint' || previous.digest !== input.checkpointDigest ||
      !issuedNotAfter(previous.statement.issuedAt, input.now) || manifest.statement.kind !== 'manifest' ||
      manifest.digest !== previous.statement.manifestDigest || manifest.statement.revision > previous.statement.revision ||
      release.statement.kind !== 'release' || !previous.statement.releaseDigests.includes(release.digest) ||
      release.statement.releaseDigest !== input.releaseDigest || !issuedNotAfter(release.statement.issuedAt, input.now) ||
      release.statement.revision > previous.statement.revision) invalid();
  return { previous: { digest: previous.digest, statement: previous.statement as CaseCheckpoint },
    entries: (manifest.statement as CaseManifest).objects };
}

/** Re-sign current grants of one organization key at a new revision and expiry,
 * keeping everything else. Each must be a distinct current, current-epoch grant
 * of exactly that organization and recipient key, not already being replaced. */
async function reissue(wires: readonly string[], context: {
  trust: OwnerTrust; owner: PrivateKey; current: CaseCheckpoint; revision: number; now: number; expiresAt: number | null;
  recipient: { organizationId: string; recipientKeyId: string }; exclude: ReadonlySet<string>;
}): Promise<{ wire: string; digest: string; statement: AccessGrant; replaces: string }[]> {
  if (wires.length > 16) invalid();
  const seen = new Set<string>();
  const out: { wire: string; digest: string; statement: AccessGrant; replaces: string }[] = [];
  for (const wire of wires) {
    const old = await verifyOwnerStatement(wire, context.trust);
    if (old.statement.kind !== 'grant' || !context.current.grantDigests.includes(old.digest) || seen.has(old.digest) ||
        context.exclude.has(old.digest) || old.statement.keyEpoch !== context.current.keyEpoch ||
        old.statement.organizationId !== context.recipient.organizationId ||
        old.statement.recipientKeyId !== context.recipient.recipientKeyId) invalid();
    seen.add(old.digest);
    const { revision: _revision, issuedAt: _issued, expiresAt: _expires, ...kept } = old.statement as AccessGrant;
    const statement = { ...kept, revision: context.revision, issuedAt: context.now, expiresAt: context.expiresAt } as AccessGrant;
    const signed = await signOwnerStatement(statement, context.owner);
    out.push({ wire: signed, statement, digest: (await verifyOwnerStatement(signed, context.trust)).digest, replaces: old.digest });
  }
  return out;
}

async function prepareGrantCommit(input: CommonInput & { decision: OwnerGrantDecision },
  recipient: { organizationId: string; recipientKeyId: string; publicKey: PublicKey }) {
  const value = { ...input, trust: { ...input.trust }, objects: input.objects.map(item => ({ ...item })),
    replacedGrants: [...(input.replacedGrants ?? [])], realignedGrants: [...(input.realignedGrants ?? [])] };
  const { trust, owner, decision, now } = value;
  if (!owner.isDecrypted() || owner.getFingerprint() !== trust.ownerFingerprint) invalid();
  const expiresAt = expiry(decision.expiresAt, now);
  const { previous, entries } = await verifiedState(value);
  const current = previous.statement, revision = current.revision + 1;
  // Exclusions must name objects of a granted scope in the signed manifest, so a
  // stray or future ID can never be read as "everything except".
  for (const objectId of decision.excludedObjectIds ?? []) {
    const entry = entries.find(item => item.objectId === objectId);
    if (!entry || !decision.scopes.includes(entry.scope)) invalid();
  }
  const replaced = new Set<string>();
  for (const wire of value.replacedGrants) {
    const old = await verifyOwnerStatement(wire, trust);
    if (old.statement.kind !== 'grant' || !current.grantDigests.includes(old.digest) || replaced.has(old.digest) ||
        old.statement.organizationId !== recipient.organizationId) invalid();
    replaced.add(old.digest);
  }
  const realigned = await reissue(value.realignedGrants, { trust, owner, current, revision, now, expiresAt, recipient,
    exclude: replaced });
  for (const item of realigned) replaced.add(item.replaces);
  const statement: AccessGrant = { kind: 'grant', caseId: trust.caseId, revision,
    grantId: decision.grantId, organizationId: recipient.organizationId, recipientKeyId: recipient.recipientKeyId,
    scopes: decision.scopes, keyEpoch: current.keyEpoch, objectRevisionLimit: decision.objectRevisionLimit,
    issuedAt: now, expiresAt, ...(decision.excludedObjectIds ? { excludedObjectIds: decision.excludedObjectIds } : {}) };
  const grant = await signOwnerStatement(statement, owner);
  const grantDigest = (await verifyOwnerStatement(grant, trust)).digest;
  if (current.grantDigests.includes(grantDigest) || realigned.some(item => item.digest === grantDigest)) invalid();
  const checkpoint = await signOwnerStatement({ ...current, revision, previousDigest: previous.digest,
    // A lagging device clock or a smaller attested offset must not make a
    // legitimate commit fail: the service refuses issuedAt < current.issuedAt.
    issuedAt: Math.max(now, current.issuedAt),
    grantDigests: [...current.grantDigests.filter(digest => !replaced.has(digest)), ...realigned.map(item => item.digest), grantDigest] }, owner);
  const checkpointDigest = (await verifyOwnerStatement(checkpoint, trust)).digest;
  const envelopes = await wrapCovered({ ...value, checkpoint, checkpointDigest, keyEpoch: current.keyEpoch,
    entries, grant, statement, recipient });
  for (const item of realigned) {
    envelopes.push(...await wrapCovered({ ...value, checkpoint, checkpointDigest, keyEpoch: current.keyEpoch,
      entries, grant: item.wire, statement: item.statement, recipient }));
  }
  const sealed = input.sealedState ? await Promise.all([trust.ownerPublicKey, ...input.sealedState.currentRecipients,
    recipient.publicKey].map(key => wrapCaseStateKey(trust.caseId, input.sealedState!.state, key, owner))) : null;
  return { grant, checkpointDigest, body: { caseId: trust.caseId, statements: [...realigned.map(item => item.wire), grant], checkpoint,
    objects: [], envelopes, recoveryPackage: null,
    ...(sealed ? { stateEnvelopes: sealed, stateKeyRotation: null } : {}) } };
}

/** Owner "Renew access": re-sign every listed current grant of ONE organization
 * with the same ID, scope, file selection and key epoch, and a new expiry
 * (`null` = until revoked). Envelopes are bound to the grant digest, so the
 * same objects are re-wrapped to the same verified organization key; the
 * organization stays a state-key recipient, so nothing rotates. */
export async function prepareGrantRenewal(input: CommonInput & {
  organization: { organizationId: string; publicKey: PublicKey };
  grants: readonly string[]; expiresAt: number | null;
}) {
  try {
    const value = { ...input, trust: { ...input.trust }, grants: [...input.grants], objects: input.objects.map(item => ({ ...item })) };
    const { trust, now } = value;
    if (!value.grants.length || value.grants.length > 16 || !Number.isSafeInteger(now) || now <= 0 || !Array.isArray(input.objects) ||
        input.objects.length > 256 || !input.owner.isDecrypted() || input.owner.getFingerprint() !== trust.ownerFingerprint ||
        input.organization.publicKey.isPrivate()) invalid();
    const expiresAt = expiry(value.expiresAt, now);
    const recipient = { organizationId: input.organization.organizationId, publicKey: input.organization.publicKey,
      recipientKeyId: await caseRecipientKeyId(input.organization.publicKey) };
    const { previous, entries } = await verifiedState(value);
    const current = previous.statement, revision = current.revision + 1;
    const renewed = await reissue(value.grants, { trust, owner: input.owner, current, revision, now, expiresAt, recipient,
      exclude: new Set() });
    const replaced = new Set(renewed.map(item => item.replaces));
    const checkpoint = await signOwnerStatement({ ...current, revision, previousDigest: previous.digest,
    // A lagging device clock or a smaller attested offset must not make a
    // legitimate commit fail: the service refuses issuedAt < current.issuedAt.
    issuedAt: Math.max(now, current.issuedAt),
      grantDigests: [...current.grantDigests.filter(digest => !replaced.has(digest)), ...renewed.map(item => item.digest)] }, input.owner);
    const checkpointDigest = (await verifyOwnerStatement(checkpoint, trust)).digest;
    const envelopes = [];
    for (const item of renewed) {
      envelopes.push(...await wrapCovered({ ...value, checkpoint, checkpointDigest, keyEpoch: current.keyEpoch,
        entries, grant: item.wire, statement: item.statement, recipient }));
    }
    if (new Set(envelopes.map(item => item.objectId)).size !== envelopes.length) invalid();
    return { checkpointDigest, body: { caseId: trust.caseId, statements: renewed.map(item => item.wire), checkpoint,
      objects: [], envelopes, recoveryPackage: null } };
  } catch { return invalid(); }
}
