import { webcrypto } from 'node:crypto';
import { generateKey, readMessage } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseReadAuthorization, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import {
  caseObjectDigest, caseRecipientKeyId, grantCaseObject, openGrantedCaseObject, openOwnerCaseObject, sealCaseObject,
} from '../../../enclave/src/confidential/caseObject';
import type { GrantedCaseObject, ObjectContext, OwnedCaseObject } from '../../../enclave/src/confidential/caseObject';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const ctx: ObjectContext = { caseId: hex(1), objectId: hex(2), scope: 'evidence', keyEpoch: 1, objectRevision: 1 };
const plaintext = new TextEncoder().encode('PRIVATE-SENTINEL: identity and unredacted synthetic evidence\u0000\u00ff');
let owner: PrivateKey, legal: PrivateKey, intruder: PrivateKey;
let auth: CaseReadAuthorization, owned: OwnedCaseObject, shared: GrantedCaseObject;
let authorize: (objects: { context: ObjectContext; ciphertext: string }[], target: number) => Promise<CaseReadAuthorization>;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [owner, legal, intruder] = await Promise.all(['owner', 'legal', 'platform-admin'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
  const trust = { caseId: ctx.caseId, ownerFingerprint: owner.getFingerprint(), ownerPublicKey: owner.toPublic() };
  const recipientKeyId = await caseRecipientKeyId(legal.toPublic());
  async function signed(statement: OwnerStatement) {
    const wire = await signOwnerStatement(statement, owner);
    return { wire, ...await verifyOwnerStatement(wire, trust) };
  }
  const grant = await signed({ kind: 'grant', caseId: ctx.caseId, revision: 2, grantId: hex(3),
    organizationId: hex(4), recipientKeyId, scopes: ['evidence'], keyEpoch: 1, objectRevisionLimit: null,
    issuedAt: now - 1000, expiresAt: now + 60_000 });
  const release = await signed({ kind: 'release', caseId: ctx.caseId, revision: 1,
    releaseDigest: hex(5), issuedAt: now - 1000 });
  // Each content change is a new owner-signed manifest and checkpoint; the grant is reused.
  authorize = async (objects, target) => {
    const entries = await Promise.all(objects.map(async ({ context, ciphertext }) => ({
      objectId: context.objectId, scope: context.scope, objectRevision: context.objectRevision,
      keyEpoch: context.keyEpoch, ciphertextDigest: await caseObjectDigest(ciphertext) })));
    const manifest = await signed({ kind: 'manifest', caseId: ctx.caseId, revision: 2, objects: entries });
    const checkpoint = await signed({ kind: 'checkpoint', caseId: ctx.caseId, revision: 2, keyEpoch: 1,
      previousDigest: null, listingDigest: null, manifestDigest: manifest.digest,
      grantDigests: [grant.digest], releaseDigests: [release.digest], issuedAt: now });
    const { context } = objects[target];
    return { trust, grant: grant.wire, release: release.wire, manifest: manifest.wire, checkpoint: checkpoint.wire,
      checkpointDigest: checkpoint.digest, request: { organizationId: hex(4), recipientKeyId, objectId: context.objectId,
        ciphertextDigest: entries[target].ciphertextDigest, scope: context.scope, releaseDigest: hex(5),
        keyEpoch: context.keyEpoch, objectRevision: context.objectRevision, now } };
  };
  owned = await sealCaseObject(ctx, plaintext, owner);
  auth = await authorize([{ context: ctx, ciphertext: owned.ciphertext }], 0);
  shared = await grantCaseObject(owned, ctx, owner, legal.toPublic(), auth);
});

describe('participant-encrypted case objects', () => {
  test('owner can recover the exact binary payload without a server recovery secret', async () => {
    expect(await openOwnerCaseObject(owned, ctx, owner)).toEqual(plaintext);
  });

  test('grant wraps the same ciphertext for the approved legal recipient', async () => {
    expect(shared.ciphertext).toBe(owned.ciphertext);
    expect(await openGrantedCaseObject(shared, ctx, legal, auth)).toEqual(plaintext);
    expect(Object.keys(shared).sort()).toEqual(['ciphertext', 'recipientEnvelope']);
    for (const sentinel of ['PRIVATE-SENTINEL', ctx.caseId, ctx.objectId, 'evidence', owner.getFingerprint(), legal.getFingerprint()]) {
      expect(JSON.stringify([owned, shared])).not.toContain(sentinel);
    }
    // Recipient key identifiers are hidden in the public OpenPGP packet header.
    const message = await readMessage({ armoredMessage: shared.recipientEnvelope });
    expect(message.getEncryptionKeyIDs().every(id => /^0+$/.test(id.toHex()))).toBe(true);
  });

  test('platform-held credentials/keys cannot open owner or legal envelopes', async () => {
    await expect(openOwnerCaseObject(owned, ctx, intruder)).rejects.toThrow('Unable to open confidential case object');
    await expect(openGrantedCaseObject(shared, ctx, intruder, auth)).rejects.toThrow('Unable to open confidential case object');
  });

  test('substituting the firm public key cannot redirect a grant', async () => {
    await expect(grantCaseObject(owned, ctx, owner, intruder.toPublic(), auth)).rejects.toThrow();
  });

  test('a platform key cannot impersonate the owner when sharing', async () => {
    await expect(grantCaseObject(owned, ctx, intruder, legal.toPublic(), auth)).rejects.toThrow();
  });

  test.each([
    ['case', { caseId: hex(99) }], ['object', { objectId: hex(99) }],
    ['scope', { scope: 'identity' as const }], ['epoch', { keyEpoch: 2 }], ['revision', { objectRevision: 2 }],
  ])('ciphertext cannot be replayed with a different %s', async (_label, change) => {
    await expect(openOwnerCaseObject(owned, { ...ctx, ...change }, owner)).rejects.toThrow();
    await expect(openGrantedCaseObject(shared, { ...ctx, ...change }, legal, auth)).rejects.toThrow();
  });

  test.each([
    ['wrong release', { releaseDigest: hex(99) }], ['expired grant', { now: now + 60_000 }],
    ['wrong organization', { organizationId: hex(99) }],
  ])('official client rejects key delivery and opening for %s', async (_label, change) => {
    const invalid = { ...auth, request: { ...auth.request, ...change } };
    await expect(grantCaseObject(owned, ctx, owner, legal.toPublic(), invalid)).rejects.toThrow();
    await expect(openGrantedCaseObject(shared, ctx, legal, invalid)).rejects.toThrow();
  });

  test('a second valid encrypted object cannot be substituted under the original envelope', async () => {
    const other = await sealCaseObject(ctx, new TextEncoder().encode('OTHER-PRIVATE-SENTINEL'), owner);
    await expect(openOwnerCaseObject({ ...owned, ciphertext: other.ciphertext }, ctx, owner)).rejects.toThrow();
    await expect(openGrantedCaseObject({ ...shared, ciphertext: other.ciphertext }, ctx, legal, auth)).rejects.toThrow();
  });

  test('owner can add evidence under existing future-inclusive consent without signing a new grant', async () => {
    const nextContext = { ...ctx, objectId: hex(20), objectRevision: 20 };
    const next = await sealCaseObject(nextContext, plaintext, owner);
    const nextAuth = await authorize([{ context: ctx, ciphertext: owned.ciphertext },
      { context: nextContext, ciphertext: next.ciphertext }], 1);
    const nextShared = await grantCaseObject(next, nextContext, owner, legal.toPublic(), nextAuth);
    expect(await openGrantedCaseObject(nextShared, nextContext, legal, nextAuth)).toEqual(plaintext);
  });

  test('current owner checkpoint removes an existing grant from the official read path', async () => {
    const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: ctx.caseId, revision: 3,
      keyEpoch: 2, previousDigest: auth.checkpointDigest, listingDigest: null,
      manifestDigest: (await verifyOwnerStatement(auth.manifest, auth.trust)).digest,
      grantDigests: [], releaseDigests: [], issuedAt: now }, owner);
    const { digest } = await verifyOwnerStatement(checkpoint, auth.trust);
    const revoked = { ...auth, checkpoint, checkpointDigest: digest };
    await expect(openGrantedCaseObject(shared, ctx, legal, revoked)).rejects.toThrow();
    // Owner recovery remains possible; this does not promise erasure of legal copies.
    expect(await openOwnerCaseObject(owned, ctx, owner)).toEqual(plaintext);
  });

  test('object encryption snapshots caller buffers and uses fresh keys/randomness', async () => {
    const copy = plaintext.slice(), mutable = { ...ctx };
    const pending = sealCaseObject(mutable, copy, owner);
    copy.fill(0); mutable.scope = 'identity';
    const result = await pending;
    expect(await openOwnerCaseObject(result, ctx, owner)).toEqual(plaintext);
    expect(result.ciphertext).not.toBe(owned.ciphertext);
  });

  test('opaque corrupt or oversized objects fail without echoing their contents', async () => {
    await expect(openOwnerCaseObject({ ...owned, ownerEnvelope: 'PRIVATE-SENTINEL' }, ctx, owner))
      .rejects.toThrow('Unable to open confidential case object');
    await expect(openGrantedCaseObject({ ...shared, ciphertext: 'PRIVATE-SENTINEL' }, ctx, legal, auth))
      .rejects.toThrow('Unable to open confidential case object');
    await expect(sealCaseObject(ctx, new Uint8Array(8 * 1024 * 1024 + 1), owner)).rejects.toThrow();
  });
});
