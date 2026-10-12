import { generateKey } from '../../../enclave/src/confidential/pgp';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { createLegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import { caseObjectDigest, caseRecipientKeyId, openGrantedCaseObject, sealCaseObject } from '../../../enclave/src/confidential/caseObject';
import { prepareOwnerGrant } from '../../../enclave/src/confidential/ownerGrant';

const hex = (value: number) => value.toString(16).padStart(64, '0');
const now = Date.now(), releaseDigest = hex(1), organizationId = hex(2);
let fixture: Parameters<typeof prepareOwnerGrant>[0];
let firm: Awaited<ReturnType<typeof generateKey>>['privateKey'];
let narrativeContext: { caseId: string; objectId: string; scope: 'narrative'; keyEpoch: number; objectRevision: number };

beforeAll(async () => {
  const owner = await createCaseOwner();
  firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic counsel' }], format: 'object' })).privateKey;
  const signed = async (statement: OwnerStatement) => {
    const wire = await signOwnerStatement(statement, owner.privateKey);
    return { wire, ...(await verifyOwnerStatement(wire, owner.trust)) };
  };
  narrativeContext = { caseId: owner.trust.caseId, objectId: hex(3), scope: 'narrative', keyEpoch: 1, objectRevision: 1 };
  const narrative = await sealCaseObject(narrativeContext, new TextEncoder().encode('PRIVATE-NARRATIVE'), owner.privateKey);
  const contact = await sealCaseObject({ ...narrativeContext, objectId: hex(4), scope: 'contact' },
    new TextEncoder().encode('PRIVATE-CONTACT'), owner.privateKey);
  const release = await signed({ kind: 'release', caseId: owner.trust.caseId, revision: 1, releaseDigest, issuedAt: now });
  const manifest = await signed({ kind: 'manifest', caseId: owner.trust.caseId, revision: 1, objects: [
    { objectId: hex(3), scope: 'narrative', objectRevision: 1, keyEpoch: 1, ciphertextDigest: await caseObjectDigest(narrative.ciphertext) },
    { objectId: hex(4), scope: 'contact', objectRevision: 1, keyEpoch: 1, ciphertextDigest: await caseObjectDigest(contact.ciphertext) },
  ] });
  const checkpoint = await signed({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1,
    previousDigest: null, listingDigest: null, manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: now });
  const ciphertext = await createLegalAccessRequest({ requestId: hex(5), scopes: ['narrative', 'contact'],
    objectRevisionLimit: 2, purpose: 'Synthetic review', issuedAt: now, expiresAt: now + 10000 }, organizationId, firm, owner.trust);
  fixture = { owner: owner.privateKey, trust: owner.trust, now, releaseDigest, manifest: manifest.wire,
    release: release.wire, checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest,
    directory: [{ organizationId, approved: true, publicKey: firm.toPublic() }],
    delivery: { caseId: owner.trust.caseId, organizationId, requestId: hex(5), recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
      ciphertext, expiresAt: now + 10000, status: 'pending' },
    decision: { grantId: hex(6), scopes: ['narrative'], objectRevisionLimit: 1, expiresAt: now + 86400000 },
    objects: [{ objectId: hex(3), ...narrative }, { objectId: hex(4), ...contact }] };
});

test('explicit owner selection prepares only the selected scope and preserves ciphertext', async () => {
  const prepared = await prepareOwnerGrant(fixture);
  expect(prepared.body.envelopes.map(item => item.objectId)).toEqual([hex(3)]);
  expect(prepared.body.objects).toEqual([]);
  const grant = await verifyOwnerStatement(prepared.grant, fixture.trust);
  expect(grant.statement).toMatchObject({ kind: 'grant', scopes: ['narrative'], objectRevisionLimit: 1 });
  const checkpoint = await verifyOwnerStatement(prepared.body.checkpoint, fixture.trust);
  expect(checkpoint.statement).toMatchObject({ previousDigest: fixture.checkpointDigest, revision: 2 });
  const plaintext = await openGrantedCaseObject({ ciphertext: fixture.objects[0].ciphertext,
    recipientEnvelope: prepared.body.envelopes[0].envelope }, narrativeContext, firm,
  { trust: fixture.trust, grant: prepared.grant, manifest: fixture.manifest, release: fixture.release,
    checkpoint: prepared.body.checkpoint, checkpointDigest: prepared.checkpointDigest,
    request: { organizationId, recipientKeyId: fixture.delivery.recipientKeyId, objectId: hex(3),
      ciphertextDigest: await caseObjectDigest(fixture.objects[0].ciphertext), scope: 'narrative',
      objectRevision: 1, keyEpoch: 1, releaseDigest, now } });
  expect(new TextDecoder().decode(plaintext)).toBe('PRIVATE-NARRATIVE');
  expect(JSON.stringify(prepared)).not.toContain('PRIVATE-CONTACT');
});

test.each(['scope', 'revision', 'expiry', 'checkpoint', 'release', 'missing-object', 'duplicate-object', 'withdrawn-firm', 'delivery'])
  ('refuses %s without preparing a commit', async defect => {
    const changed = { ...fixture, decision: { ...fixture.decision }, delivery: { ...fixture.delivery } };
    if (defect === 'scope') changed.decision.scopes = ['identity'];
    if (defect === 'revision') changed.decision.objectRevisionLimit = null;
    if (defect === 'expiry') changed.decision.expiresAt = now;
    if (defect === 'checkpoint') changed.checkpointDigest = hex(99);
    if (defect === 'release') changed.releaseDigest = hex(99);
    if (defect === 'missing-object') changed.objects = [];
    if (defect === 'duplicate-object') changed.objects = [fixture.objects[0], fixture.objects[0]];
    if (defect === 'withdrawn-firm') changed.directory = [{ ...fixture.directory[0], approved: false }];
    if (defect === 'delivery') changed.delivery.requestId = hex(99);
    await expect(prepareOwnerGrant(changed)).rejects.toThrow('Cannot prepare confidential access grant');
  });

test('sealed mode re-wraps the unchanged state key to owner, existing grantees and the new firm', async () => {
  const { generateCaseStateKey, findCaseStateKey } = await import('../../../enclave/src/confidential/caseStateKey');
  const existing = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Existing counsel' }], format: 'object' })).privateKey;
  const outsider = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Outsider' }], format: 'object' })).privateKey;
  const state = generateCaseStateKey(1);
  const prepared = await prepareOwnerGrant({ ...fixture, sealedState: { state, currentRecipients: [existing.toPublic()] } });
  const body = prepared.body as typeof prepared.body & { stateEnvelopes: string[]; stateKeyRotation: null };
  expect(body.stateKeyRotation).toBeNull();
  expect(body.stateEnvelopes).toHaveLength(3);
  for (const reader of [fixture.owner, existing, firm]) {
    expect((await findCaseStateKey(body.stateEnvelopes, fixture.trust.caseId, reader, fixture.trust.ownerPublicKey)).key).toEqual(state.key);
  }
  await expect(findCaseStateKey(body.stateEnvelopes, fixture.trust.caseId, outsider, fixture.trust.ownerPublicKey)).rejects.toThrow();
});

test('owner can grant from key envelopes alone; digest comes from the signed manifest', async () => {
  const envelopesOnly = fixture.objects.map(item => ({ objectId: item.objectId, ownerEnvelope: item.ownerEnvelope }));
  const prepared = await prepareOwnerGrant({ ...fixture, objects: envelopesOnly });
  const full = fixture.objects.find(item => item.objectId === hex(3))!;
  const opened = await openGrantedCaseObject({ ciphertext: (full as { ciphertext: string }).ciphertext,
    recipientEnvelope: prepared.body.envelopes[0].envelope }, narrativeContext, firm, {
    trust: fixture.trust, grant: prepared.grant, checkpoint: prepared.body.checkpoint, checkpointDigest: prepared.checkpointDigest,
    manifest: fixture.manifest, release: fixture.release, request: { organizationId, recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
      objectId: hex(3), ciphertextDigest: await caseObjectDigest((full as { ciphertext: string }).ciphertext), scope: 'narrative',
      releaseDigest, keyEpoch: 1, objectRevision: 1, now } });
  expect(new TextDecoder().decode(opened)).toBe('PRIVATE-NARRATIVE');
  // An owner envelope for a different object cannot be relabeled into this one.
  const swapped = [{ objectId: hex(3), ownerEnvelope: fixture.objects[1].ownerEnvelope }, envelopesOnly[1]];
  await expect(prepareOwnerGrant({ ...fixture, objects: swapped })).rejects.toThrow();
});
