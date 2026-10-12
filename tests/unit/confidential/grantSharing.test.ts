import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import {
  MAX_GRANT_LIFETIME_MS, authorizeCaseRead, grantActiveAt, grantCoversObject, signOwnerStatement, verifyOwnerStatement,
} from '../../../enclave/src/confidential/authorization';
import type { AccessGrant, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import {
  createLegalAccessRequest, openLegalAccessRequest, parseRequestDetails, requestWebsite,
} from '../../../enclave/src/confidential/accessRequest';
import type { AccessRequestDetails } from '../../../enclave/src/confidential/accessRequest';
import {
  caseObjectDigest, caseRecipientKeyId, openGrantedCaseObject, sealCaseObject,
} from '../../../enclave/src/confidential/caseObject';
import type { ObjectContext } from '../../../enclave/src/confidential/caseObject';
import { prepareDirectGrant, prepareGrantRenewal, prepareOwnerGrant } from '../../../enclave/src/confidential/ownerGrant';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const DAY = 86_400_000;
const now = Date.now(), releaseDigest = hex(1), organizationId = hex(2), otherOrganization = hex(3);
const DETAILS: AccessRequestDetails = { kind: 'new', conflictsChecked: true, feeBasis: 'contingency', responseTime: 'two-days',
  practiceAreas: ['Whistleblowing', 'Employment'], jurisdiction: 'New York', website: 'https://counsel.example/' };

let owner: Awaited<ReturnType<typeof createCaseOwner>>;
let firm: PrivateKey, other: PrivateKey;
let contexts: ObjectContext[];
let sealed: { objectId: string; ciphertext: string; ownerEnvelope: string }[];
let base: Parameters<typeof prepareOwnerGrant>[0];

async function signed(statement: OwnerStatement) {
  const wire = await signOwnerStatement(statement, owner.privateKey);
  return { wire, ...(await verifyOwnerStatement(wire, owner.trust)) };
}

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  owner = await createCaseOwner();
  [firm, other] = await Promise.all(['firm', 'other'].map(async name => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: `Synthetic ${name}` }], format: 'object' })).privateKey));
  const caseId = owner.trust.caseId;
  contexts = [
    { caseId, objectId: hex(0x10), scope: 'narrative', keyEpoch: 1, objectRevision: 1 },
    { caseId, objectId: hex(0x11), scope: 'contact', keyEpoch: 1, objectRevision: 1 },
    { caseId, objectId: hex(0x12), scope: 'evidence', keyEpoch: 1, objectRevision: 1 },
    { caseId, objectId: hex(0x13), scope: 'evidence', keyEpoch: 1, objectRevision: 1 },
  ];
  sealed = await Promise.all(contexts.map(async context => ({ objectId: context.objectId,
    ...await sealCaseObject(context, new TextEncoder().encode(`PRIVATE-${context.objectId.slice(-2)}`), owner.privateKey) })));
  const release = await signed({ kind: 'release', caseId, revision: 1, releaseDigest, issuedAt: now });
  const manifest = await signed({ kind: 'manifest', caseId, revision: 1, objects: await Promise.all(contexts.map(async (context, index) => ({
    objectId: context.objectId, scope: context.scope, objectRevision: 1, keyEpoch: 1, ciphertextDigest: await caseObjectDigest(sealed[index].ciphertext) }))) });
  const checkpoint = await signed({ kind: 'checkpoint', caseId, revision: 1, keyEpoch: 1, previousDigest: null, listingDigest: null,
    manifestDigest: manifest.digest, grantDigests: [], releaseDigests: [release.digest], issuedAt: now });
  const ciphertext = await createLegalAccessRequest({ requestId: hex(0x20), scopes: ['narrative', 'evidence', 'messages'],
    objectRevisionLimit: null, purpose: 'Structured review', issuedAt: now, expiresAt: now + DAY, details: DETAILS },
  organizationId, firm, owner.trust);
  base = { owner: owner.privateKey, trust: owner.trust, now, releaseDigest, manifest: manifest.wire, release: release.wire,
    checkpoint: checkpoint.wire, checkpointDigest: checkpoint.digest,
    directory: [{ organizationId, approved: true, publicKey: firm.toPublic() }],
    delivery: { caseId, organizationId, requestId: hex(0x20), recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
      ciphertext, expiresAt: now + DAY, status: 'pending' },
    decision: { grantId: hex(0x20), scopes: ['narrative', 'evidence', 'messages'], objectRevisionLimit: null, expiresAt: null },
    objects: sealed.map(item => ({ objectId: item.objectId, ownerEnvelope: item.ownerEnvelope })) };
});

async function readAs(key: PrivateKey, prepared: { grant: string; checkpointDigest: string; body: { checkpoint: string;
  envelopes: { objectId: string; envelope: string }[] } }, index: number, at = now) {
  const context = contexts[index], envelope = prepared.body.envelopes.find(item => item.objectId === context.objectId);
  if (!envelope) throw new Error('no envelope');
  const plaintext = await openGrantedCaseObject({ ciphertext: sealed[index].ciphertext, recipientEnvelope: envelope.envelope }, context, key, {
    trust: owner.trust, grant: prepared.grant, manifest: base.manifest, release: base.release, checkpoint: prepared.body.checkpoint,
    checkpointDigest: prepared.checkpointDigest, request: { organizationId, recipientKeyId: await caseRecipientKeyId(key.toPublic()),
      objectId: context.objectId, ciphertextDigest: await caseObjectDigest(sealed[index].ciphertext), scope: context.scope,
      releaseDigest, keyEpoch: 1, objectRevision: 1, now: at } });
  return new TextDecoder().decode(plaintext);
}

describe('grant schema', () => {
  const grant: AccessGrant = { kind: 'grant', caseId: hex(1), revision: 2, grantId: hex(2), organizationId: hex(3), recipientKeyId: hex(4),
    scopes: ['evidence'], keyEpoch: 1, objectRevisionLimit: null, issuedAt: now, expiresAt: null };

  test('until-revoked grants never lapse; dated grants lapse at their end', () => {
    expect(grantActiveAt(grant, now + 10 * 365 * DAY)).toBe(true);
    // Issue times from another clock are accepted within the tolerated skew, no further.
    expect(grantActiveAt(grant, now - CLOCK_SKEW_MS)).toBe(true);
    expect(grantActiveAt(grant, now - CLOCK_SKEW_MS - 1)).toBe(false);
    expect(grantActiveAt({ ...grant, expiresAt: now + 5 }, now + 5)).toBe(false);
  });

  test('exclusions, revision limits and scopes decide coverage', () => {
    const entry = { objectId: hex(9), scope: 'evidence' as const, objectRevision: 3 };
    expect(grantCoversObject(grant, entry)).toBe(true);
    expect(grantCoversObject({ ...grant, excludedObjectIds: [hex(9)] }, entry)).toBe(false);
    expect(grantCoversObject({ ...grant, objectRevisionLimit: 2 }, entry)).toBe(false);
    expect(grantCoversObject({ ...grant, scopes: ['narrative'] }, entry)).toBe(false);
  });

  test('canonical encoding: exclusions sorted and non-empty; legacy grants keep their digest', async () => {
    const legacy = await signed({ ...grant, caseId: owner.trust.caseId, expiresAt: now + DAY });
    expect(JSON.parse(legacy.wire).statement).not.toHaveProperty('excludedObjectIds');
    const withExclusions = await signed({ ...grant, caseId: owner.trust.caseId, excludedObjectIds: [hex(5), hex(6)] });
    expect((withExclusions.statement as AccessGrant).excludedObjectIds).toEqual([hex(5), hex(6)]);
    for (const bad of [[], [hex(6), hex(5)], [hex(5), hex(5)], ['nope']]) {
      await expect(signOwnerStatement({ ...grant, caseId: owner.trust.caseId, excludedObjectIds: bad }, owner.privateKey)).rejects.toThrow();
    }
    await expect(signOwnerStatement({ ...grant, caseId: owner.trust.caseId, expiresAt: now + MAX_GRANT_LIFETIME_MS + 1 },
      owner.privateKey)).rejects.toThrow();
  });
});

describe('structured access requests', () => {
  test('details are signed, encrypted to the owner and parsed back exactly', async () => {
    const ciphertext = base.delivery.ciphertext;
    expect(ciphertext).not.toContain('Whistleblowing');
    const opened = await openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, base.directory, now);
    expect(opened.format).toBe('vera-legal-access-request/v2');
    expect(opened.details).toEqual(DETAILS);
  });

  test('legacy v1 requests still open with details: null', async () => {
    const ciphertext = await createLegalAccessRequest({ requestId: hex(0x21), scopes: ['narrative'], objectRevisionLimit: null,
      purpose: 'Legacy', issuedAt: now, expiresAt: now + DAY }, organizationId, firm, owner.trust);
    const opened = await openLegalAccessRequest(ciphertext, owner.trust.caseId, owner.privateKey, base.directory, now);
    expect([opened.format, opened.details]).toEqual(['vera-legal-access-request/v1', null]);
  });

  test.each([
    ['unknown fee basis', { feeBasis: 'free-lunch' }], ['unknown reply time', { responseTime: 'soon' }],
    ['too many practice areas', { practiceAreas: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] }],
    ['duplicate practice area', { practiceAreas: ['Tax', 'Tax'] }], ['multi-line jurisdiction', { jurisdiction: 'A\nB' }],
    ['http website', { website: 'http://counsel.example/' }], ['credentials in website', { website: 'https://u:p@counsel.example/' }],
    ['javascript website', { website: 'javascript:alert(1)' }], ['extra field', { phone: '555' }],
    ['kind', { kind: 'other' }], ['conflicts as text', { conflictsChecked: 'yes' }],
  ])('refuses %s', async (_name, change) => {
    expect(() => parseRequestDetails({ ...DETAILS, ...change })).toThrow();
    await expect(createLegalAccessRequest({ requestId: hex(0x22), scopes: ['narrative'], objectRevisionLimit: null, purpose: 'x',
      issuedAt: now, expiresAt: now + DAY, details: { ...DETAILS, ...change } as AccessRequestDetails }, organizationId, firm, owner.trust)).rejects.toThrow();
  });

  test('websites are normalized https pages only', () => {
    expect(requestWebsite(null)).toBeNull();
    expect(requestWebsite('https://counsel.example/about')).toBe('https://counsel.example/about');
    expect(() => requestWebsite('https://counsel.example:8443/')).toThrow();
    expect(() => requestWebsite('https://COUNSEL.example/')).toThrow(); // Not in canonical form.
  });
});

describe('owner grant preparation', () => {
  test('"until revoked" and only some files: excluded files and contact get no envelope', async () => {
    const prepared = await prepareOwnerGrant({ ...base, decision: { ...base.decision, excludedObjectIds: [hex(0x13)] } });
    const grant = (await verifyOwnerStatement(prepared.grant, owner.trust)).statement as AccessGrant;
    expect(grant).toMatchObject({ expiresAt: null, excludedObjectIds: [hex(0x13)] });
    expect(prepared.body.envelopes.map(item => item.objectId).sort()).toEqual([hex(0x10), hex(0x12)]);
    await expect(readAs(firm, prepared, 2, now + 1000 * DAY)).resolves.toBe('PRIVATE-12');
    // The excluded file is refused by the read authorization itself, not only by missing keys.
    await expect(authorizeCaseRead({ trust: owner.trust, grant: prepared.grant, manifest: base.manifest, release: base.release,
      checkpoint: prepared.body.checkpoint, checkpointDigest: prepared.checkpointDigest, request: { organizationId,
        recipientKeyId: base.delivery.recipientKeyId, objectId: hex(0x13), ciphertextDigest: await caseObjectDigest(sealed[3].ciphertext),
        scope: 'evidence', releaseDigest, keyEpoch: 1, objectRevision: 1, now } })).rejects.toThrow();
  });

  test.each([
    ['exclusion outside the manifest', { excludedObjectIds: [hex(0x99)] }],
    ['exclusion of an ungranted scope', { excludedObjectIds: [hex(0x11)] }],
    ['expiry beyond the longest term', { expiresAt: now + MAX_GRANT_LIFETIME_MS + 1 }],
    ['expiry in the past', { expiresAt: now }], ['empty exclusion list', { excludedObjectIds: [] }],
  ])('refuses %s', async (_name, change) => {
    await expect(prepareOwnerGrant({ ...base, decision: { ...base.decision, ...change } })).rejects.toThrow('Cannot prepare');
  });

  test('replacing grants is limited to current grants of the same organization', async () => {
    const first = await prepareOwnerGrant(base);
    const foreign = await signed({ kind: 'grant', caseId: owner.trust.caseId, revision: 1, grantId: hex(0x30), organizationId: otherOrganization,
      recipientKeyId: await caseRecipientKeyId(other.toPublic()), scopes: ['narrative'], keyEpoch: 1, objectRevisionLimit: null,
      issuedAt: now, expiresAt: null });
    await expect(prepareOwnerGrant({ ...base, replacedGrants: [foreign.wire] })).rejects.toThrow('Cannot prepare');
    // A grant not in the current checkpoint cannot be "replaced" either.
    await expect(prepareOwnerGrant({ ...base, replacedGrants: [first.grant] })).rejects.toThrow('Cannot prepare');
    const next = { ...base, checkpoint: first.body.checkpoint, checkpointDigest: first.checkpointDigest };
    const replaced = await prepareOwnerGrant({ ...next, replacedGrants: [first.grant],
      decision: { ...base.decision, scopes: ['narrative'], expiresAt: now + 30 * DAY } });
    const checkpoint = (await verifyOwnerStatement(replaced.body.checkpoint, owner.trust)).statement;
    expect(checkpoint).toMatchObject({ kind: 'checkpoint', grantDigests: [(await verifyOwnerStatement(replaced.grant, owner.trust)).digest] });
  });

  test('direct contact grant wraps only contact objects for the verified key', async () => {
    const first = await prepareOwnerGrant(base);
    const next = { ...base, checkpoint: first.body.checkpoint, checkpointDigest: first.checkpointDigest };
    const contact = await prepareDirectGrant({ ...next, organization: { organizationId, publicKey: firm.toPublic() },
      decision: { grantId: hex(0x40), scopes: ['contact'], objectRevisionLimit: null, expiresAt: null } });
    expect(contact.body.envelopes.map(item => item.objectId)).toEqual([hex(0x11)]);
    await expect(readAs(firm, contact, 1)).resolves.toBe('PRIVATE-11');
    const checkpoint = (await verifyOwnerStatement(contact.body.checkpoint, owner.trust)).statement;
    expect((checkpoint as { grantDigests: string[] }).grantDigests).toHaveLength(2);
  });

  test('a new Allow replaces report access and moves kept contact sharing to the same end', async () => {
    const first = await prepareOwnerGrant({ ...base, decision: { ...base.decision, expiresAt: now + 7 * DAY } });
    const afterFirst = { ...base, checkpoint: first.body.checkpoint, checkpointDigest: first.checkpointDigest };
    const contact = await prepareDirectGrant({ ...afterFirst, organization: { organizationId, publicKey: firm.toPublic() },
      decision: { grantId: hex(0x41), scopes: ['contact'], objectRevisionLimit: null, expiresAt: now + 7 * DAY } });
    const next = { ...base, now: now + 1000, checkpoint: contact.body.checkpoint, checkpointDigest: contact.checkpointDigest };
    const allowed = await prepareOwnerGrant({ ...next, replacedGrants: [first.grant], realignedGrants: [contact.grant],
      decision: { ...base.decision, scopes: ['narrative'], expiresAt: null } });
    expect(allowed.body.statements).toHaveLength(2);
    const [realignedWire] = allowed.body.statements;
    const realigned = (await verifyOwnerStatement(realignedWire, owner.trust)).statement as AccessGrant;
    const oldContact = (await verifyOwnerStatement(contact.grant, owner.trust)).statement as AccessGrant;
    expect(realigned).toEqual({ ...oldContact, revision: oldContact.revision + 1, issuedAt: now + 1000, expiresAt: null });
    const checkpoint = (await verifyOwnerStatement(allowed.body.checkpoint, owner.trust)).statement as { grantDigests: string[] };
    expect(checkpoint.grantDigests).toEqual([(await verifyOwnerStatement(realignedWire, owner.trust)).digest,
      (await verifyOwnerStatement(allowed.grant, owner.trust)).digest]);
    // Fresh envelopes: the report for the new grant, contact for the re-signed one.
    expect(allowed.body.envelopes.map(item => item.objectId).sort()).toEqual([hex(0x10), hex(0x11)]);
    await expect(readAs(firm, { grant: realignedWire, checkpointDigest: allowed.checkpointDigest, body: allowed.body }, 1, now + 100 * DAY))
      .resolves.toBe('PRIVATE-11');
    // The same grant cannot be both replaced and kept, and only current grants of this organization key qualify.
    await expect(prepareOwnerGrant({ ...next, replacedGrants: [contact.grant], realignedGrants: [contact.grant] })).rejects.toThrow('Cannot prepare');
    await expect(prepareOwnerGrant({ ...next, realignedGrants: [first.body.statements[0], first.body.statements[0]] })).rejects.toThrow('Cannot prepare');
    const foreign = await signed({ kind: 'grant', caseId: owner.trust.caseId, revision: 1, grantId: hex(0x31), organizationId: otherOrganization,
      recipientKeyId: await caseRecipientKeyId(other.toPublic()), scopes: ['contact'], keyEpoch: 1, objectRevisionLimit: null,
      issuedAt: now, expiresAt: null });
    await expect(prepareOwnerGrant({ ...next, realignedGrants: [foreign.wire] })).rejects.toThrow('Cannot prepare');
  });

  test('renewal re-signs the same access with a new end and fresh envelopes', async () => {
    const dated = await prepareOwnerGrant({ ...base, decision: { ...base.decision, expiresAt: now + 7 * DAY, excludedObjectIds: [hex(0x12)] } });
    const next = { ...base, checkpoint: dated.body.checkpoint, checkpointDigest: dated.checkpointDigest };
    const renewal = await prepareGrantRenewal({ ...next, now: now + 1000, organization: { organizationId, publicKey: firm.toPublic() },
      grants: [dated.grant], expiresAt: null });
    const [wire] = renewal.body.statements;
    const renewed = (await verifyOwnerStatement(wire, owner.trust)).statement as AccessGrant;
    const old = (await verifyOwnerStatement(dated.grant, owner.trust)).statement as AccessGrant;
    expect(renewed).toEqual({ ...old, revision: old.revision + 1, issuedAt: now + 1000, expiresAt: null });
    expect(renewal.body.envelopes.map(item => item.objectId).sort()).toEqual([hex(0x10), hex(0x13)]);
    await expect(readAs(firm, { grant: wire, checkpointDigest: renewal.checkpointDigest, body: renewal.body }, 3, now + 100 * DAY))
      .resolves.toBe('PRIVATE-13');
    // Old envelopes are bound to the old grant and do not open under the renewed one.
    await expect(readAs(firm, { grant: wire, checkpointDigest: renewal.checkpointDigest, body: { ...renewal.body,
      envelopes: dated.body.envelopes } }, 3, now + 2000)).rejects.toThrow();
    // A different key (for example a rotated firm key) cannot inherit the grant.
    await expect(prepareGrantRenewal({ ...next, organization: { organizationId, publicKey: other.toPublic() }, grants: [dated.grant],
      expiresAt: null })).rejects.toThrow('Cannot prepare');
    await expect(prepareGrantRenewal({ ...next, organization: { organizationId, publicKey: firm.toPublic() }, grants: [dated.grant],
      expiresAt: now + MAX_GRANT_LIFETIME_MS + 1 })).rejects.toThrow('Cannot prepare');
  });
});
