import * as pgp from '../../../enclave/src/confidential/pgp';
import { webcrypto } from 'node:crypto';
import { CLOCK_SKEW_MS } from '../../../enclave/src/confidential/clockSkew';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey, PublicKey } from '../../../enclave/src/confidential/pgp';
import {
  authorizeCaseRead, createCaseReadAuthorizer, signOwnerStatement, verifiedListing, verifyOwnerStatement,
} from '../../../enclave/src/confidential/authorization';
import type {
  AccessGrant, CaseCheckpoint, CaseReadRequest, ManifestEntry, OwnerStatement, OwnerTrust, ReleaseApproval,
} from '../../../enclave/src/confidential/authorization';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const now = Date.now();
const grant: AccessGrant = {
  kind: 'grant', caseId: hex(1), revision: 2, grantId: hex(2), organizationId: hex(3),
  recipientKeyId: hex(4), scopes: ['narrative', 'evidence'], keyEpoch: 1,
  objectRevisionLimit: null, issuedAt: now - 1_000, expiresAt: now + 60_000,
};
const release: ReleaseApproval = {
  kind: 'release', caseId: hex(1), revision: 1, releaseDigest: hex(5), issuedAt: now - 1_000,
};
const request: CaseReadRequest = {
  organizationId: hex(3), recipientKeyId: hex(4), objectId: hex(6), ciphertextDigest: hex(7), scope: 'evidence',
  releaseDigest: hex(5), keyEpoch: 1, objectRevision: 3, now,
};
const entry: ManifestEntry = { objectId: hex(6), scope: 'evidence', objectRevision: 3, keyEpoch: 1, ciphertextDigest: hex(7) };
let owner: PrivateKey, other: PrivateKey, publicKey: PublicKey, trust: OwnerTrust;

beforeAll(async () => {
  // Node runs the same Web Crypto digest used by browsers; cryptography is not mocked.
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  const keys = await Promise.all(['owner', 'other'].map(name => generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }], format: 'object',
  })));
  owner = keys[0].privateKey;
  publicKey = keys[0].publicKey;
  other = keys[1].privateKey;
  trust = { caseId: hex(1), ownerFingerprint: publicKey.getFingerprint(), ownerPublicKey: publicKey };
});

async function signed(statement: OwnerStatement) {
  const wire = await signOwnerStatement(statement, owner);
  return { wire, ...await verifyOwnerStatement(wire, trust) };
}

async function fixture(grantChange: Partial<AccessGrant> = {}, stateChange: Partial<CaseCheckpoint> = {},
  entries: ManifestEntry[] = [entry]) {
  const g = await signed({ ...grant, ...grantChange });
  const r = await signed(release);
  const m = await signed({ kind: 'manifest', caseId: hex(1), revision: 3, objects: entries });
  const c = await signed({ kind: 'checkpoint', caseId: hex(1), revision: 3, keyEpoch: 1, previousDigest: null,
    listingDigest: null, manifestDigest: m.digest, issuedAt: now, grantDigests: [g.digest],
    releaseDigests: [r.digest], ...stateChange });
  return { grant: g.wire, release: r.wire, manifest: m.wire, checkpoint: c.wire, checkpointDigest: c.digest, trust, request };
}

describe('participant-owned case authorization', () => {
  // Reject extra listing fields even when the owner offers to sign them.
  test.each([{ publishedAt: '2026-09-28' }, { publishedAt: -1 }, { publishedAt: 1.5 }, { publishedAt: 8_640_000_000_000_001 }, { publishedAt: null }, { hasAttachments: 'yes' }, { hasAttachments: 1 }, { hasAttachments: null }, { category: 'financial-fraud' }, { region: 'europe' }, { category: 'fraud' }, { category: null }, { region: 'us-west' }, { region: 'Springfield, IL' },
    { location: 'Portland' }, { region: 'europe', location: 'Portland' }])('refuses extra public listing fields rather than silently stripping them: %j', async extra => {
    await expect(signOwnerStatement({ kind: 'listing', caseId: hex(1), revision: 1,
      summary: 'Public summary', ...extra } as OwnerStatement, owner)).rejects.toThrow();
  });

  test('owner approves an exact firm, disclosure scope, and backend release', async () => {
    await expect(authorizeCaseRead(await fixture())).resolves.toBeUndefined();
  });

  test('public listing exposes only the approved summary and opaque identifier', async () => {
    const listing = await signed({ kind: 'listing', caseId: hex(1), revision: 1,
      summary: 'Potential procurement irregularities. Seeking independent legal review.' });
    const current = await signed({ kind: 'checkpoint', caseId: hex(1), revision: 1, keyEpoch: 1, previousDigest: null,
      listingDigest: listing.digest, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: now });
    expect(await verifiedListing(listing.wire, current.wire, trust)).toEqual({
      caseId: hex(1), summary: 'Potential procurement irregularities. Seeking independent legal review.', revision: 1,
    });
    const g = await signed(grant);
    await expect(verifiedListing(g.wire, current.wire, trust)).rejects.toThrow('Invalid confidential authorization');
  });

  test('an older or withdrawn summary is not current even though its signature is valid', async () => {
    const old = await signed({ kind: 'listing', caseId: hex(1), revision: 1, summary: 'Mentions a unique role' });
    const edited = await signed({ kind: 'listing', caseId: hex(1), revision: 2, summary: 'Generic summary' });
    const current = await signed({ kind: 'checkpoint', caseId: hex(1), revision: 2, keyEpoch: 1, previousDigest: null,
      listingDigest: edited.digest, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: now });
    const withdrawn = await signed({ kind: 'checkpoint', caseId: hex(1), revision: 3, keyEpoch: 1,
      previousDigest: current.digest, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [], issuedAt: now });
    await expect(verifiedListing(old.wire, current.wire, trust)).rejects.toThrow();
    await expect(verifiedListing(edited.wire, current.wire, trust)).resolves.toMatchObject({ summary: 'Generic summary' });
    await expect(verifiedListing(edited.wire, withdrawn.wire, trust)).rejects.toThrow();
  });

  test('host cannot withhold, relabel, or replay objects outside the owner manifest', async () => {
    const input = await fixture();
    for (const change of [{ objectId: hex(99) }, { ciphertextDigest: hex(99) }, { scope: 'identity' as const },
      { objectRevision: 2 }]) {
      await expect(authorizeCaseRead({ ...input, request: { ...request, ...change } })).rejects.toThrow();
    }
    const otherManifest = await fixture({}, {}, [{ ...entry, ciphertextDigest: hex(98) }]);
    await expect(authorizeCaseRead({ ...input, manifest: otherManifest.manifest })).rejects.toThrow();
  });

  test('objects sealed under an earlier epoch stay readable by a still-current re-signed grant', async () => {
    const input = await fixture({ keyEpoch: 2 }, { keyEpoch: 2 });
    await expect(authorizeCaseRead(input)).resolves.toBeUndefined();
    const future = await fixture({ keyEpoch: 2 }, { keyEpoch: 2 }, [{ ...entry, keyEpoch: 3 }]);
    await expect(authorizeCaseRead({ ...future, request: { ...request, keyEpoch: 3 } })).rejects.toThrow();
  });

  test.each([
    ['case', { caseId: hex(999) }], ['recipient', { recipientKeyId: hex(999) }],
    ['scope', { scopes: ['identity'] }], ['epoch', { keyEpoch: 2 }],
    ['expiry', { expiresAt: now + 600_000 }], ['future access', { objectRevisionLimit: 2 }],
  ])('rejects modification of signed %s', async (_name, change) => {
    const value = JSON.parse((await signed(grant)).wire);
    Object.assign(value.statement, change);
    await expect(verifyOwnerStatement(JSON.stringify(value), trust)).rejects.toThrow('Invalid confidential authorization');
  });

  test('rejects a real signature from a substituted owner, including a forged pinned fingerprint', async () => {
    const forged = JSON.parse(await signOwnerStatement(grant, other));
    await expect(verifyOwnerStatement(JSON.stringify(forged), trust)).rejects.toThrow();
    forged.ownerFingerprint = trust.ownerFingerprint;
    await expect(verifyOwnerStatement(JSON.stringify(forged), trust)).rejects.toThrow();
    await expect(verifyOwnerStatement((await signed(grant)).wire, {
      ...trust, ownerPublicKey: other.toPublic(),
    })).rejects.toThrow();
  });

  test('rejects a correctly signed grant replayed in another case', async () => {
    await expect(verifyOwnerStatement((await signed(grant)).wire, {
      ...trust, caseId: hex(999),
    })).rejects.toThrow();
  });

  test.each([
    ['organization', { organizationId: hex(999) }], ['recipient', { recipientKeyId: hex(999) }],
    ['identity disclosure', { scope: 'identity' as const }], ['contact disclosure', { scope: 'contact' as const }],
    ['backend release', { releaseDigest: hex(999) }], ['key epoch', { keyEpoch: 2 }],
    ['expired grant', { now: grant.expiresAt }],
    ['future approval', { now: now - CLOCK_SKEW_MS - 1 }],
  ])('rejects an authentic grant used with a different %s', async (_name, change) => {
    const input = await fixture();
    await expect(authorizeCaseRead({ ...input, request: { ...request, ...change } })).rejects.toThrow();
  });

  test('accepts a grant signed on an owner device whose clock is ahead within the tolerated skew', async () => {
    const input = await fixture();
    await expect(authorizeCaseRead({ ...input, request: { ...request, now: now - CLOCK_SKEW_MS + 1_000 } })).resolves.toBeUndefined();
  });

  test('current checkpoint revokes an otherwise valid grant', async () => {
    await expect(authorizeCaseRead(await fixture({}, { grantDigests: [] }))).rejects.toThrow();
  });

  test('current checkpoint withdraws a previously owner-approved release', async () => {
    await expect(authorizeCaseRead(await fixture({}, { releaseDigests: [] }))).rejects.toThrow();
  });

  test('old correctly signed checkpoint fails against the authenticated current digest', async () => {
    const old = await fixture();
    const current = await fixture({}, { revision: 4, keyEpoch: 2, grantDigests: [] });
    await expect(authorizeCaseRead({ ...old, checkpointDigest: current.checkpointDigest })).rejects.toThrow();
  });

  test('reusing a grant id with different terms does not match the approved grant payload', async () => {
    const input = await fixture();
    const changed = await signed({ ...grant, scopes: ['identity'], revision: 3 });
    await expect(authorizeCaseRead({ ...input, grant: changed.wire,
      request: { ...request, scope: 'identity' } })).rejects.toThrow();
  });

  test('snapshot-only grant excludes future objects but permits the approved snapshot', async () => {
    const input = await fixture({ objectRevisionLimit: 2 }, {}, [entry, { ...entry, objectId: hex(8), objectRevision: 2 }]);
    await expect(authorizeCaseRead(input)).rejects.toThrow();
    await expect(authorizeCaseRead({ ...input, request: { ...request, objectId: hex(8), objectRevision: 2 } })).resolves.toBeUndefined();
  });

  test('future-inclusive grant permits later objects without another policy approval', async () => {
    const input = await fixture({}, {}, [{ ...entry, objectRevision: 100 }]);
    await expect(authorizeCaseRead({ ...input, request: { ...request, objectRevision: 100 } })).resolves.toBeUndefined();
  });

  test('checkpoint cannot predate the grant or release it purports to authorize', async () => {
    await expect(authorizeCaseRead(await fixture({}, { revision: 1 }))).rejects.toThrow();
  });

  test('a grant signature cannot stand in for a separate release approval', async () => {
    const input = await fixture();
    await expect(authorizeCaseRead({ ...input, release: input.grant })).rejects.toThrow();
  });

  test('canonical payload digest does not depend on signature bytes or JSON key order', async () => {
    const first = await signed(grant);
    const second = await signed(grant);
    expect(second.digest).toBe(first.digest);
    const value = JSON.parse(first.wire);
    value.statement = Object.fromEntries(Object.entries(value.statement).reverse());
    expect((await verifyOwnerStatement(JSON.stringify(value), trust)).digest).toBe(first.digest);
  });

  test('signing snapshots the approved fields before asynchronous work', async () => {
    const input = { ...grant, scopes: [...grant.scopes] };
    const result = signOwnerStatement(input, owner);
    input.scopes.push('identity');
    input.recipientKeyId = hex(999);
    expect((await verifyOwnerStatement(await result, trust)).statement).toEqual(grant);
  });

  test.each([
    { ...grant, adminOverride: true }, { ...grant, revision: 1.1 }, { ...grant, revision: Number.MAX_SAFE_INTEGER + 1 },
    { ...grant, scopes: [] }, { ...grant, scopes: ['evidence', 'evidence'] }, { ...grant, scopes: ['*'] },
    { ...grant, objectRevisionLimit: 0 }, { ...grant, objectRevisionLimit: true },
    { ...grant, expiresAt: grant.issuedAt }, { ...grant, caseId: 'legacy-report-id' },
    { kind: 'listing', caseId: hex(1), revision: 1, summary: '' },
    { kind: 'listing', caseId: hex(1), revision: 1, summary: ' ' },
    { kind: 'listing', caseId: hex(1), revision: 1, summary: 'x'.repeat(601) },
    { kind: 'listing', caseId: hex(1), revision: 1, summary: 'Safe', narrative: 'PRIVATE' },
    { kind: 'manifest', caseId: hex(1), revision: 1, objects: [entry, entry] },
    { kind: 'manifest', caseId: hex(1), revision: 1, objects: [{ ...entry, filename: 'PRIVATE.pdf' }] },
    { kind: 'checkpoint', caseId: hex(1), revision: 1, keyEpoch: 1, listingDigest: null, manifestDigest: null,
      grantDigests: [], releaseDigests: [], issuedAt: now },
  ])('rejects malformed or overbroad statement %#', async input => {
    await expect(signOwnerStatement(input as OwnerStatement, owner)).rejects.toThrow();
  });

  test('rejects unknown versions, unsigned records, extra fields, oversized input and malformed signatures', async () => {
    const original = JSON.parse((await signed(grant)).wire);
    for (const value of [
      { ...original, protocol: 'vera-owner-authorization/v2' },
      { ...original, signature: '' }, { ...original, signature: 'PRIVATE-SENTINEL' },
      { ...original, admin: true }, { ...original, statement: { ...original.statement, admin: true } },
    ]) {
      await expect(verifyOwnerStatement(JSON.stringify(value), trust)).rejects.toThrow('Invalid confidential authorization');
    }
    await expect(verifyOwnerStatement('x'.repeat(65_537), trust)).rejects.toThrow('Invalid confidential authorization');
    await expect(verifyOwnerStatement('PRIVATE-SENTINEL', trust)).rejects.toThrow('Invalid confidential authorization');
  });
});


describe('operation-local case read authorizer', () => {
  test('256 objects times 64 denied grants verify only 67 distinct wires', async () => {
    const objects = Array.from({ length: 256 }, (_, i) => ({ ...entry, objectId: hex(1000 + i), scope: 'narrative' as const }));
    const grants = await Promise.all(Array.from({ length: 64 }, (_, i) => signed({ ...grant,
      grantId: hex(2000 + i), scopes: ['evidence'] })));
    const r = await signed(release);
    const m = await signed({ kind: 'manifest', caseId: trust.caseId, revision: 3, objects });
    const c = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 3, keyEpoch: 1, previousDigest: null,
      listingDigest: null, manifestDigest: m.digest, issuedAt: now, grantDigests: grants.map(g => g.digest), releaseDigests: [r.digest] });
    const verify = jest.spyOn(pgp, 'verify');
    try {
      const authorize = createCaseReadAuthorizer(trust);
      let denied = 0;
      for (const object of objects) for (const g of grants) {
        try {
          await authorize({ grant: g.wire, release: r.wire, manifest: m.wire, checkpoint: c.wire,
            checkpointDigest: c.digest, request: { ...request, ...object } });
        } catch { denied++; }
      }
      expect(denied).toBe(256 * 64);
      expect(verify).toHaveBeenCalledTimes(67);
    } finally { verify.mockRestore(); }
  });

  test('a warm cache rechecks time, recipient, object scope, revision and current checkpoint', async () => {
    const input = await fixture();
    const authorize = createCaseReadAuthorizer(trust);
    await expect(authorize(input)).resolves.toBeUndefined();
    for (const change of [
      { now: grant.expiresAt! }, { organizationId: hex(999) }, { recipientKeyId: hex(999) },
      { scope: 'identity' as const }, { objectRevision: 999 }, { keyEpoch: 2 },
      { releaseDigest: hex(999) }, { ciphertextDigest: hex(999) },
    ]) {
      await expect(authorize({ ...input, request: { ...request, ...change } })).rejects.toThrow();
    }
    await expect(authorize({ ...input, checkpointDigest: hex(999) })).rejects.toThrow();
    const revoked = await signed({ kind: 'checkpoint', caseId: trust.caseId, revision: 4, keyEpoch: 1,
      previousDigest: input.checkpointDigest, listingDigest: null,
      manifestDigest: (await verifyOwnerStatement(input.manifest, trust)).digest,
      grantDigests: [], releaseDigests: [(await verifyOwnerStatement(input.release, trust)).digest], issuedAt: now });
    await expect(authorize({ ...input, checkpoint: revoked.wire, checkpointDigest: revoked.digest })).rejects.toThrow();
  });

  test('changed wires are verified and a new operation cannot inherit another owner trust', async () => {
    const input = await fixture();
    const authorize = createCaseReadAuthorizer(trust);
    await authorize(input);
    const forged = JSON.parse(input.grant);
    forged.statement.scopes = ['identity'];
    await expect(authorize({ ...input, grant: JSON.stringify(forged) })).rejects.toThrow();
    await expect(createCaseReadAuthorizer({ ...trust, caseId: hex(999) })(input)).rejects.toThrow();
    await expect(createCaseReadAuthorizer({ ...trust, ownerPublicKey: other.toPublic(),
      ownerFingerprint: other.getFingerprint() })(input)).rejects.toThrow();
  });
});


test('cached authorization preserves exclusions and revision limits after a successful read', async () => {
  const otherEntry = { ...entry, objectId: hex(88), objectRevision: 4 };
  for (const constraint of [{ excludedObjectIds: [otherEntry.objectId] }, { objectRevisionLimit: 3 }]) {
    const input = await fixture(constraint, {}, [entry, otherEntry]);
    const authorize = createCaseReadAuthorizer(trust);
    await expect(authorize(input)).resolves.toBeUndefined();
    await expect(authorize({ ...input, request: { ...request, ...otherEntry } })).rejects.toThrow();
  }
});

test('the standalone participant predicate still verifies every call independently', async () => {
  const input = await fixture();
  const verify = jest.spyOn(pgp, 'verify');
  try {
    await authorizeCaseRead(input);
    await authorizeCaseRead(input);
    expect(verify).toHaveBeenCalledTimes(8);
  } finally { verify.mockRestore(); }
});
