import { webcrypto } from 'node:crypto';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { AccessGrant, CaseCheckpoint, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { buildOwnerTimeline, formatDay, ownerJourney } from '../../../lib/confidential/ownerTimeline';
import type { OwnerHistoryEntry, OwnerThread, VerifiedOrganization, VerifiedRequest, CurrentGrantee } from '../../../lib/confidential/ownerCase';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 8, 1);

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

/** A real owner-signed, hash-linked history built step by step. */
async function history() {
  const owner = await createCaseOwner();
  const caseId = owner.trust.caseId;
  const statements: Record<string, string> = {};
  const sign = async (statement: OwnerStatement) => {
    const wire = await signOwnerStatement(statement, owner.privateKey);
    const { digest } = await verifyOwnerStatement(wire, owner.trust);
    statements[digest] = wire;
    return digest;
  };
  const entries: OwnerHistoryEntry[] = [];
  let current: CaseCheckpoint | null = null;
  const commit = async (changes: Partial<CaseCheckpoint>, at: number) => {
    const next = { kind: 'checkpoint', caseId, keyEpoch: 1, listingDigest: null, manifestDigest: null, grantDigests: [],
      releaseDigests: [], ...(current ?? {}), ...changes, revision: (current?.revision ?? 0) + 1,
      previousDigest: entries.length ? entries[entries.length - 1].digest : null, issuedAt: at } as CaseCheckpoint;
    const wire = await signOwnerStatement(next, owner.privateKey);
    const { digest } = await verifyOwnerStatement(wire, owner.trust);
    entries.push({ digest, wire, checkpoint: next });
    current = next;
  };
  const evidence = (n: number, revision: number) => ({ objectId: hex(0x100 + n), scope: 'evidence' as const, objectRevision: revision,
    keyEpoch: 1, ciphertextDigest: hex(0x200 + n) });
  const narrative = { objectId: hex(0x99), scope: 'narrative' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(0x98) };

  const firmKey = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Alpha' }], format: 'object' })).privateKey;
  const otherKey = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Bravo' }], format: 'object' })).privateKey;
  const alpha: VerifiedOrganization = { organizationId: hex(0xa1), publicKey: firmKey.toPublic(), approved: true, displayName: 'Alpha LLP', domain: 'alpha.example' };
  const bravo: VerifiedOrganization = { organizationId: hex(0xb1), publicKey: otherKey.toPublic(), approved: true, displayName: 'Bravo LLP', domain: 'bravo.example' };
  const grant = async (organization: VerifiedOrganization, grantId: number, issuedAt: number, expiresAt: number, revision: number) =>
    sign({ kind: 'grant', caseId, revision, grantId: hex(grantId), organizationId: organization.organizationId,
      recipientKeyId: await caseRecipientKeyId(organization.publicKey), scopes: ['narrative', 'evidence', 'messages'], keyEpoch: 1,
      objectRevisionLimit: null, issuedAt, expiresAt } as AccessGrant);

  const listing1 = await sign({ kind: 'listing', caseId, revision: 1, summary: 'First summary' });
  const release1 = await sign({ kind: 'release', caseId, revision: 1, releaseDigest: hex(0x5e1), issuedAt: T0 });
  const manifest1 = await sign({ kind: 'manifest', caseId, revision: 1, objects: [narrative, evidence(1, 1)] });
  await commit({ listingDigest: listing1, manifestDigest: manifest1, releaseDigests: [release1] }, T0);
  const alphaGrant = await grant(alpha, 0x71, T0 + DAY, T0 + 31 * DAY, 2);
  await commit({ grantDigests: [alphaGrant] }, T0 + DAY);
  const manifest3 = await sign({ kind: 'manifest', caseId, revision: 3, objects: [narrative, evidence(1, 1), evidence(2, 3), evidence(3, 3)] });
  await commit({ manifestDigest: manifest3 }, T0 + 2 * DAY);
  const listing4 = await sign({ kind: 'listing', caseId, revision: 4, summary: 'Edited summary' });
  await commit({ listingDigest: listing4 }, T0 + 3 * DAY);
  await commit({ grantDigests: [], keyEpoch: 1 }, T0 + 4 * DAY);
  await commit({ listingDigest: null }, T0 + 5 * DAY);
  const release7 = await sign({ kind: 'release', caseId, revision: 7, releaseDigest: hex(0x5e2), issuedAt: T0 + 6 * DAY });
  await commit({ releaseDigests: [release1, release7] }, T0 + 6 * DAY);
  // Bravo: open-ended grant, later replaced by a shorter one (a change, not a revoke).
  const bravoOpen = await grant(bravo, 0x72, T0 + 7 * DAY, T0 + 7 * DAY + 400 * DAY, 8);
  await commit({ grantDigests: [bravoOpen] }, T0 + 7 * DAY);
  const bravoShort = await grant(bravo, 0x73, T0 + 8 * DAY, T0 + 9 * DAY, 9);
  await commit({ grantDigests: [bravoShort] }, T0 + 8 * DAY);
  return { owner, entries, statements, alpha, bravo, current: current! };
}

describe('owner timeline from the verified checkpoint chain', () => {
  test('records each signed change with the organization named by its domain-confirmed key', async () => {
    const { owner, entries, statements, alpha, bravo, current } = await history();
    const request = { delivery: {} as VerifiedRequest['delivery'], organization: alpha,
      request: { requestId: hex(0xabc), issuedAt: T0 + 10 * DAY } as VerifiedRequest['request'] } as VerifiedRequest;
    const threads: OwnerThread[] = [{ organization: alpha, canSend: true, messages: [
      { sender: 'organization', sequence: 1, sentAt: T0 + 1.5 * DAY, body: 'PRIVATE BODY' },
      { sender: 'owner', sequence: 1, sentAt: T0 + 1.6 * DAY, body: 'PRIVATE REPLY' },
    ] as OwnerThread['messages'] }];
    const now = T0 + 11 * DAY;
    const timeline = await buildOwnerTimeline({ trust: owner.trust, history: entries, statements,
      roster: [alpha, bravo], requests: [request], threads, now });
    expect(timeline.incomplete).toBe(false);
    const chronological = [...timeline.events].reverse().map(event => [event.kind, event.title]);
    expect(chronological).toEqual([
      ['submitted', 'You submitted your report'],
      ['summary-published', 'Your summary was published for legal organizations'],
      ['access-allowed', 'You allowed access for Alpha LLP'],
      ['message-received', 'Message from Alpha LLP'],
      ['message-sent', 'You sent a message to Alpha LLP'],
      ['files-added', 'You added 2 files'],
      ['summary-edited', 'You edited your summary'],
      ['access-revoked', 'You revoked access for Alpha LLP'],
      ['summary-withdrawn', 'You withdrew your summary from the directory'],
      ['update-approved', 'You approved an update to VERA’s secure service'],
      ['access-allowed', 'You allowed access for Bravo LLP'],
      ['access-changed', 'You changed access for Bravo LLP'],
      ['access-ended', 'Access for Bravo LLP ended'],
      ['request', 'Alpha LLP asked for access'],
    ]);
    const byKind = (kind: string) => timeline.events.filter(event => event.kind === kind);
    expect(byKind('submitted')[0].detail).toBe('With 1 file. Encrypted on your device.');
    // Access coverage is signed; whether the organization received the key is not,
    // so the record never claims the files were shared.
    expect(byKind('files-added')[0].detail).toBe('Covered by access for Alpha LLP.');
    expect(byKind('files-added')[0].detail).not.toMatch(/shared with/i);
    expect(byKind('access-allowed').find(event => event.organization === 'Bravo LLP')!.detail).not.toContain('until you revoke it');
    expect(byKind('access-allowed').find(event => event.organization === 'Bravo LLP')!.detail).toMatch(/until .*20[0-9]{2}/);
    expect(byKind('access-revoked')[0].detail).toContain('already read or downloaded');
    expect(byKind('access-changed')[0].detail).toContain(`until ${formatDay(T0 + 9 * DAY)}`);
    expect(byKind('update-approved')[0].detail).toBe(`Release ID ${hex(0x5e2).slice(0, 12)}…`);
    // Signed changes vs. sealed participant records; no private text in the timeline.
    expect(byKind('request')[0].record).toBe('sealed');
    expect(byKind('access-revoked')[0].record).toBe('signed');
    expect(JSON.stringify(timeline)).not.toMatch(/PRIVATE|First summary|Edited summary/);
    expect(ownerJourney(current, [request], [], now)).toEqual({ submitted: true, visible: false, requests: 1, sharedWith: 0 });
  });

  test('summary publish, edit and withdraw events never include the summary text', async () => {
    const owner = await createCaseOwner();
    const caseId = owner.trust.caseId;
    const statements: Record<string, string> = {};
    const sign = async (statement: OwnerStatement) => {
      const wire = await signOwnerStatement(statement, owner.privateKey);
      const { digest } = await verifyOwnerStatement(wire, owner.trust);
      statements[digest] = wire;
      return digest;
    };
    const entries: OwnerHistoryEntry[] = [];
    const commit = async (listingDigest: string | null, at: number) => {
      const checkpoint = { kind: 'checkpoint', caseId, keyEpoch: 1, revision: entries.length + 1, listingDigest,
        manifestDigest: null, grantDigests: [], releaseDigests: [],
        previousDigest: entries.length ? entries[entries.length - 1].digest : null, issuedAt: at } as CaseCheckpoint;
      const wire = await signOwnerStatement(checkpoint, owner.privateKey);
      const { digest } = await verifyOwnerStatement(wire, owner.trust);
      entries.push({ digest, wire, checkpoint });
    };
    await commit(await sign({ kind: 'listing', caseId, revision: 1, summary: 'SECRET ONE' } as OwnerStatement), T0);
    await commit(await sign({ kind: 'listing', caseId, revision: 2, summary: 'SECRET TWO' } as OwnerStatement), T0 + DAY);
    await commit(null, T0 + 2 * DAY);
    const timeline = await buildOwnerTimeline({ trust: owner.trust, history: entries, statements, roster: [], requests: [],
      threads: [], now: T0 + 3 * DAY });
    expect(timeline.incomplete).toBe(false);
    const summaries = [...timeline.events].reverse().filter(event => event.kind.startsWith('summary'))
      .map(event => [event.title, event.detail]);
    expect(summaries).toEqual([
      ['Your summary was published for legal organizations', undefined],
      ['You edited your summary', undefined],
      ['You withdrew your summary from the directory', undefined],
    ]);
    expect(JSON.stringify(timeline)).not.toContain('SECRET');
  });

  test('never names an organization whose confirmed key differs from the signed grant', async () => {
    const { owner, entries, statements, alpha } = await history();
    const impostor = { ...alpha, publicKey: (await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
      userIDs: [{ name: 'Impostor' }], format: 'object' })).publicKey };
    const timeline = await buildOwnerTimeline({ trust: owner.trust, history: entries, statements, roster: [impostor],
      requests: [], threads: [], now: T0 });
    const allowed = timeline.events.filter(event => event.kind === 'access-allowed');
    expect(allowed.map(event => event.title)).toEqual([
      'You allowed access for a legal organization VERA can no longer verify',
      'You allowed access for a legal organization VERA can no longer verify']);
    expect(timeline.events.some(event => event.title.includes('Alpha'))).toBe(false);
  });

  test('missing or substituted statements mark the timeline incomplete instead of inventing details', async () => {
    const { owner, entries, statements, alpha, bravo } = await history();
    const grantDigest = entries[1].checkpoint.grantDigests[0];
    const listingDigest = entries[0].checkpoint.listingDigest!;
    const tampered = { ...statements, [grantDigest]: statements[listingDigest] };
    const timeline = await buildOwnerTimeline({ trust: owner.trust, history: entries, statements: tampered,
      roster: [alpha, bravo], requests: [], threads: [], now: T0 });
    expect(timeline.incomplete).toBe(true);
    expect(timeline.events.some(event => event.title === 'You allowed access for Alpha LLP')).toBe(false);
    expect(timeline.events[timeline.events.length - 1].kind).toBe('submitted');
  });

  test('journey counts only current, unexpired access and a withdrawn summary', async () => {
    const { current } = await history();
    const grantee = (expiresAt: number) => ({ grantDigests: [], organizationId: hex(1), organization: null,
      grants: [{ issuedAt: T0 - 2 * DAY, expiresAt } as AccessGrant] }) as CurrentGrantee;
    expect(ownerJourney({ ...current, listingDigest: null }, [], [grantee(T0 + DAY), grantee(T0 - 1)], T0))
      .toEqual({ submitted: true, visible: false, requests: 0, sharedWith: 1 });
  });
});
