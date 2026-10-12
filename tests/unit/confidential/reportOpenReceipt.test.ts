import { generateKey } from '../../../enclave/src/confidential/pgp';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint, OwnerStatement } from '../../../enclave/src/confidential/authorization';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { openReportOpenReceipt, sealReportOpenReceipt } from '../../../enclave/src/confidential/reportOpenReceipt';
import { readReportOpens } from '../../../lib/confidential/ownerCase';
import type { OwnerInbox, OwnerSession, VerifiedOrganization } from '../../../lib/confidential/ownerCase';
import { buildOwnerTimeline } from '../../../lib/confidential/ownerTimeline';

const hex = (n: number) => n.toString(16).padStart(64, '0');
async function fixture() {
  const owner = await createCaseOwner();
  const firm = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Example Legal' }], format: 'object' })).privateKey;
  const organization: VerifiedOrganization = { organizationId: hex(5), publicKey: firm.toPublic(), approved: true,
    displayName: 'Example Legal', domain: 'legal.example', profile: null };
  const participants = { owner: owner.trust, organization }, now = Date.now();
  const statements: Record<string, string> = {};
  const signed = async (statement: OwnerStatement) => {
    const wire = await signOwnerStatement(statement, owner.privateKey);
    const verified = await verifyOwnerStatement(wire, owner.trust);
    statements[verified.digest] = wire;
    return { digest: verified.digest, wire, checkpoint: statement as CaseCheckpoint };
  };
  const manifest = await signed({ kind: 'manifest', caseId: owner.trust.caseId, revision: 1, objects: [] });
  const grant = await signed({ kind: 'grant', caseId: owner.trust.caseId, revision: 1, grantId: hex(6),
    organizationId: organization.organizationId, recipientKeyId: await caseRecipientKeyId(firm.toPublic()),
    scopes: ['narrative'], keyEpoch: 1, objectRevisionLimit: null, issuedAt: now - 1000, expiresAt: null });
  const entry = await signed({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1, keyEpoch: 1,
    previousDigest: null, manifestDigest: manifest.digest, listingDigest: null, grantDigests: [grant.digest],
    releaseDigests: [], issuedAt: now - 1000 });
  const session = { trust: owner.trust, owner: owner.privateKey, history: [entry] } as OwnerSession;
  const ciphertext = await sealReportOpenReceipt({ checkpointDigest: entry.digest, openedAt: now }, participants, firm);
  const row = { organizationId: organization.organizationId, sender: 'organization', kind: 'report-open' as const, ciphertext, createdAt: now };
  const inbox = { statements, messages: [row], current: entry.checkpoint } as OwnerInbox;
  return { owner, firm, organization, participants, session, inbox, row, now, entry, ciphertext };
}

test('first-open receipt is encrypted, signed, bound to the report and authorized in owner history', async () => {
  const f = await fixture();
  expect(f.ciphertext).not.toContain(f.organization.organizationId);
  expect(f.ciphertext).not.toContain('vera-report-open');
  const receipt = await openReportOpenReceipt(f.ciphertext, f.participants, f.owner.privateKey);
  expect(receipt.openedAt).toBe(f.now);
  await expect(openReportOpenReceipt(f.ciphertext, { ...f.participants,
    owner: { ...f.owner.trust, caseId: hex(777) } }, f.owner.privateKey)).rejects.toThrow();
  await expect(openReportOpenReceipt(f.ciphertext, { ...f.participants,
    organization: { ...f.organization, publicKey: f.owner.privateKey.toPublic() } }, f.owner.privateKey)).rejects.toThrow();
  const later = await sealReportOpenReceipt({ checkpointDigest: f.entry.digest, openedAt: f.now + 1 }, f.participants, f.firm);
  f.inbox.messages.push({ ...f.row, ciphertext: later }, { ...f.row });
  const opens = await readReportOpens(f.session, f.inbox, [f.organization], f.now + 1);
  expect(opens).toHaveLength(1);
  expect(opens[0].receipt.openedAt).toBe(f.now);
  const timeline = await buildOwnerTimeline({ trust: f.owner.trust, history: f.session.history!,
    statements: f.inbox.statements, roster: [f.organization], requests: [], threads: [], opens, now: f.now + 1 });
  expect(timeline.events.filter(item => item.kind === 'report-opened')).toEqual([expect.objectContaining({
    title: 'Example Legal first opened your report', at: f.now, record: 'organization' })]);
});

test('legacy messages, wrong checkpoint, absent grant and fabricated future receipts never become views', async () => {
  const f = await fixture();
  f.inbox.messages = [{ ...f.row, kind: undefined }];
  expect(await readReportOpens(f.session, f.inbox, [f.organization], f.now)).toEqual([]);
  for (const input of [{ checkpointDigest: hex(999), openedAt: f.now },
    { checkpointDigest: f.entry.digest, openedAt: f.now + 86400000 }]) {
    f.inbox.messages = [{ ...f.row, ciphertext: await sealReportOpenReceipt(input, f.participants, f.firm) }];
    expect(await readReportOpens(f.session, f.inbox, [f.organization], f.now)).toEqual([]);
  }
  f.inbox.messages = [f.row];
  f.entry.checkpoint.grantDigests = [];
  expect(await readReportOpens(f.session, f.inbox, [f.organization], f.now)).toEqual([]);
});

test('the first opening remains verifiable after a firm rotates its key', async () => {
  const f = await fixture();
  const replacement = (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Replacement' }], format: 'object' })).privateKey;
  const rotated = { ...f.organization, publicKey: replacement.toPublic() };
  const opens = await readReportOpens(f.session, f.inbox, [rotated], f.now);
  expect(opens).toHaveLength(1);
  expect(opens[0].receipt.openedAt).toBe(f.now);
  expect(opens[0].receipt.recipientKeyId).toBe(await caseRecipientKeyId(f.firm.toPublic()));
  // A key with no historical owner-signed grant cannot substitute a receipt.
  f.inbox.messages = [{ ...f.row, ciphertext: await sealReportOpenReceipt({ checkpointDigest: f.entry.digest, openedAt: f.now },
    { owner: f.owner.trust, organization: rotated }, replacement) }];
  expect(await readReportOpens(f.session, f.inbox, [rotated], f.now)).toEqual([]);
});
