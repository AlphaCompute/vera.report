// Regression: a firm device hands the case state key only to a release whose
// owner approval is listed in the checkpoint this device last verified, not to
// any historic approval the locked service still returns.
jest.mock('../../../lib/confidential/client', () => ({
  ...jest.requireActual('../../../lib/confidential/client'),
  channelSessionsFor: jest.fn(() => ({})),
  publicCaseOperation: jest.fn(),
}));
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { generateFirmIdentity } from '../../../lib/confidential/firmKey';
import { ensureReleaseApproved } from '../../../lib/confidential/firmCase';
import type { FirmSession } from '../../../lib/confidential/firmCase';
import { firmWorkspace, readFirmWorkspace } from '../../../lib/confidential/firmWorkspace';
import { publicCaseOperation } from '../../../lib/confidential/client';

const RELEASE = 'a'.repeat(64);

async function fixture() {
  const owner = await createCaseOwner();
  const firm = await generateFirmIdentity({ organizationId: '44'.repeat(32), domain: 'firm.example' });
  const caseId = owner.trust.caseId;
  const approve = async (revision: number) => {
    const wire = await signOwnerStatement({ kind: 'release', caseId, revision, releaseDigest: RELEASE,
      issuedAt: Date.now() - 60_000 }, owner.privateKey);
    return { wire, digest: (await verifyOwnerStatement(wire, owner.trust)).digest };
  };
  const session = { firm, owners: new Map([[caseId, owner.trust]]), pins: new Map(), pinReleases: new Map(),
    sequences: new Map(), relay: {}, releaseManifest: 'synthetic', releaseDigest: RELEASE,
    accessToken: async () => 'synthetic' } as unknown as FirmSession;
  const pin = { caseId, ownerFingerprint: owner.trust.ownerFingerprint, revision: 5, keyEpoch: 1, digest: 'c'.repeat(64) };
  return { caseId, session, approve, pin };
}

test('a historic approval no longer in the pinned checkpoint is refused', async () => {
  const f = await fixture();
  const dropped = await approve(f, 2), current = await approve(f, 4);
  f.session.pins.set(f.caseId, f.pin);
  f.session.pinReleases!.set(f.caseId, { digest: f.pin.digest, releaseDigests: [current.digest] });
  // The locked service returns only the dropped approval of this release.
  jest.mocked(publicCaseOperation).mockResolvedValue({ releases: [dropped.wire] });
  await expect(ensureReleaseApproved(f.session, f.caseId, Date.now())).rejects.toMatchObject({ code: 'release-not-approved' });
  // The approval listed in the pinned checkpoint is accepted.
  jest.mocked(publicCaseOperation).mockResolvedValue({ releases: [dropped.wire, current.wire] });
  await expect(ensureReleaseApproved(f.session, f.caseId, Date.now())).resolves.toBeUndefined();
  // Approvals pinned for an older checkpoint digest are not trusted for the current pin.
  f.session.pinReleases!.set(f.caseId, { digest: 'd'.repeat(64), releaseDigests: [dropped.digest] });
  jest.mocked(publicCaseOperation).mockResolvedValue({ releases: [dropped.wire] });
  await expect(ensureReleaseApproved(f.session, f.caseId, Date.now())).rejects.toMatchObject({ code: 'release-not-approved' });
});

test('pinned approvals survive a workspace backup and still gate the unlock', async () => {
  const f = await fixture();
  const dropped = await approve(f, 2), current = await approve(f, 4);
  f.session.pins.set(f.caseId, f.pin);
  f.session.pinReleases!.set(f.caseId, { digest: f.pin.digest, releaseDigests: [current.digest] });
  const saved = JSON.parse(JSON.stringify(firmWorkspace(f.session, [])));
  expect(saved.pins[0].releaseDigests).toEqual([current.digest]);
  const restored = await readFirmWorkspace(saved);
  expect(restored.pins.get(f.caseId)).toEqual(f.pin);
  const session = { ...f.session, pins: restored.pins, pinReleases: restored.pinReleases } as FirmSession;
  jest.mocked(publicCaseOperation).mockResolvedValue({ releases: [dropped.wire] });
  await expect(ensureReleaseApproved(session, f.caseId, Date.now())).rejects.toMatchObject({ code: 'release-not-approved' });
  // A malformed saved list is rejected rather than silently widening trust.
  await expect(readFirmWorkspace({ ...saved, pins: [{ ...saved.pins[0], releaseDigests: ['nope'] }] })).rejects.toThrow();
});

test('without pinned approvals (first open, or an older backup) any verified approval is accepted', async () => {
  const f = await fixture();
  const dropped = await approve(f, 2);
  jest.mocked(publicCaseOperation).mockResolvedValue({ releases: [dropped.wire] });
  await expect(ensureReleaseApproved(f.session, f.caseId, Date.now())).resolves.toBeUndefined();
  f.session.pins.set(f.caseId, f.pin);
  await expect(ensureReleaseApproved(f.session, f.caseId, Date.now())).resolves.toBeUndefined();
});

function approve(f: Awaited<ReturnType<typeof fixture>>, revision: number) { return f.approve(revision); }
