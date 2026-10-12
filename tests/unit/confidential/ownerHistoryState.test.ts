import { webcrypto } from 'node:crypto';
import { signOwnerStatement, verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import type { CaseCheckpoint } from '../../../enclave/src/confidential/authorization';
import { createCaseOwner } from '../../../enclave/src/confidential/recovery';
import { ownerOperation } from '../../../lib/confidential/client';
import { readOwnerInbox, ConfidentialRollbackError } from '../../../lib/confidential/ownerCase';
import type { OwnerSession, OwnerHistoryEntry } from '../../../lib/confidential/ownerCase';

jest.mock('../../../lib/confidential/client', () => ({
  ...jest.requireActual('../../../lib/confidential/client'),
  ownerOperation: jest.fn(), channelSessionsFor: jest.fn(),
}));
const operation = jest.mocked(ownerOperation);
const reply = (checkpoints: string[]) => ({ checkpoints, statements: {}, requests: [], messages: [] });

async function fixture() {
  const owner = await createCaseOwner();
  const entries: OwnerHistoryEntry[] = [];
  for (let revision = 1; revision <= 3; revision++) {
    const checkpoint: CaseCheckpoint = { kind: 'checkpoint', caseId: owner.trust.caseId, revision, keyEpoch: 1,
      previousDigest: entries.at(-1)?.digest ?? null, listingDigest: null, manifestDigest: null,
      grantDigests: [], releaseDigests: [], issuedAt: Date.now() };
    const wire = await signOwnerStatement(checkpoint, owner.privateKey);
    entries.push({ wire, checkpoint, digest: (await verifyOwnerStatement(wire, owner.trust)).digest });
  }
  const pin = (index: number) => ({ caseId: owner.trust.caseId, ownerFingerprint: owner.trust.ownerFingerprint,
    revision: index + 1, keyEpoch: 1, digest: entries[index].digest });
  const session: OwnerSession = { relay: {} as OwnerSession['relay'], releaseManifest: '', releaseDigest: '',
    owner: owner.privateKey, trust: owner.trust, pin: pin(0), pinnedCheckpoint: entries[0].wire,
    recoveryCode: '', freshness: 'device-pinned', history: [entries[0]] };
  return { session, entries, pin };
}

beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });
beforeEach(() => operation.mockReset());

test.each(['bad-successor', 'missing-minimum'] as const)('failed %s read preserves cached history and pin', async defect => {
  const { session, entries, pin } = await fixture();
  const history = session.history, previousPin = session.pin;
  if (defect === 'missing-minimum') session.minimumPin = pin(2);
  operation.mockResolvedValue(reply([entries[1].wire, ...(defect === 'bad-successor' ? ['invalid-signature'] : [])]));
  await expect(readOwnerInbox(session, Date.now())).rejects.toBeInstanceOf(ConfidentialRollbackError);
  expect(session.history).toBe(history);
  expect(session.history).toEqual([entries[0]]);
  expect(session.pin).toBe(previousPin);
  if (defect === 'missing-minimum') expect(session.minimumPin).toEqual(pin(2));
});

test('a late earlier read cannot overwrite newer verified history or duplicate its entries', async () => {
  const { session, entries } = await fixture();
  let release!: (value: ReturnType<typeof reply>) => void;
  operation.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const older = readOwnerInbox(session, Date.now());
  operation.mockResolvedValueOnce(reply([entries[1].wire, entries[2].wire]));
  const newer = await readOwnerInbox(session, Date.now());
  expect(newer.checkpointDigest).toBe(entries[2].digest);
  const acceptedHistory = session.history;
  release(reply([entries[1].wire]));
  await expect(older).rejects.toBeInstanceOf(ConfidentialRollbackError);
  expect(session.history).toBe(acceptedHistory);
  expect(session.history).toEqual(entries);
  expect(session.pin.digest).toBe(entries[2].digest);
});
