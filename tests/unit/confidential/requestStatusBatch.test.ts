jest.mock('../../../lib/confidential/client', () => ({
  ...jest.requireActual('../../../lib/confidential/client'),
  authenticatedOperation: jest.fn(), channelSessionsFor: jest.fn(() => ({})),
}));

import { authenticatedOperation } from '../../../lib/confidential/client';
import { checkReportAccessBatch } from '../../../lib/confidential/firmCase';
import type { FirmSession, ReportAccessTarget } from '../../../lib/confidential/firmCase';
import type { OwnerTrust } from '../../../enclave/src/confidential/authorization';
import { REQUEST_STATUS_BATCH_LIMIT } from '../../../enclave/src/confidential/requestStatusBatch';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const operation = jest.mocked(authenticatedOperation);
const targets = (count: number): ReportAccessTarget[] => Array.from({ length: count }, (_, i) => ({ caseId: hex(i + 1), requestId: null }));
const locked = { access: { state: 'unknown', expiresAt: null, scopes: [], contactShared: false, releaseApproved: null }, requests: [] };
let sent: ReportAccessTarget[][];
let session: FirmSession;
beforeEach(() => {
  sent = [];
  session = { firm: { organizationId: hex(999) }, accessToken: async () => 'synthetic', owners: new Map(), pins: new Map() } as unknown as FirmSession;
  operation.mockReset().mockImplementation(async (_sessions, input) => {
    const request = input.request('synthetic-proof') as { operation: string; body: string };
    expect(request.operation).toBe('legal.request-status-batch');
    const { cases } = JSON.parse(Buffer.from(request.body, 'base64').toString('utf8'));
    sent.push(cases);
    return { statuses: cases.map((target: ReportAccessTarget) => ({ caseId: target.caseId, status: locked })) };
  });
});

test('89 locked reports use one status operation and no background unlocks', async () => {
  const batch = targets(89).map(target => ({ ...target, owner: { caseId: target.caseId, ownerFingerprint: hex(900) } as OwnerTrust }));
  const result = await checkReportAccessBatch(session, batch, Date.now());
  expect(sent.map(batch => batch.length)).toEqual([89]);
  expect(operation).toHaveBeenCalledTimes(1);
  expect(result.size).toBe(89);
  expect([...result.values()].every(status => status?.access === 'unknown')).toBe(true);
  expect(session.owners.size).toBe(89);
});

test('larger lists use bounded batches without duplicates', async () => {
  const batch = targets(REQUEST_STATUS_BATCH_LIMIT * 2 + 1);
  const result = await checkReportAccessBatch(session, batch, Date.now());
  expect(sent.map(page => page.length)).toEqual([256, 256, 1]);
  expect(sent.flat()).toEqual(batch);
  expect(result.size).toBe(batch.length);
});

test('empty lists make no request; duplicates and malformed IDs fail before network', async () => {
  expect((await checkReportAccessBatch(session, [], Date.now())).size).toBe(0);
  await expect(checkReportAccessBatch(session, [...targets(1), ...targets(1)], Date.now())).rejects.toThrow();
  await expect(checkReportAccessBatch(session, [{ caseId: 'bad', requestId: null }], Date.now())).rejects.toThrow();
  expect(operation).not.toHaveBeenCalled();
});

test.each(['missing', 'reordered', 'wrong-request', 'extra-field'])('rejects %s replies instead of mislabeling reports', async corruption => {
  const batch = targets(2);
  batch[0].requestId = hex(777);
  operation.mockImplementationOnce(async () => {
    const rows: any[] = batch.map(target => ({ caseId: target.caseId, status: { ...locked,
      requests: target.requestId ? [{ requestId: target.requestId, state: 'declined' }] : [] } }));
    if (corruption === 'missing') rows.pop();
    if (corruption === 'reordered') rows.reverse();
    if (corruption === 'wrong-request') rows[0].status.requests[0].requestId = hex(778);
    if (corruption === 'extra-field') rows[0].privateData = 'unexpected';
    return { statuses: rows };
  });
  await expect(checkReportAccessBatch(session, batch, Date.now())).rejects.toThrow();
});

test('one unavailable report or changed owner key does not turn into denied access', async () => {
  const batch = targets(3);
  session.owners.set(batch[2].caseId, { ownerFingerprint: hex(5) } as OwnerTrust);
  batch[2].owner = { caseId: batch[2].caseId, ownerFingerprint: hex(6) } as OwnerTrust;
  operation.mockResolvedValueOnce({ statuses: [
    { caseId: batch[0].caseId, status: locked }, { caseId: batch[1].caseId, error: 'unavailable' },
  ] });
  const result = await checkReportAccessBatch(session, batch, Date.now());
  expect(result.get(batch[0].caseId)?.access).toBe('unknown');
  expect(result.get(batch[1].caseId)).toBeNull();
  expect(result.get(batch[2].caseId)).toBeNull();
  expect(session.owners.get(batch[2].caseId)?.ownerFingerprint).toBe(hex(5));
});

test('cancellation prevents later batches from running', async () => {
  const controller = new AbortController();
  operation.mockImplementationOnce(async () => { controller.abort(); return {}; });
  await expect(checkReportAccessBatch(session, targets(257), Date.now(), controller.signal)).rejects.toThrow();
  expect(operation).toHaveBeenCalledTimes(1);
});
