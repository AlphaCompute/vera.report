/**
 * Two API tasks run the SLA sweep against one database (#1043). Each breach
 * must produce one audit event and one admin email, whichever task wins.
 */

import crypto from 'node:crypto';
import { useDisseminationMongo } from '../../helpers/disseminationMongo';
useDisseminationMongo();
import { receiptTracker } from '../../../src/services/dissemination/receiptTracker';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { emailNotificationService } from '../../../src/services/emailNotification';
import type { SubmissionDoc } from '../../../src/services/dissemination/types';

jest.mock('../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined) },
}));

const flushNotifications = () => new Promise<void>(resolve => setImmediate(resolve));
const DAY = 24 * 60 * 60 * 1000;

async function overdueSubmission(feedbackOverdue = false): Promise<SubmissionDoc> {
  const id = crypto.randomUUID();
  const past = new Date(Date.now() - DAY);
  const doc: SubmissionDoc = {
    submissionId: `sla-${id}`, trackingId: `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`,
    entityId: 'synthetic-entity', tier: 'A', idempotencyKey: `sla-${id}`, state: 'dispatched', packetVersion: 1,
    attempts: 1, dispatchedAt: new Date(Date.now() - 100 * DAY),
    sla: { ackDueAt: past, feedbackDueAt: feedbackOverdue ? past : new Date(Date.now() + DAY), ackBreached: false, feedbackBreached: false },
    createdAt: past, updatedAt: past,
  };
  expect(await disseminationPersistence.insertSubmission(doc)).toBe(true);
  return doc;
}

/** Hold every sweep's read until all have read, so all see the clock unbreached. */
function readBarrier(sweeps: number): void {
  const read = disseminationPersistence.getSubmissionsWithOpenSla.bind(disseminationPersistence);
  let waiting = 0;
  let release!: () => void;
  const allRead = new Promise<void>(resolve => { release = resolve; });
  jest.spyOn(disseminationPersistence, 'getSubmissionsWithOpenSla').mockImplementation(async () => {
    const rows = await read();
    if (++waiting === sweeps) release();
    await allRead;
    return rows;
  });
}

async function slaEvents(trackingId: string) {
  return (await disseminationPersistence.getAuditForReport(trackingId)).filter(event => event.event === 'sla_breached');
}

beforeEach(() => {
  (emailNotificationService.sendAlert as jest.Mock).mockClear();
});
afterEach(() => jest.restoreAllMocks());

test('two concurrent sweeps record one audit event and send one email', async () => {
  const sub = await overdueSubmission();
  readBarrier(2);
  await Promise.all([receiptTracker.checkSlas(), receiptTracker.checkSlas()]);
  await flushNotifications();

  const events = await slaEvents(sub.trackingId);
  expect(events).toHaveLength(1);
  expect(events[0].detail).toEqual({ breaches: ['7-day acknowledgment'] });
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
  expect((await disseminationPersistence.getSubmission(sub.submissionId))?.sla).toMatchObject({ ackBreached: true, feedbackBreached: false });

  // A later sweep sees the stored flag and stays quiet.
  jest.restoreAllMocks();
  await receiptTracker.checkSlas();
  await flushNotifications();
  expect(await slaEvents(sub.trackingId)).toHaveLength(1);
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
});

test('each clock is won once even when both breach in the same concurrent sweep', async () => {
  const sub = await overdueSubmission(true);
  readBarrier(3);
  await Promise.all([receiptTracker.checkSlas(), receiptTracker.checkSlas(), receiptTracker.checkSlas()]);
  await flushNotifications();

  const breaches = (await slaEvents(sub.trackingId)).flatMap(event => (event.detail as { breaches: string[] }).breaches);
  expect(breaches.sort()).toEqual(['3-month feedback', '7-day acknowledgment']);
  expect((emailNotificationService.sendAlert as jest.Mock).mock.calls.length).toBeLessThanOrEqual(2);
  expect((emailNotificationService.sendAlert as jest.Mock).mock.calls.length).toBeGreaterThanOrEqual(1);
});

test('a receipt recorded after the sweep read the row wins over the breach', async () => {
  const sub = await overdueSubmission();
  const read = disseminationPersistence.getSubmissionsWithOpenSla.bind(disseminationPersistence);
  jest.spyOn(disseminationPersistence, 'getSubmissionsWithOpenSla').mockImplementation(async () => {
    const rows = await read();
    await disseminationPersistence.advanceReceiptSubmission(sub.submissionId, 'acknowledged', new Date());
    return rows;
  });
  await receiptTracker.checkSlas();
  await flushNotifications();

  expect(await slaEvents(sub.trackingId)).toHaveLength(0);
  expect(emailNotificationService.sendAlert).not.toHaveBeenCalled();
  expect((await disseminationPersistence.getSubmission(sub.submissionId))?.sla?.ackBreached).toBe(false);
});
