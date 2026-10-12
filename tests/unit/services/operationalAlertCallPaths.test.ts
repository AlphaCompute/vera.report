import { emailNotificationService } from '../../../src/services/emailNotification';
import { receiptTracker } from '../../../src/services/dissemination/receiptTracker';
import { dispatchWorker } from '../../../src/services/dissemination/dispatchWorker';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { getAdapter } from '../../../src/services/dissemination/adapters/registry';
import type { SubmissionDoc } from '../../../src/services/dissemination/types';
import { reportPersistenceService } from '../../../src/services/reportPersistence';

jest.mock('../../../src/services/emailNotification', () => ({
  emailNotificationService: {
    notifyCriticalAdminAction: jest.fn(), notifyErrorThreshold: jest.fn(), sendAlert: jest.fn(),
  },
}));
jest.mock('../../../src/services/submissionWebhook', () => ({ notifyOperationalEvent: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../src/services/dissemination/disseminationPersistence', () => ({
  disseminationPersistence: {
    getSubmissionsWithOpenSla: jest.fn(), patchSubmission: jest.fn(), appendAudit: jest.fn(), markSlaBreached: jest.fn(),
    setDispositionChannelState: jest.fn(), claimNextDueSubmission: jest.fn(), getDisposition: jest.fn(),
    updateUnsentSubmission: jest.fn(), getSubmission: jest.fn(),
  },
}));
jest.mock('../../../src/services/reportPersistence', () => ({ reportPersistenceService: { get: jest.fn() } }));
jest.mock('../../../src/services/dissemination/disseminationService', () => ({ disseminationService: { buildView: jest.fn() } }));
jest.mock('../../../src/services/dissemination/packetGenerator', () => ({ packetGenerator: {} }));
jest.mock('../../../src/services/dissemination/adapters/registry', () => ({ getAdapter: jest.fn() }));
jest.mock('../../../src/services/dissemination/adapters/emailAdapter', () => ({ disseminationMode: () => 'live' }));

const flushNotifications = () => new Promise<void>(resolve => setImmediate(resolve));
const submission = () => ({
  submissionId: 'private-submission-id', trackingId: 'private-report-id', entityId: 'private-channel',
  attempts: 4, state: 'approved', claimToken: 'synthetic-claim',
  sla: { ackDueAt: new Date(0), feedbackDueAt: null, ackBreached: false, feedbackBreached: false },
} as SubmissionDoc);

beforeEach(() => {
  jest.clearAllMocks();
  for (const method of Object.values(emailNotificationService)) (method as jest.Mock).mockResolvedValue(undefined);
  for (const method of Object.values(disseminationPersistence)) (method as jest.Mock).mockReset().mockResolvedValue(undefined);
  (disseminationPersistence.getSubmissionsWithOpenSla as jest.Mock).mockResolvedValue([]);
  (disseminationPersistence.patchSubmission as jest.Mock).mockResolvedValue(true);
});
afterEach(() => jest.restoreAllMocks());

test('SLA alerts omit report/channel/submission identifiers while preserving the internal audit', async () => {
  const sub = submission();
  (disseminationPersistence.getSubmissionsWithOpenSla as jest.Mock).mockResolvedValue([sub]);
  // The first sweep wins the compare-and-set; the second finds the clock already breached.
  (disseminationPersistence.markSlaBreached as jest.Mock).mockResolvedValueOnce(true).mockResolvedValue(false);
  await receiptTracker.checkSlas();
  await flushNotifications();
  expect(disseminationPersistence.appendAudit).toHaveBeenCalledWith(expect.objectContaining({
    trackingId: sub.trackingId, entityId: sub.entityId, event: 'sla_breached',
  }), `sla_breached:${sub.submissionId}:ack`);
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
  expect(JSON.stringify((emailNotificationService.sendAlert as jest.Mock).mock.calls)).not.toContain('private-');
  expect((emailNotificationService.sendAlert as jest.Mock).mock.calls[0][2]).toContain('7-day acknowledgment');
  await receiptTracker.checkSlas();
  await flushNotifications();
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
});

test('dead-letter alert omits identifiers while the worker persists failure and audit state', async () => {
  const sub = submission();
  (getAdapter as jest.Mock).mockReturnValue(undefined);
  (disseminationPersistence.claimNextDueSubmission as jest.Mock).mockResolvedValueOnce(sub).mockResolvedValue(null);
  await dispatchWorker.tick();
  await flushNotifications();
  expect(disseminationPersistence.patchSubmission).toHaveBeenCalledWith(sub.submissionId, expect.objectContaining({ state: 'failed' }), sub.claimToken);
  expect(disseminationPersistence.appendAudit).toHaveBeenCalledWith(expect.objectContaining({ trackingId: sub.trackingId, event: 'dead_lettered' }));
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
  expect(JSON.stringify((emailNotificationService.sendAlert as jest.Mock).mock.calls)).not.toContain('private-');
});

test('exhausted retries never include arbitrary failure text in the email', async () => {
  const sub = submission();
  (getAdapter as jest.Mock).mockReturnValue({ allowsDispatch: () => true });
  (disseminationPersistence.getDisposition as jest.Mock).mockResolvedValue({ narrativeReviewedAt: new Date() });
  (disseminationService.buildView as jest.Mock).mockRejectedValue(new Error('private-provider-secret <script>private-report-content</script>'));
  (disseminationPersistence.claimNextDueSubmission as jest.Mock).mockResolvedValueOnce(sub).mockResolvedValue(null);
  await dispatchWorker.tick();
  await flushNotifications();
  expect(disseminationPersistence.patchSubmission).toHaveBeenCalledWith(sub.submissionId, expect.objectContaining({ state: 'failed', attempts: 5 }), sub.claimToken);
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
  expect(JSON.stringify((emailNotificationService.sendAlert as jest.Mock).mock.calls)).not.toMatch(/private-|script/);
});

test('threshold alerts pass counts without arbitrary errors, request context or secrets', async () => {
  // The module owns an hourly cleanup timer; capture and clear it for this test.
  const timers: ReturnType<typeof setInterval>[] = [];
  const originalInterval = global.setInterval;
  jest.spyOn(global, 'setInterval').mockImplementation(((...args: Parameters<typeof setInterval>) => {
    const timer = originalInterval(...args);
    timers.push(timer);
    return timer;
  }) as typeof setInterval);
  try {
    const { ErrorMonitor } = require('../../../src/utils/errorMonitor');
    const monitor = new ErrorMonitor();
    for (let i = 0; i < 5; i++) monitor.logError('private-report-content private-provider-secret', 'critical', {
      endpoint: '/private-report-id', token: 'private-provider-secret',
    });
    await flushNotifications();
    expect(emailNotificationService.notifyErrorThreshold).toHaveBeenCalledWith(5);
    expect((emailNotificationService.notifyErrorThreshold as jest.Mock).mock.calls.every(args => args.length === 1 && typeof args[0] === 'number')).toBe(true);
  } finally {
    timers.forEach(clearInterval);
  }
});

test('automatic consent withdrawal alerts admins without report details', async () => {
  const sub = { ...submission(), entityId: 'eeoc' } as SubmissionDoc;
  (getAdapter as jest.Mock).mockReturnValue({ allowsDispatch: () => true });
  (reportPersistenceService.get as jest.Mock).mockResolvedValue({ trackingId: sub.trackingId,
    consent: { psst: { granted: false }, agency: true, capturedAt: new Date(), textVersion: 'v3-legal-review-default' } });
  (disseminationPersistence.updateUnsentSubmission as jest.Mock).mockResolvedValue(true);
  (disseminationPersistence.claimNextDueSubmission as jest.Mock).mockResolvedValueOnce(sub).mockResolvedValue(null);
  await dispatchWorker.tick();
  await flushNotifications();
  expect(disseminationPersistence.updateUnsentSubmission).toHaveBeenCalledWith(sub.submissionId, expect.objectContaining({ state: 'withdrawn' }), false, sub.claimToken);
  expect(emailNotificationService.sendAlert).toHaveBeenCalledTimes(1);
  expect((emailNotificationService.sendAlert as jest.Mock).mock.calls[0][1]).toBe('Dissemination channel withdrawn automatically');
  expect(JSON.stringify((emailNotificationService.sendAlert as jest.Mock).mock.calls)).not.toContain('private-');
});
