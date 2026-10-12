import { sendSecurePacket } from '../../../../src/services/dissemination/securePacketSender';
import { emailNotificationService } from '../../../../src/services/emailNotification';
/**
 * Inbound receipt mail ingest tests (Phase 2a): mailbox → entity mapping,
 * tracking-ID extraction, the full-auto receipt path, and the review
 * queue lifecycle (resolve / dismiss).
 */

import crypto from 'node:crypto';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import {
  inboundMailService,
  resolveEntityFromRecipient,
  extractTrackingId,
} from '../../../../src/services/dissemination/inboundMail';
import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { dispatchWorker } from '../../../../src/services/dissemination/dispatchWorker';
import { reportPersistenceService } from '../../../../src/services/reportPersistence';

jest.mock('../../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: {
    uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'QmPacketCid' }),
  },
}));

// sendAlert is fire-and-forget on the dispatch path (dispatchWorker/receiptTracker);
// unmocked it leaks an Auth0 fetch + AWS SES call past teardown and force-exits the worker.
jest.mock('../../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined), sendSecurePacketEmail: jest.fn().mockResolvedValue({ sent: true }) },
}));

const ORIGINAL_ENV = { ...process.env };
afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

async function seedDispatchedCisaSubmission(): Promise<string> {
  process.env.DISSEMINATION_MODE = 'dryrun';
  process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';
  process.env.DISSEMINATION_SENDER_EMAIL = 'submissions@vera.test';
  process.env.AWS_ENDPOINT_URL = ''; // never reached — dispatch mocked below

  process.env.DISSEMINATION_RECEIPT_SENDERS = JSON.stringify({ cisa: ['no-reply@cisa.dhs.gov'] });
  const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  await reportPersistenceService.upsert({
    trackingId,
    status: 'verified',
    categories: ['cyber-security'],
    consent: {
      psst: { granted: false },
      agency: true,
      capturedAt: new Date(),
      textVersion: 'v1',
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

  // Skip real SES: mark the submission dispatched directly.
  const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  await disseminationPersistence.patchSubmission(sub.submissionId, {
    state: 'dispatched',
    dispatchedAt: new Date(),
    sla: {
      ackDueAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
      feedbackDueAt: new Date(Date.now() + 90 * 24 * 3600 * 1000),
      ackBreached: false,
      feedbackBreached: false,
    },
  });
  return trackingId;
}

describe('recipient mailbox mapping', () => {
  it('maps <entityId>-receipts@ to the entity', () => {
    expect(resolveEntityFromRecipient('cisa-receipts@receipts.vera.report')).toBe('cisa');
    expect(resolveEntityFromRecipient('gao-fraudnet-receipts@receipts.vera.report')).toBe('gao-fraudnet');
  });

  it('rejects unknown entities and non-receipt mailboxes', () => {
    expect(resolveEntityFromRecipient('nonsense-receipts@receipts.vera.report')).toBeNull();
    expect(resolveEntityFromRecipient('cisa@receipts.vera.report')).toBeNull();
  });
});

describe('tracking ID extraction', () => {
  it('finds a tracking ID in subject or body, case-insensitively', () => {
    expect(extractTrackingId('Re: report vra-abcdef0123456789', undefined)).toBe('VRA-ABCDEF0123456789');
    expect(extractTrackingId('no id here', 'ref VRA-0123456789ABCDEF ok')).toBe('VRA-0123456789ABCDEF');
    expect(extractTrackingId('nothing', 'nothing')).toBeNull();
  });
});

describe('inbound ingest', () => {
  it('auto-records a receipt when mailbox, tracking ID, and pattern all match', async () => {
    const trackingId = await seedDispatchedCisaSubmission();

    const result = await inboundMailService.ingest({
      recipient: 'cisa-receipts@receipts.vera.report',
      from: 'no-reply@cisa.dhs.gov',
      authentication: { spf: 'PASS', dkim: 'PASS', dmarc: 'PASS' },
      subject: `Re: Whistleblower report ${trackingId}`,
      body: `Thank you. Your incident ID: CISA-2026-99101 has been recorded.`,
      messageId: `ses-${trackingId}`,
    });

    expect(result.autoParsed).toBe(true);
    expect(result.entityId).toBe('cisa');
    expect(result.trackingId).toBe(trackingId);

    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('acknowledged');
    expect(sub.sla?.ackReceivedAt).toBeDefined();

    const receipts = await disseminationPersistence.getReceiptsForReport(trackingId);
    expect(receipts.some((r) => r.type === 'incident-id' && r.value === 'CISA-2026-99101')).toBe(true);

    const mail = await disseminationPersistence.getInboundMail(result.inboundId);
    expect(mail?.status).toBe('resolved');
    expect(mail?.autoParsed).toBe(true);
  });

  it('queues mail for review when the tracking ID is missing', async () => {
    const result = await inboundMailService.ingest({
      recipient: 'cisa-receipts@receipts.vera.report',
      from: 'someone@example.com',
      subject: 'A reply with no reference',
      body: 'incident ID: CISA-2026-55555',
      messageId: 'ses-no-tracking',
    });

    expect(result.autoParsed).toBe(false);
    const mail = await disseminationPersistence.getInboundMail(result.inboundId);
    expect(mail?.status).toBe('pending_review');
  });

  it('is idempotent on the SES message ID', async () => {
    const payload = {
      recipient: 'unknown@receipts.vera.report',
      from: 'x@example.com',
      subject: 'dup test',
      body: 'body',
      messageId: 'ses-duplicate-1',
    };
    const first = await inboundMailService.ingest(payload);
    const second = await inboundMailService.ingest(payload);
    expect(first.inboundId).toBe(second.inboundId);

    const all = await disseminationPersistence.listInboundMail();
    expect(all.filter((m) => m.inboundId === first.inboundId)).toHaveLength(1);
  });

  it('admin resolve attaches queued mail as a receipt; dismiss closes it', async () => {
    const trackingId = await seedDispatchedCisaSubmission();

    const queued = await inboundMailService.ingest({
      recipient: 'cisa-receipts@receipts.vera.report',
      from: 'no-reply@cisa.dhs.gov',
      authentication: { spf: 'PASS', dkim: 'PASS', dmarc: 'PASS' },
      subject: 'Acknowledgment (no tracking reference)',
      body: 'We received your submission.',
      messageId: `ses-review-${trackingId}`,
    });
    expect(queued.autoParsed).toBe(false);

    const resolved = await inboundMailService.resolve(queued.inboundId, 'admin@test', {
      trackingId,
      entityId: 'cisa',
      kind: 'ack',
    });
    expect(resolved.ok).toBe(true);

    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('acknowledged');

    // Already-resolved mail cannot be re-actioned.
    const again = await inboundMailService.resolve(queued.inboundId, 'admin@test', {
      trackingId,
      entityId: 'cisa',
    });
    expect(again).toEqual({ ok: false, error: 'already_resolved' });

    const spam = await inboundMailService.ingest({
      recipient: 'cisa-receipts@receipts.vera.report',
      from: 'spam@example.com',
      subject: 'unrelated',
      body: 'noise',
      messageId: `ses-spam-${trackingId}`,
    });
    const dismissed = await inboundMailService.dismiss(spam.inboundId, 'admin@test');
    expect(dismissed.ok).toBe(true);
    const mail = await disseminationPersistence.getInboundMail(spam.inboundId);
    expect(mail?.status).toBe('dismissed');
  });
});

describe('email adapter Reply-To (receipt mailbox)', () => {
  it('adds Reply-To when the receipt domain is configured', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';
    process.env.DISSEMINATION_RECEIPT_DOMAIN = 'receipts.vera.report';

    const { cisaAdapter } = await import('../../../../src/services/dissemination/adapters/cisa');
    const trackingId = await seedDispatchedCisaSubmission();
    const loaded = await disseminationService.buildView(trackingId);
    const { packetGenerator } = await import('../../../../src/services/dissemination/packetGenerator');
    const packet = await packetGenerator.generate(loaded!.view, 'cisa');
    const prep = await cisaAdapter.prepare(loaded!.view, packet);
    const mime = Buffer.from(await cisaAdapter.buildMime('sender@vera.test', prep.email!)).toString('utf8');

    expect(mime).toContain('Reply-To: cisa-receipts@receipts.vera.report');
  });

  it('omits Reply-To without the receipt domain', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';
    delete process.env.DISSEMINATION_RECEIPT_DOMAIN;

    const { cisaAdapter } = await import('../../../../src/services/dissemination/adapters/cisa');
    expect(cisaAdapter.replyToAddress()).toBeNull();
  });
});

afterAll(() => {
  dispatchWorker.stop();
});

it('reconciles a recipient CASE reference only within its receiving channel', async () => {
  const trackingId = await seedDispatchedCisaSubmission();
  const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  const caseReference = 'CASE-0123456789abcdef01234567';
  await disseminationPersistence.patchSubmission(sub.submissionId, { caseReference });
  const good = await inboundMailService.ingest({ recipient: 'cisa-receipts@vera.test', from: 'agency@example.org', subject: `Re: ${caseReference}`, body: 'Receipt pending' });
  expect(good.trackingId).toBe(trackingId);
  const wrongChannel = await inboundMailService.ingest({ recipient: 'osha-receipts@vera.test', from: 'agency@example.org', subject: caseReference, body: 'Receipt pending' });
  expect(wrongChannel.trackingId).toBeUndefined();
  expect(wrongChannel.autoParsed).toBe(false);
});

it('correlates standalone secure-packet replies after database reconnect without exposing reporter credentials', async () => {
  const trackingId = await seedDispatchedCisaSubmission();
  process.env.DISSEMINATION_RELAY_ENABLED = 'true';
  process.env.DISSEMINATION_RECEIPT_DOMAIN = 'vera.test';
  await disseminationPersistence.upsertDisposition({ ...(await disseminationPersistence.getDisposition(trackingId))!, narrativeReviewedAt: new Date() });
  // Secure legal packets run on legal-review consent, not agency consent (#926).
  await reportPersistenceService.patch(trackingId, { consent: { psst: { granted: false }, agency: false, legalReview: true, capturedAt: new Date(), textVersion: 'v4-legal-review' } });
  const sent = await sendSecurePacket({ trackingId, recipientEmail: 'counsel@example.org', actor: 'admin' });
  expect(sent.sent).toBe(true);
  const message = jest.mocked(emailNotificationService.sendSecurePacketEmail).mock.calls.at(-1)![0];
  expect(JSON.stringify(message)).not.toContain(trackingId);
  expect(message.trackingId).toMatch(/^CASE-/);
  await disseminationPersistence.disconnect();
  const reply = await inboundMailService.ingest({ recipient: message.replyTo!, from: 'counsel@example.org', subject: `Re: ${message.trackingId}`, body: 'Please contact counsel', messageId: 'secure-case-reply' });
  expect(reply.trackingId).toBe(trackingId);
  expect(reply.entityId).toBe('secure-link');
  expect(reply.autoParsed).toBe(false);
  const pending = await disseminationPersistence.listInboundMail('pending_review');
  expect(pending.find(m => m.inboundId === reply.inboundId)?.trackingId).toBe(trackingId);
  expect(await disseminationPersistence.resolveRecipientCase(message.trackingId, 'cisa')).toBeUndefined();
});

it.each(['missing', 'failed', 'untrusted'])('keeps %s sender authentication in manual review', async scenario => {
  const trackingId = await seedDispatchedCisaSubmission();
  const result = await inboundMailService.ingest({
    recipient: 'cisa-receipts@receipts.vera.report',
    from: scenario === 'untrusted' ? 'attacker@outside.invalid' : 'no-reply@cisa.dhs.gov',
    authentication: scenario === 'missing' ? undefined : { spf: 'PASS', dkim: 'PASS', dmarc: scenario === 'failed' ? 'FAIL' : 'PASS' },
    subject: trackingId, body: 'Your incident ID: CISA-2026-99101', messageId: `untrusted-${scenario}`,
  });
  expect(result.autoParsed).toBe(false);
  expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe('dispatched');
  expect(await disseminationPersistence.getReceiptsForReport(trackingId)).toHaveLength(0);
});
it('deduplicates concurrent authenticated email receipt and audit side effects', async () => {
  const trackingId = await seedDispatchedCisaSubmission();
  const payload = { recipient: 'cisa-receipts@receipts.vera.report', from: 'no-reply@cisa.dhs.gov',
    authentication: { spf: 'PASS', dkim: 'PASS', dmarc: 'PASS' }, subject: trackingId,
    body: 'Your incident ID: CISA-2026-99101', messageId: 'concurrent-authenticated-email' };
  await Promise.all([inboundMailService.ingest(payload), inboundMailService.ingest(payload)]);
  expect(await disseminationPersistence.getReceiptsForReport(trackingId)).toHaveLength(1);
  const audit = await disseminationPersistence.getAuditForReport(trackingId);
  expect(audit.filter(event => event.event === 'receipt_ack')).toHaveLength(1);
});
