jest.mock('../../../../src/services/dissemination/packetEvidence', () => ({ snapshotPacketEvidence: jest.fn().mockResolvedValue('a'.repeat(64)) }));
import { snapshotPacketEvidence } from '../../../../src/services/dissemination/packetEvidence';
import { verifySecureLinkToken } from '../../../../src/services/dissemination/secureLink';
/**
 * Secure-packet sender — the automatic on-submit send and its allowlist.
 *
 * These are the safety invariants of the reporter-reward auto-send:
 *   - the recipient allowlist (id → env address) can't be bypassed;
 *   - consent, report status, and redaction each gate the send;
 *   - a redaction outage fails closed (nothing sent, nothing persisted);
 *   - dryrun routes to the test inbox, never a real recipient.
 */

jest.mock('../../../../src/services/dissemination/disseminationService', () => ({
  disseminationService: { buildView: jest.fn(), consentFromReport: jest.fn() },
}));
jest.mock('../../../../src/services/dissemination/disseminationPersistence', () => ({
  disseminationPersistence: { getDisposition: jest.fn().mockResolvedValue({ narrativeReviewedAt: new Date() }), issueRecipientGrant: jest.fn().mockResolvedValue(undefined),
    registerRecipientCase: jest.fn().mockResolvedValue(undefined), appendAudit: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('../../../../src/services/dissemination/redactionService', () => ({
  redactionService: { propose: jest.fn() },
}));
jest.mock('../../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendSecurePacketEmail: jest.fn() },
}));
jest.mock('../../../../src/services/reportPersistence', () => ({
  reportPersistenceService: { patch: jest.fn().mockResolvedValue(undefined) },
}));
jest.mock('../../../../src/services/reportFieldCrypto', () => ({
  encryptContactValue: jest.fn((s: string) => `enc:${s}`),
}));

import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { redactionService } from '../../../../src/services/dissemination/redactionService';
import { emailNotificationService } from '../../../../src/services/emailNotification';
import { reportPersistenceService } from '../../../../src/services/reportPersistence';
import { sendSecurePacket, generateSecurePacket, autoSendSecurePackets, resolveRecipientEmail } from '../../../../src/services/dissemination/securePacketSender';

const ORIGINAL_ENV = process.env;

beforeEach(() => {
  process.env = {
    ...ORIGINAL_ENV,
    DISSEMINATION_WEBHOOK_SECRET: 'test-secret',
    DISSEMINATION_DRYRUN_INBOX: 'dryrun@test.local',
  };
  delete process.env.DISSEMINATION_MODE; // default dryrun
  delete process.env.DISSEMINATION_RECIPIENT_EMAILS;
  jest.clearAllMocks();
  jest.mocked(disseminationPersistence.getDisposition).mockResolvedValue({ narrativeReviewedAt: new Date() } as any);
  (disseminationService.buildView as jest.Mock).mockResolvedValue({
    narrativeReadable: true, report: { consent: { legalReview: true, textVersion: 'v4-legal-review' }, status: 'verified', processingStatus: 'completed', verification: { isLegitimate: true } },
    view: { narrative: 'raw' },
  });
  (disseminationService.consentFromReport as jest.Mock).mockReturnValue({ legalReview: true });
  (redactionService.propose as jest.Mock).mockResolvedValue({ redacted: 'scrubbed', notes: [], clean: false });
  (emailNotificationService.sendSecurePacketEmail as jest.Mock).mockResolvedValue({ sent: true });
});
afterEach(() => {
  process.env = ORIGINAL_ENV;
});

const baseReport = (over: Record<string, unknown> = {}): any => ({
  trackingId: 'VRA-0000000000000001',
  status: 'verified',
  processingStatus: 'completed',
  verification: { isLegitimate: true },
  consent: { legalReview: true, textVersion: 'v4-legal-review' },
  disseminationRecipients: ['whistleblower-org'],
  ...over,
});

describe('resolveRecipientEmail (server-side allowlist)', () => {
  it('resolves a known id from the env map', () => {
    process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'intake@wb.org' });
    expect(resolveRecipientEmail('whistleblower-org')).toBe('intake@wb.org');
  });

  it('returns null for an unknown id even if the env supplies an address', () => {
    process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ attacker: 'evil@x.com' });
    expect(resolveRecipientEmail('attacker')).toBeNull();
  });

  it('returns null when the env map is unset or malformed', () => {
    expect(resolveRecipientEmail('whistleblower-org')).toBeNull(); // unset
    process.env.DISSEMINATION_RECIPIENT_EMAILS = '{not valid json';
    expect(resolveRecipientEmail('whistleblower-org')).toBeNull();
  });

  it('returns null for a malformed address', () => {
    process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'not-an-email' });
    expect(resolveRecipientEmail('whistleblower-org')).toBeNull();
  });
});

describe('secure-packet recipient validation before issuance', () => {
  const invalidAddresses = [
    'a,b@c.org', 'person@b\u00fccher.org', 'r\u00e9cipient@example.org',
    `${'a'.repeat(65)}@example.org`, `a@${'b'.repeat(64)}.org`,
    'a..b@example.org', 'person@-example.org', 'person@example..org',
    'person@example.org\r\n', 'person@example.org\u0000',
    'one@example.org,two@example.org', 'Name <person@example.org>',
  ];

  it.each(invalidAddresses)('rejects invalid live recipient %j without issuing a link', async recipientEmail => {
    process.env.DISSEMINATION_MODE = 'live';
    const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail, actor: 'admin' });
    expect(result).toEqual({ sent: false, error: 'recipient_email_missing' });
    expect(snapshotPacketEvidence).not.toHaveBeenCalled();
    expect(disseminationPersistence.issueRecipientGrant).not.toHaveBeenCalled();
    expect(disseminationPersistence.registerRecipientCase).not.toHaveBeenCalled();
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });

  it.each(invalidAddresses)('rejects invalid configured allowlist address %j', recipientEmail => {
    process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': recipientEmail });
    expect(resolveRecipientEmail('whistleblower-org')).toBeNull();
  });

  it.each(invalidAddresses)('rejects invalid dryrun inbox %j without issuing a link', async inbox => {
    process.env.DISSEMINATION_DRYRUN_INBOX = inbox;
    const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail: '', actor: 'admin' });
    expect(result).toEqual({ sent: false, error: 'dryrun_inbox_invalid' });
    expect(snapshotPacketEvidence).not.toHaveBeenCalled();
    expect(disseminationPersistence.issueRecipientGrant).not.toHaveBeenCalled();
    expect(disseminationPersistence.registerRecipientCase).not.toHaveBeenCalled();
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });

  it.each(['live', 'dryrun'])('trims the actual %s destination while retaining case and plus addressing', async mode => {
    process.env.DISSEMINATION_MODE = mode;
    process.env.DISSEMINATION_DRYRUN_INBOX = '  Test+Inbox@example.org  ';
    const recipientEmail = '  Reviewer+Case@xn--bcher-kva.org  ';
    const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail, actor: 'admin' });
    const sentTo = mode === 'live' ? recipientEmail.trim() : 'Test+Inbox@example.org';
    expect(result).toEqual(expect.objectContaining({ sent: true, sentTo, mode }));
    expect(emailNotificationService.sendSecurePacketEmail).toHaveBeenCalledWith(expect.objectContaining({ recipient: sentTo }));
  });

  it('normalizes an allowlisted address without changing recipient identity', () => {
    process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': '  Reviewer+Case@example.org  ' });
    expect(resolveRecipientEmail('whistleblower-org')).toBe('Reviewer+Case@example.org');
  });

  it.each([undefined, '', '   '])('keeps missing dryrun inbox %j fail-closed', async inbox => {
    if (inbox === undefined) delete process.env.DISSEMINATION_DRYRUN_INBOX;
    else process.env.DISSEMINATION_DRYRUN_INBOX = inbox;
    const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail: '', actor: 'admin' });
    expect(result).toEqual({ sent: false, error: 'dryrun_inbox_not_configured' });
    expect(disseminationPersistence.issueRecipientGrant).not.toHaveBeenCalled();
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });

  it('never falls back to the live recipient when the dryrun inbox is invalid', async () => {
    process.env.DISSEMINATION_DRYRUN_INBOX = 'bad,inbox@example.org';
    const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail: 'reviewer@example.org', actor: 'admin' });
    expect(result).toEqual({ sent: false, error: 'dryrun_inbox_invalid' });
    expect(disseminationPersistence.issueRecipientGrant).not.toHaveBeenCalled();
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });
});

describe('autoSendSecurePackets gating', () => {
  it('sends nothing when the reporter chose no recipients', async () => {
    await autoSendSecurePackets(baseReport({ disseminationRecipients: [] }), 'narrative');
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
    expect(redactionService.propose).not.toHaveBeenCalled();
  });

  it('sends nothing without legal-review consent', async () => {
    await autoSendSecurePackets(baseReport({ consent: { legalReview: false, textVersion: 'v4-legal-review' } }), 'narrative');
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });

  it.each([{ status: 'rejected' }, { status: 'pending', verification: { isLegitimate: false, credibilityScore: 10 } }])('does not auto-forward an AI-rejected report, and audits the skip (%j)', async (fields) => {
    await autoSendSecurePackets(baseReport(fields), 'narrative');
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
    expect(disseminationPersistence.appendAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'secure_packet_autosend_skipped',
        detail: expect.objectContaining({ reason: 'report_rejected' }),
      }),
    );
  });

  it('fails closed when redaction is unavailable — nothing sent, nothing persisted', async () => {
    (redactionService.propose as jest.Mock).mockRejectedValue(new Error('VENICE_API_KEY missing'));
    await autoSendSecurePackets(baseReport(), 'narrative');
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
    expect(reportPersistenceService.patch).not.toHaveBeenCalled();
    expect(disseminationPersistence.appendAudit).toHaveBeenCalledWith(
      expect.objectContaining({ detail: expect.objectContaining({ reason: 'redaction_unavailable' }) }),
    );
  });

  it('dryrun happy path: scrubs the narrative, persists it, routes to the dryrun inbox', async () => {
    await autoSendSecurePackets(baseReport(), 'raw narrative');
    expect(redactionService.propose).toHaveBeenCalledWith('raw narrative');
    expect(reportPersistenceService.patch).toHaveBeenCalledWith(
      'VRA-0000000000000001',
      expect.objectContaining({ encryptedDisseminationNarrative: expect.stringContaining('enc:scrubbed') }),
    );
    expect(emailNotificationService.sendSecurePacketEmail).toHaveBeenCalledWith(
      expect.objectContaining({ recipient: 'dryrun@test.local', dryrun: true }),
    );
  });
});

describe('secure-packet Reply-To gating (relay flag, #524 review note)', () => {
  it('omits Reply-To when the receipt domain is set but the relay is not enabled', async () => {
    process.env.DISSEMINATION_RECEIPT_DOMAIN = 'receipts.example.com';
    delete process.env.DISSEMINATION_RELAY_ENABLED;
    await autoSendSecurePackets(baseReport(), 'n');
    expect(emailNotificationService.sendSecurePacketEmail).toHaveBeenCalledWith(
      expect.objectContaining({ replyTo: undefined }),
    );
  });

  it('attaches Reply-To only when the relay is explicitly enabled', async () => {
    process.env.DISSEMINATION_RECEIPT_DOMAIN = 'receipts.example.com';
    process.env.DISSEMINATION_RELAY_ENABLED = 'true';
    await autoSendSecurePackets(baseReport(), 'n');
    expect(emailNotificationService.sendSecurePacketEmail).toHaveBeenCalledWith(
      expect.objectContaining({ replyTo: 'secure-link-receipts@receipts.example.com' }),
    );
  });
});

 it.each([
   { processingStatus: 'failed' }, { processingStatus: 'processing' },
   { processingStatus: undefined }, { verification: undefined }, { status: 'dismissed' },
 ])('does not send an ineligible report %j', async override => {
   process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'intake@wb.org' });
   await autoSendSecurePackets(baseReport(override), 'narrative');
   expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
   expect(redactionService.propose).not.toHaveBeenCalled();
 });

it('refuses to send when durable CASE correlation cannot be saved', async () => {
  process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'intake@wb.org' });
  jest.mocked(disseminationPersistence.registerRecipientCase).mockRejectedValueOnce(new Error('storage unavailable'));
  await autoSendSecurePackets(baseReport(), 'narrative');
  expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
});

it.each(['dismissed', 'rejected'])('rechecks %s report after asynchronous redaction before emailing', async status => {
  process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'intake@wb.org' });
  jest.mocked(disseminationService.buildView).mockResolvedValue({ report: { status, consent: { legalReview: true, textVersion: 'v4-legal-review' } } } as any);
  await autoSendSecurePackets(baseReport(), 'narrative');
  expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
});

it.each(['unreviewed', 'unreadable'])('refuses standalone manual packet links for %s narrative', async state => {
  if (state === 'unreviewed') jest.mocked(disseminationPersistence.getDisposition).mockResolvedValue(null);
  else jest.mocked(disseminationService.buildView).mockResolvedValue({ report: { consent: { legalReview: true, textVersion: 'v4-legal-review' } }, narrativeReadable: false } as any);
  const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', recipientEmail: 'counsel@example.org', actor: 'admin' });
  expect(result.sent).toBe(false);
  expect(result.error).toBe('narrative_review_required');
  expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
});

describe('generate-only admin packet', () => {
  const generate = async () => (await import('../../../../src/services/dissemination/securePacketSender')).generateSecurePacket({ trackingId: 'VRA-0000000000000001', actor: 'reviewer@test.local' });
  it('generates an audited link with no email or dryrun inbox required', async () => {
    delete process.env.DISSEMINATION_DRYRUN_INBOX;
    const result = await generate();
    expect(result.url).toMatch(/secure-packet/);
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
    expect(disseminationPersistence.appendAudit).toHaveBeenCalledWith(expect.objectContaining({ event: 'secure_packet_generated' }));
    expect(JSON.stringify(jest.mocked(disseminationPersistence.appendAudit).mock.calls)).not.toContain(result.url);
  });
  it('refuses generation without reporter consent', async () => {
    jest.mocked(disseminationService.consentFromReport).mockReturnValue({ legalReview: false } as any);
    expect(await generate()).toEqual({ error: 'reporter_consent_missing' });
    expect(disseminationPersistence.appendAudit).not.toHaveBeenCalled();
  });
  it('refuses unreviewed narrative', async () => {
    jest.mocked(disseminationPersistence.getDisposition).mockResolvedValue({} as any);
    expect(await generate()).toEqual({ error: 'narrative_review_required' });
  });
  it('returns no link when audit persistence fails', async () => {
    jest.mocked(disseminationPersistence.appendAudit).mockRejectedValueOnce(new Error('offline'));
    await expect(generate()).rejects.toThrow('offline');
    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();
  });
});

it('includes the evidence snapshot by default when generating an admin link', async () => {
  const result = await generateSecurePacket({ trackingId: 'VRA-0000000000000001', actor: 'admin@test.local' });
  expect(result.url).toBeDefined();
  const scope = verifySecureLinkToken(result.url!.split('/').pop()!);
  expect(scope?.evidenceDigest).toBe('a'.repeat(64));
  expect(snapshotPacketEvidence).toHaveBeenCalledWith('VRA-0000000000000001');
});
it('includes the evidence snapshot by default when emailing an admin link', async () => {
  const result = await sendSecurePacket({ trackingId: 'VRA-0000000000000001', actor: 'admin@test.local', recipientEmail: 'recipient@test.local' });
  expect(result.sent).toBe(true);
  const scope = verifySecureLinkToken(result.url!.split('/').pop()!);
  expect(scope?.evidenceDigest).toBe('a'.repeat(64));
});
