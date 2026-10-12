/**
 * Auto-send on submission — the durable side effects, against a real MongoDB.
 *
 * The unit suite proves the GATING of `autoSendSecurePackets` (consent, status,
 * fail-closed) with every collaborator mocked. What a mock can't show is that the
 * writes actually land: that the scrubbed dissemination narrative is persisted
 * encrypted and the send is audited — and, on the fail-closed path, that NOTHING
 * is written.
 *
 * Here the two true externals stay mocked (the redaction AI and the SMTP send) plus
 * buildView (report eligibility), while reportPersistenceService and
 * disseminationPersistence run against a real in-memory MongoDB. We then read the
 * database back to confirm what did — and didn't — persist.
 *
 * tests/integration/services → runs in the CI gate; Mongo only, no proof server.
 */

jest.mock('../../../src/services/dissemination/disseminationService', () => ({
  disseminationService: { buildView: jest.fn(), consentFromReport: jest.fn() },
}));
jest.mock('../../../src/services/dissemination/redactionService', () => ({
  redactionService: { propose: jest.fn() },
}));
jest.mock('../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendSecurePacketEmail: jest.fn() },
}));

import { MongoMemoryServer } from 'mongodb-memory-server';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { redactionService } from '../../../src/services/dissemination/redactionService';
import { emailNotificationService } from '../../../src/services/emailNotification';
import { autoSendSecurePackets } from '../../../src/services/dissemination/securePacketSender';
import { reportPersistenceService } from '../../../src/services/reportPersistence';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { decryptContactValue } from '../../../src/services/reportFieldCrypto';

let mongoServer: MongoMemoryServer;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'REWARD_ENCRYPTION_KEY', 'DISSEMINATION_MODE', 'DISSEMINATION_DRYRUN_INBOX', 'DISSEMINATION_RECIPIENT_EMAILS', 'DISSEMINATION_WEBHOOK_SECRET'] as const;
const savedEnv: Record<string, string | undefined> = {};

const eligible = (trackingId: string) => ({
  trackingId,
  status: 'verified',
  processingStatus: 'completed',
  verification: { isLegitimate: true, credibilityScore: 80, category: 'fraud' },
  consent: { agency: false, legalReview: true, press: false, psst: { treatment: 'hold-encrypted' }, textVersion: 'v4-legal-review' },
  disseminationRecipients: ['whistleblower-org'],
  createdAt: new Date('2026-01-02T00:00:00.000Z'),
  updatedAt: new Date('2026-01-02T00:00:00.000Z'),
});

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_autosend';
  process.env.REWARD_ENCRYPTION_KEY = 'autosend-integration-test-key';
  process.env.DISSEMINATION_DRYRUN_INBOX = 'dryrun@test.local';
  process.env.DISSEMINATION_RECIPIENT_EMAILS = JSON.stringify({ 'whistleblower-org': 'intake@wb.org' });
  process.env.DISSEMINATION_WEBHOOK_SECRET = 'autosend-integration-secret'; // seals the secure-link token
  delete process.env.DISSEMINATION_MODE; // default dryrun

  // Seed the reports so reportPersistenceService.patch() has something to update.
  await reportPersistenceService.upsert(eligible('VRA-AUTOSEND00000HAPPY') as any);
  await reportPersistenceService.upsert(eligible('VRA-AUTOSEND0000CLOSED') as any);
});

afterAll(async () => {
  await reportPersistenceService.close().catch(() => {});
  await disseminationPersistence.disconnect().catch(() => {});
  if (mongoServer) await mongoServer.stop();
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

beforeEach(() => {
  jest.clearAllMocks();
  // buildView / consent report eligibility (externals to the persistence under test).
  (disseminationService.buildView as jest.Mock).mockImplementation(async (trackingId: string) => ({
    report: { trackingId, status: 'verified', processingStatus: 'completed', verification: { isLegitimate: true }, consent: { legalReview: true, textVersion: 'v4-legal-review' } },
    view: { trackingId, narrative: 'scrubbed' },
    narrativeReadable: true,
  }));
  (disseminationService.consentFromReport as jest.Mock).mockReturnValue({ legalReview: true });
  (redactionService.propose as jest.Mock).mockResolvedValue({ redacted: 'scrubbed narrative', notes: [], clean: false });
  (emailNotificationService.sendSecurePacketEmail as jest.Mock).mockResolvedValue({ sent: true });
});

describe('happy dryrun path persists the real side effects', () => {
  it('freezes the scrubbed narrative encrypted, routes to the dryrun inbox, and audits the send', async () => {
    const tid = 'VRA-AUTOSEND00000HAPPY';
    await autoSendSecurePackets(eligible(tid) as any, 'raw self-identifying narrative');

    // Routed to the dryrun inbox, never the real agency address.
    expect(emailNotificationService.sendSecurePacketEmail).toHaveBeenCalledWith(
      expect.objectContaining({ recipient: 'dryrun@test.local', dryrun: true }),
    );

    // The scrubbed narrative is persisted, encrypted at rest, and decrypts back.
    const stored = await reportPersistenceService.get(tid);
    expect(stored!.encryptedDisseminationNarrative).toBeTruthy();
    expect(stored!.encryptedDisseminationNarrative).not.toContain('scrubbed narrative'); // not plaintext
    expect(decryptContactValue(stored!.encryptedDisseminationNarrative!)).toBe('scrubbed narrative');

    // The send is durably audited in MongoDB.
    const audit = await disseminationPersistence.getAuditForReport(tid);
    expect(audit.some((e) => e.event === 'secure_packet_emailed')).toBe(true);
  });
});

describe('fail-closed on redaction outage leaves the database clean', () => {
  it('sends nothing, persists no narrative, and records the skip', async () => {
    (redactionService.propose as jest.Mock).mockRejectedValue(new Error('VENICE_API_KEY missing'));
    const tid = 'VRA-AUTOSEND0000CLOSED';
    await autoSendSecurePackets(eligible(tid) as any, 'raw self-identifying narrative');

    expect(emailNotificationService.sendSecurePacketEmail).not.toHaveBeenCalled();

    const stored = await reportPersistenceService.get(tid);
    expect(stored!.encryptedDisseminationNarrative).toBeFalsy(); // nothing frozen

    const audit = await disseminationPersistence.getAuditForReport(tid);
    expect(audit.some((e) => e.event === 'secure_packet_emailed')).toBe(false); // nothing emailed
    expect(audit.some((e) => e.event === 'secure_packet_autosend_skipped')).toBe(true); // skip recorded
  });
});
