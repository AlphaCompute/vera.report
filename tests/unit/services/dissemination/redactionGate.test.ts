import { packetGenerator } from '../../../../src/services/dissemination/packetGenerator';
import { getAdapter } from '../../../../src/services/dissemination/adapters/registry';
/**
 * Review fix H1: an UN-REVIEWED narrative must never be dispatched to a real
 * agency. In live mode the dispatch worker defers a channel with
 * `awaiting_narrative_review` until an admin either freezes a redacted
 * narrative (narrativeOverride) or marks the narrative reviewed with no
 * redaction needed (markReviewedClean). Once reviewed, the channel dispatches.
 *
 * Persistence uses disposable MongoDB; evidence storage and SES are mocked out.
 */

import crypto from 'node:crypto';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import { dispatchWorker } from '../../../../src/services/dissemination/dispatchWorker';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { redactionService } from '../../../../src/services/dissemination/redactionService';
import { reportPersistenceService } from '../../../../src/services/reportPersistence';
import { encryptContactValue } from '../../../../src/services/reportFieldCrypto';

jest.mock('../../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: {
    uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'QmPacketCid' }),
    unpin: jest.fn().mockResolvedValue(undefined),
  },
}));

// sendAlert is fire-and-forget on the dispatch path (dispatchWorker/receiptTracker);
// unmocked it leaks an Auth0 fetch past teardown (the SES mock below only covers the send).
jest.mock('../../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined) },
}));

// Live-mode dispatch would otherwise call SES; resolve the send deterministically.
jest.mock('@aws-sdk/client-sesv2', () => ({
  SESv2Client: jest.fn().mockImplementation(() => ({
    send: jest.fn().mockResolvedValue({ MessageId: 'ses-msg-h1' }),
  })),
  SendEmailCommand: jest.fn().mockImplementation((input) => ({ input })),
}));

const ORIGINAL_ENV = { ...process.env };

function uniqueTrackingId(): string {
  return `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

async function seedApprovedReport(): Promise<string> {
  const trackingId = uniqueTrackingId();
  await reportPersistenceService.upsert({
    trackingId,
    evidenceHash: 'a'.repeat(64),
    status: 'verified',
    encryptedDescription: encryptContactValue('As the only engineer hired last March, I saw the CFO falsify invoices.'),
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
  const result = await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
  if ('error' in result) throw new Error(`approve failed: ${result.error}`);
  return trackingId;
}

describe('H1 gate: un-reviewed narrative is never dispatched to a real agency', () => {
  it('defers in live mode until reviewed, then dispatches after mark-clean', async () => {
    try {
      process.env.DISSEMINATION_MODE = 'live';
      // This suite tests narrative consent; outbound SES is mocked.
      process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({
        'contact@mail.cisa.dhs.gov': { allowUnencrypted: true, reason: 'Synthetic fixture; SES is mocked.' },
      });
      process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';

      const trackingId = await seedApprovedReport();

      // No review yet → the worker defers the channel rather than dispatching.
      await dispatchWorker.tick();
      let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe('deferred');
      expect(sub.lastError).toBe('awaiting_narrative_review');
      expect(sub.dispatchedAt).toBeUndefined();

      // Admin marks the narrative reviewed (no redaction needed).
      const marked = await redactionService.markReviewedClean(trackingId, 'admin@test');
      expect(marked.ok).toBe(true);

      // Clear the backoff so the deferred submission is claimable this tick.
      await disseminationPersistence.patchSubmission(sub.submissionId, {
        nextAttemptAt: new Date(Date.now() - 1000),
      });

      // Now it dispatches (SES returns a provisional receipt, so the channel
      // advances past 'dispatched' to 'receipted').
      await dispatchWorker.tick();
      [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(['dispatched', 'receipted']).toContain(sub.state);
      expect(sub.dispatchedAt).toBeDefined();
      expect(sub.lastError).toBeUndefined();
      const audit = await disseminationPersistence.getAuditForReport(trackingId);
      expect(audit).toEqual(expect.arrayContaining([expect.objectContaining({
        trackingId, entityId: 'cisa', event: 'email_plaintext_exception_attempted',
        detail: { recipient: 'contact@mail.cisa.dhs.gov', reason: 'Synthetic fixture; SES is mocked.' },
      })]));
      const send = (require('@aws-sdk/client-sesv2').SESv2Client as jest.Mock).mock.results.flatMap((r: any) => r.value?.send?.mock?.calls || []);
      expect(send.length).toBeGreaterThan(0);
      for (const call of send) expect(Buffer.from(call[0].input.Content.Raw.Data).toString()).not.toContain(trackingId);

    } finally {
      process.env = { ...ORIGINAL_ENV };
    }
  });

  it('an accepted redaction override also satisfies the gate', async () => {
    try {
      process.env.DISSEMINATION_MODE = 'live';
      // This suite tests narrative consent; outbound SES is mocked.
      process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({
        'contact@mail.cisa.dhs.gov': { allowUnencrypted: true, reason: 'Synthetic fixture; SES is mocked.' },
      });
      process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';

      const trackingId = await seedApprovedReport();

      await dispatchWorker.tick();
      let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe('deferred');
      expect(sub.lastError).toBe('awaiting_narrative_review');

      // Freeze a redacted narrative onto the disposition.
      const accepted = await redactionService.accept(
        trackingId,
        '[ROLE], I saw the CFO falsify invoices.',
        ['Removed self-identifying hiring detail'],
        'admin@test',
      );
      expect(accepted.ok).toBe(true);

      await disseminationPersistence.patchSubmission(sub.submissionId, {
        nextAttemptAt: new Date(Date.now() - 1000),
      });

      await dispatchWorker.tick();
      [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(['dispatched', 'receipted']).toContain(sub.state);
    } finally {
      process.env = { ...ORIGINAL_ENV };
    }
  });

  it('dryrun mode is not gated but sends the internal inbox no report content', async () => {
    try {
      process.env.DISSEMINATION_MODE = 'dryrun';
      process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';
      process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
      delete process.env.DISSEMINATION_EMAIL_POLICIES;
      const sesCalls = () => (require('@aws-sdk/client-sesv2').SESv2Client as jest.Mock).mock.results.flatMap((r: any) => r.value?.send?.mock?.calls || []);
      const before = sesCalls().length;

      const trackingId = await seedApprovedReport();

      // No review, but dryrun dispatches straight to the internal inbox.
      await dispatchWorker.tick();
      const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(['dispatched', 'receipted']).toContain(sub.state);
      expect(sub.lastError).not.toBe('awaiting_narrative_review');

      // ...as a content-free notice: no unreviewed narrative, no evidence archive.
      const sent = sesCalls().slice(before);
      expect(sent).toHaveLength(1);
      const raw = Buffer.from(sent[0][0].input.Content.Raw.Data).toString();
      expect(raw).toContain('no report content');
      expect(raw).not.toContain('CFO');
      expect(raw).not.toContain('Content-Disposition: attachment');
    } finally {
      process.env = { ...ORIGINAL_ENV };
    }
  });

  it('defers, not dead-letters as uncertain, when the dryrun inbox key cannot encrypt', async () => {
    try {
      process.env.DISSEMINATION_MODE = 'dryrun';
      process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';
      process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
      process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({
        'internal@vera.test': { publicKey: 'not a key', fingerprint: 'a'.repeat(40) },
      });

      const trackingId = await seedApprovedReport();
      await dispatchWorker.tick();
      const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe('deferred');
      expect(sub.lastError).toContain('no plaintext email was sent');
      expect(sub.dispatchInFlightAt).toBeUndefined();
      expect(sub.dispatchedAt).toBeUndefined();
    } finally {
      process.env = { ...ORIGINAL_ENV };
    }
  });
});

for (const phase of ['before-worker', 'during-packet'] as const) {
  it.each(['consent-revoked', 'dismissed', 'closed', 'suppressed', 'unreadable'])('blocks %s sharing changed ' + phase, async change => {
    process.env.DISSEMINATION_MODE = 'live';
    process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
    const trackingId = await seedApprovedReport();
    await redactionService.markReviewedClean(trackingId, 'admin');
    const mutate = async () => {
      if (change === 'consent-revoked') {
        const report = await reportPersistenceService.get(trackingId);
        await reportPersistenceService.patch(trackingId, { consent: { ...report!.consent!, agency: false } });
      } else if (change === 'dismissed') await reportPersistenceService.patch(trackingId, { status: 'dismissed' });
      else if (change === 'unreadable') await reportPersistenceService.patch(trackingId, { encryptedDescription: 'corrupt-ciphertext' });
      else await disseminationPersistence.setDispositionChannelState(trackingId, 'cisa', change as 'closed' | 'suppressed');
    };
    const dispatch = jest.spyOn(getAdapter('cisa')!, 'dispatch');
    if (phase === 'before-worker') await mutate();
    else {
      const generate = packetGenerator.generate.bind(packetGenerator);
      jest.spyOn(packetGenerator, 'generate').mockImplementationOnce(async (...args) => { const packet = await generate(...args); await mutate(); return packet; });
    }
    try {
      await dispatchWorker.tick();
      expect(dispatch).not.toHaveBeenCalled();
      expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].dispatchInFlightAt).toBeUndefined();
      if (change === 'closed' || change === 'suppressed') expect((await disseminationPersistence.getDisposition(trackingId))!.channels[0].state).toBe(change);
    } finally { jest.restoreAllMocks(); process.env = { ...ORIGINAL_ENV }; }
  });
}
it('withdrawal during packet preparation wins against the subsequent dispatch claim', async () => {
  process.env.DISSEMINATION_MODE = 'live'; process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
  const trackingId = await seedApprovedReport();
  await redactionService.markReviewedClean(trackingId, 'admin');
  const adapter = getAdapter('cisa')!;
  const prepare = adapter.prepare.bind(adapter);
  const dispatch = jest.spyOn(adapter, 'dispatch');
  jest.spyOn(adapter, 'prepare').mockImplementationOnce(async (...args) => {
    const result = await prepare(...args);
    expect(await disseminationService.withdraw(trackingId, 'cisa', 'admin')).toEqual({ ok: true });
    return result;
  });
  try {
    await dispatchWorker.tick();
    expect(dispatch).not.toHaveBeenCalled();
    expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe('withdrawn');
  } finally { jest.restoreAllMocks(); process.env = { ...ORIGINAL_ENV }; }
});
it('refuses withdrawal after an atomic dispatch claim', async () => {
  const trackingId = await seedApprovedReport();
  const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  await disseminationPersistence.patchSubmission(sub.submissionId, { state: 'packet_ready' });
  expect(await disseminationPersistence.claimDispatch(sub.submissionId)).toBe(true);
  expect(await disseminationService.withdraw(trackingId, 'cisa', 'admin')).toEqual({ ok: false, error: 'dispatch_started_or_channel_changed' });
  expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe('packet_ready');
});

it('defers a rendered packet when a reviewer replaces its narrative during preparation', async () => {
  process.env.DISSEMINATION_MODE = 'live';
  process.env.DISSEMINATION_SENDER_EMAIL = 'sender@vera.test';
  const trackingId = await seedApprovedReport();
  await redactionService.markReviewedClean(trackingId, 'admin');
  const adapter = getAdapter('cisa')!;
  const dispatch = jest.spyOn(adapter, 'dispatch');
  const prepare = adapter.prepare.bind(adapter);
  jest.spyOn(adapter, 'prepare').mockImplementationOnce(async (...args) => {
    const prepared = await prepare(...args);
    expect(await redactionService.accept(trackingId, '[REPORTER] saw falsified invoices.', [], 'admin')).toEqual({ ok: true });
    return prepared;
  });
  try {
    await dispatchWorker.tick();
    expect(dispatch).not.toHaveBeenCalled();
    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('deferred');
    expect(sub.lastError).toBe('sharing_authorization_changed');
    expect(sub.dispatchInFlightAt).toBeUndefined();
  } finally { jest.restoreAllMocks(); process.env = { ...ORIGINAL_ENV }; }
});
