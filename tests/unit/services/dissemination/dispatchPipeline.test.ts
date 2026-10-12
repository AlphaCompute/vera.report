import { logger } from '../../../../src/utils/logger';
/**
 * Pipeline tests: consent gating on approval, dispatch idempotency,
 * retry/backoff, dead-lettering, and the Psst handoff lifecycle.
 *
 * Persistence uses disposable MongoDB; external delivery is mocked out.
 */

import crypto from 'node:crypto';
import { getAdapter } from '../../../../src/services/dissemination/adapters/registry';
import { DispatchNotSentError } from '../../../../src/services/dissemination/types';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import { disseminationService, idempotencyKeyFor } from '../../../../src/services/dissemination/disseminationService';
import { dispatchWorker, DispatchWorker, backoffDelayMs } from '../../../../src/services/dissemination/dispatchWorker';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { packetGenerator } from '../../../../src/services/dissemination/packetGenerator';
import { reportPersistenceService, type ReportRecord } from '../../../../src/services/reportPersistence';
import { encryptContactValue } from '../../../../src/services/reportFieldCrypto';

jest.mock('../../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: {
    uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'QmPacketCid' }),
    unpin: jest.fn().mockResolvedValue(undefined),
  },
}));

// sendAlert is fire-and-forget on the dispatch path (dispatchWorker/receiptTracker);
// unmocked it leaks an Auth0 fetch + AWS SES call past teardown and force-exits the worker.
jest.mock('../../../../src/services/emailNotification', () => ({
  emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined) },
}));

const ORIGINAL_ENV = { ...process.env };

test('close drains an outstanding claim and prevents additional queue passes', async () => {
  const worker = new DispatchWorker();
  let release!: (value: null) => void;
  const claimed = new Promise<null>(resolve => { release = resolve; });
  const claim = jest.spyOn(disseminationPersistence, 'claimNextDueSubmission').mockReturnValueOnce(claimed);
  const run = worker.tick();
  let closed = false;
  try {
    const closing = worker.close().then(() => { closed = true; });
    await Promise.resolve();
    expect(closed).toBe(false);
    release(null);
    await Promise.all([run, closing]);
    await worker.tick();
    expect(claim).toHaveBeenCalledTimes(1);
  } finally { release(null); await run; await worker.close(); claim.mockRestore(); }
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

function uniqueTrackingId(): string {
  return `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

async function seedReport(overrides: Partial<ReportRecord> = {}): Promise<string> {
  const trackingId = uniqueTrackingId();
  await reportPersistenceService.upsert({
    trackingId,
    evidenceHash: 'a'.repeat(64),
    status: 'verified',
    categories: ['cyber-security'],
    urgency: 'high',
    consent: {
      psst: { granted: true, treatment: 'hold-encrypted' },
      agency: true,
      capturedAt: new Date(),
      textVersion: 'v1',
    },
    zkProof: {
      proofHash: '0xproof',
      nullifier: '0xnull',
      publicSignals: [],
      verified: true,
    },
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });
  return trackingId;
}

describe('idempotency key', () => {
  it('is deterministic and unique per (report, entity, packet version)', () => {
    const a = idempotencyKeyFor('VRA-X', 'cisa', 1);
    expect(idempotencyKeyFor('VRA-X', 'cisa', 1)).toBe(a);
    expect(idempotencyKeyFor('VRA-X', 'gao-fraudnet', 1)).not.toBe(a);
    expect(idempotencyKeyFor('VRA-Y', 'cisa', 1)).not.toBe(a);
    expect(idempotencyKeyFor('VRA-X', 'cisa', 2)).not.toBe(a);
  });
});

describe('consent gating on approval (FR-8)', () => {
  it('refuses everything when the report has no consent record', async () => {
    const trackingId = await seedReport({ consent: undefined });
    const result = await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    expect(result).toEqual({ error: 'no_consent_on_record' });
  });

  it('refuses agency channels without agency consent, but allows Psst with Psst consent', async () => {
    const trackingId = await seedReport({
      consent: {
        psst: { granted: true, treatment: 'hold-encrypted' },
        agency: false,
        capturedAt: new Date(),
        textVersion: 'v1',
      },
    });

    const result = await disseminationService.approve(trackingId, ['cisa', 'psst-safe'], 'admin@test');
    expect('error' in result).toBe(false);
    if ('error' in result) return;

    expect(result.refused).toEqual([{ entityId: 'cisa', reason: 'reporter_consent_missing' }]);
    expect(result.disposition.channels.map((c) => c.entityId)).toEqual(['psst-safe']);
  });

  it('allows securedrop only with press consent (reporter-elected press disclosure)', async () => {
    const trackingId = await seedReport({
      consent: {
        psst: { granted: false },
        agency: false,
        press: true,
        capturedAt: new Date(),
        textVersion: 'v2',
      },
    });

    const result = await disseminationService.approve(trackingId, ['securedrop'], 'admin@test');
    expect('error' in result).toBe(false);
    if ('error' in result) return;

    expect(result.refused).toEqual([]);
    expect(result.disposition.channels.map((c) => c.entityId)).toEqual(['securedrop']);
  });

  it('refuses securedrop when press consent is missing (fail-closed)', async () => {
    const trackingId = await seedReport({
      consent: {
        psst: { granted: true, treatment: 'hold-encrypted' },
        agency: true,
        press: false,
        capturedAt: new Date(),
        textVersion: 'v2',
      },
    });

    const result = await disseminationService.approve(trackingId, ['securedrop'], 'admin@test');
    expect(result).toMatchObject({ error: expect.stringContaining('no_channels_approved') });
  });

  it('refuses unknown entities and entities without adapters this phase', async () => {
    const trackingId = await seedReport();
    const result = await disseminationService.approve(
      trackingId,
      ['not-a-real-entity', 'irs-ci'],
      'admin@test',
    );
    expect(result).toMatchObject({ error: expect.stringContaining('no_channels_approved') });
  });

  it('snapshots consent on the disposition', async () => {
    const trackingId = await seedReport();
    const result = await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    if ('error' in result) throw new Error('unexpected refusal');
    expect(result.disposition.consentSnapshot.agency).toBe(true);
    expect(result.disposition.consentSnapshot.textVersion).toBe('v1');
    expect(result.disposition.approvedBy).toBe('admin@test');
  });

  it('re-approving the same channel is a no-op (unique idempotency key)', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    const submissions = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(submissions).toHaveLength(1);
  });
});

describe('routing recommendations', () => {
  it('surfaces recorded consent without approving or dispatching a channel', async () => {
    const trackingId = await seedReport();

    const plan = await disseminationService.plan(trackingId);

    expect(plan?.consent).toMatchObject({
      agency: true,
      psst: { granted: true, treatment: 'hold-encrypted' },
      textVersion: 'v1',
    });
    expect(plan?.channels.length).toBeGreaterThan(0);
    expect(await disseminationPersistence.getDisposition(trackingId)).toBeNull();
    expect(await disseminationPersistence.getSubmissionsForReport(trackingId)).toEqual([]);
    expect(await disseminationPersistence.getAuditForReport(trackingId)).toEqual([]);
  });

  it('returns a consent-free recommendation without creating dispatch state', async () => {
    const trackingId = await seedReport({ consent: undefined });

    const plan = await disseminationService.plan(trackingId);

    expect(plan?.consent).toBeNull();
    expect(plan?.channels.every((channel) => channel.consentSatisfied === false)).toBe(true);
    expect(await disseminationPersistence.getDisposition(trackingId)).toBeNull();
    expect(await disseminationPersistence.getSubmissionsForReport(trackingId)).toEqual([]);
  });
});

describe('backoff', () => {
  it('doubles per attempt and caps at six hours', () => {
    expect(backoffDelayMs(0)).toBe(60_000);
    expect(backoffDelayMs(1)).toBe(120_000);
    expect(backoffDelayMs(2)).toBe(240_000);
    expect(backoffDelayMs(20)).toBe(6 * 60 * 60 * 1000);
  });
});

describe('dispatch worker', () => {
  it('fences an old worker after a stale claim is replaced', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    async function claimTarget(now: Date) {
      for (let i = 0; i < 100; i++) {
        const claim = await disseminationPersistence.claimNextDueSubmission(now);
        if (!claim || claim.trackingId === trackingId) return claim;
      }
      throw new Error('Target claim not found');
    }
    const old = (await claimTarget(new Date()))!;
    const replacement = (await claimTarget(new Date(Date.now() + 11 * 60 * 1000)))!;
    expect(old.claimToken).toBeDefined();
    expect(replacement.claimToken).not.toBe(old.claimToken);
    expect(await disseminationPersistence.claimDispatch(old.submissionId, old.claimToken)).toBe(false);
    expect(await disseminationPersistence.updateUnsentSubmission(old.submissionId, { state: 'deferred' }, false, old.claimToken)).toBe(false);
    expect(await disseminationPersistence.claimDispatch(replacement.submissionId, replacement.claimToken)).toBe(true);
    expect(await disseminationPersistence.patchSubmission(old.submissionId, { state: 'deferred', dispatchInFlightAt: undefined }, old.claimToken)).toBe(false);
    const actual = await disseminationPersistence.getSubmission(old.submissionId);
    expect(actual?.state).toBe('packet_ready');
    expect(actual?.dispatchInFlightAt).toBeDefined();
    expect(actual?.claimToken).toBe(replacement.claimToken);
    // Finish the synthetic uncertain row so later suite cases do not consume it.
    await disseminationPersistence.patchSubmission(old.submissionId, { state: 'failed' }, replacement.claimToken);
  });

  it('keeps failure details in storage and out of operator email', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(sub.submissionId, { attempts: 4 });
    const send = jest.spyOn(getAdapter('psst-safe')!, 'dispatch').mockRejectedValue(new DispatchNotSentError('<img src=x onerror=alert(1)>'));
    try {
      await dispatchWorker.tick();
      await new Promise(resolve => setImmediate(resolve));
      const alerts = require('../../../../src/services/emailNotification').emailNotificationService.sendAlert.mock.calls;
      const alert = alerts.find((call: string[]) => call[1] === 'Dissemination dispatch failed');
      expect(alert).toBeDefined();
      expect(JSON.stringify(alert)).not.toContain(trackingId);
      expect(JSON.stringify(alert)).not.toContain(sub.submissionId);
      expect(JSON.stringify(alert)).not.toContain('onerror');
      expect((await disseminationPersistence.getSubmission(sub.submissionId))?.lastError).toBe('<img src=x onerror=alert(1)>');
    } finally { send.mockRestore(); }
  });

  it.each(['disposition', 'audit', 'outcome', 'outcome-acknowledgement'] as const)('does not resend after accepted delivery and a failed %s write', async (failure) => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    const adapter = getAdapter('psst-safe')!;
    const send = jest.spyOn(adapter, 'dispatch').mockResolvedValue({ outcome: 'sent' });
    const target = failure === 'disposition' ? 'setDispositionChannelState' : failure === 'audit' ? 'appendAudit' : 'patchSubmission';
    const original = disseminationPersistence[target].bind(disseminationPersistence);
    const write = jest.spyOn(disseminationPersistence, target).mockImplementation((...args: any[]) => {
      const isOutcome = target === 'patchSubmission' && args[1]?.state === 'dispatched';
      const isDisposition = target === 'setDispositionChannelState' && args[2] === 'dispatched';
      const isAudit = target === 'appendAudit' && args[0]?.event === 'dispatched';
      if (isOutcome && failure === 'outcome-acknowledgement') return (original as any)(...args).then(() => { throw new Error('injected database failure'); });
      if (isOutcome || isDisposition || isAudit) return Promise.reject(new Error('injected database failure'));
      return (original as any)(...args);
    });
    try {
      if (failure.startsWith('outcome')) await dispatchWorker.tick();
      else await expect(dispatchWorker.tick()).rejects.toThrow('injected database failure');
      write.mockRestore();
      await dispatchWorker.tick();
      expect(send.mock.calls.filter(([prep]) => prep.auditTrackingId === trackingId)).toHaveLength(1);
      const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe(failure.startsWith('outcome') ? 'failed' : 'dispatched');
      if (failure.startsWith('outcome')) {
        expect(sub.dispatchInFlightAt).toBeDefined();
        expect(await disseminationService.retry(trackingId, 'psst-safe', 'admin@test')).toEqual({ ok: false, error: 'dispatch_outcome_requires_reconciliation' });
      }
    } finally { write.mockRestore(); send.mockRestore(); }
  });

  it.each([false, true])('retries only explicitly unsent failures (definitely unsent: %s)', async (notSent) => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    const send = jest.spyOn(getAdapter('psst-safe')!, 'dispatch').mockRejectedValue(notSent ? new DispatchNotSentError('validation') : new Error('timeout after send'));
    try {
      await dispatchWorker.tick();
      const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe(notSent ? 'deferred' : 'failed');
      expect(Boolean(sub.dispatchInFlightAt)).toBe(!notSent);
      await dispatchWorker.tick();
      expect(send).toHaveBeenCalledTimes(1);
    } finally { send.mockRestore(); }
  });

  it('completes the Psst Stage-1 handoff lifecycle', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');

    await dispatchWorker.tick();

    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('dispatched');
    expect(sub.handoff?.url).toBe('https://safe.psst.org/to/safe');
    expect(sub.handoff?.depositBody).not.toContain(trackingId);
    expect(sub.handoff?.depositBody).toContain('CASE-');
    expect(sub.packetHash).toHaveLength(64);
    // Psst neither acknowledges nor sends feedback, so both clocks are off
    // — no false SLA-breach alerts for a fire-and-forget channel (PDR §14).
    expect(sub.sla?.ackDueAt).toBeNull();
    expect(sub.sla?.feedbackDueAt).toBeNull();

    // Manual receipt closes the loop.
    const record = await disseminationService.recordManualReceipt(
      trackingId,
      'psst-safe',
      'Deposited, confirmation seen',
      'admin@test',
      'ack',
    );
    expect(record.ok).toBe(true);

    const [after] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(after.state).toBe('acknowledged');
    expect(after.sla?.ackReceivedAt).toBeDefined();

    const receipts = await disseminationPersistence.getReceiptsForReport(trackingId);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].type).toBe('manual');
  });

  it('defers with backoff when an email dispatch fails, then dead-letters after max attempts', async () => {
    // Dryrun with no inbox: the email adapter throws deterministically.
    process.env.DISSEMINATION_MODE = 'dryrun';
    delete process.env.DISSEMINATION_DRYRUN_INBOX;

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    await dispatchWorker.tick();

    let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('deferred');
    expect(sub.attempts).toBe(1);
    expect(sub.lastError).toContain('DISSEMINATION_DRYRUN_INBOX');
    expect(sub.nextAttemptAt!.getTime()).toBeGreaterThan(Date.now());

    // Fast-forward to the final attempt: worker should dead-letter.
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      attempts: 4,
      nextAttemptAt: new Date(Date.now() - 1000),
    });
    await dispatchWorker.tick();

    [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('failed');
    expect(sub.attempts).toBe(5);

    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'dead_lettered')).toBe(true);
  });

  it('does NOT re-dispatch a submission whose send was interrupted mid-flight (no duplicate agency filing)', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    delete process.env.DISSEMINATION_DRYRUN_INBOX;

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);

    // Simulate a prior attempt that reached the external send but crashed before
    // recording the outcome: the in-flight marker is still set and the row is
    // claimable again.
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      state: 'deferred',
      nextAttemptAt: new Date(Date.now() - 1000),
      dispatchInFlightAt: new Date(Date.now() - 60_000),
    });

    await dispatchWorker.tick();

    [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    // Flagged for human reconciliation, NOT re-sent.
    expect(sub.state).toBe('failed');
    expect(sub.lastError).toBe('dispatch_uncertain_after_interruption');
    expect(sub.dispatchedAt).toBeUndefined();

    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'dispatch_uncertain')).toBe(true);
    expect(audit.some((e) => e.event === 'dispatched')).toBe(false);
  });

  it('still retries a cleanly-failed dispatch — the crash guard does not block normal retries', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    delete process.env.DISSEMINATION_DRYRUN_INBOX;

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);

    // A cleanly-failed attempt has NO in-flight marker, so the guard must let it
    // process normally (here it re-defers, since the dryrun inbox is unset).
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      state: 'deferred',
      nextAttemptAt: new Date(Date.now() - 1000),
    });

    await dispatchWorker.tick();

    [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.lastError).not.toBe('dispatch_uncertain_after_interruption');
    expect(sub.attempts).toBeGreaterThan(0);
  });

  it('dead-lettered channels surface in the alerts query and can be retried', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    delete process.env.DISSEMINATION_DRYRUN_INBOX;

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    await dispatchWorker.tick();

    let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      attempts: 4,
      nextAttemptAt: new Date(Date.now() - 1000),
    });
    await dispatchWorker.tick();

    // Failed submission appears in the attention list.
    const attention = await disseminationPersistence.listAttentionSubmissions();
    const alert = attention.find((s) => s.trackingId === trackingId);
    expect(alert).toBeDefined();
    expect(alert!.state).toBe('failed');

    // Retry is only valid from 'failed'.
    const badRetry = await disseminationService.retry(trackingId, 'psst-safe', 'admin@test');
    expect(badRetry.ok).toBe(false);

    const retried = await disseminationService.retry(trackingId, 'cisa', 'admin@test');
    expect(retried.ok).toBe(true);

    [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('approved');
    expect(sub.attempts).toBe(0);
    expect(sub.lastError).toBeUndefined();

    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'retry_requested')).toBe(true);

    // Once retried, it leaves the alerts list.
    const after = await disseminationPersistence.listAttentionSubmissions();
    expect(after.some((s) => s.trackingId === trackingId)).toBe(false);
  });

  it('SLA-breached open channels surface in the alerts query', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    // Simulate a dispatched channel whose 7-day ack clock has run out
    // (SES is not mocked here; the SLA sweep itself is receiptTracker's).
    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      state: 'dispatched',
      dispatchedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
      sla: {
        ackDueAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
        feedbackDueAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        ackBreached: true,
        feedbackBreached: false,
      },
    });

    const attention = await disseminationPersistence.listAttentionSubmissions();
    const alert = attention.find((s) => s.trackingId === trackingId);
    expect(alert).toBeDefined();
    expect(alert!.sla?.ackBreached).toBe(true);
  });

  it('withdrawal blocks dispatch for a not-yet-dispatched channel', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    const withdrawal = await disseminationService.withdraw(trackingId, 'cisa', 'admin@test');
    expect(withdrawal.ok).toBe(true);

    await dispatchWorker.tick();

    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('withdrawn');
    expect(sub.dispatchedAt).toBeUndefined();
  });

  it('records provider unpinning without claiming global packet destruction', async () => {
    const { evidenceStorageService } = jest.requireMock('../../../../src/services/evidenceStorage');
    (evidenceStorageService.unpin as jest.Mock).mockClear();

    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    // Simulate a failed dispatch that already generated and pinned a packet.
    let [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(sub.submissionId, {
      state: 'failed',
      packetCid: 'QmPacketCid',
      packetHash: 'f'.repeat(64),
    });

    const withdrawal = await disseminationService.withdraw(trackingId, 'cisa', 'admin@test');
    expect(withdrawal.ok).toBe(true);

    expect(evidenceStorageService.unpin).toHaveBeenCalledWith('QmPacketCid');

    [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('withdrawn');
    expect(sub.packetCid).toBeUndefined();

    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'packet_destroyed')).toBe(false);
    const unpinned = audit.find((e) => e.event === 'packet_unpinned');
    expect(unpinned).toBeDefined();
    expect(unpinned!.detail).toMatchObject({ packetCid: 'QmPacketCid', unpinned: true });
  });

  it('withdraws access while recording failed cleanup without leaking provider errors', async () => {
    const { evidenceStorageService } = jest.requireMock('../../../../src/services/evidenceStorage');
    process.env.LOG_LEVEL = 'warn';
    const warning = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    const [original] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(original.submissionId, {
      state: 'failed', packetCid: 'private-packet-cid', packetHash: 'f'.repeat(64),
    });
    evidenceStorageService.unpin.mockRejectedValueOnce(new Error(`provider-secret ${trackingId} private-packet-cid`));
    try {
      expect(await disseminationService.withdraw(trackingId, 'cisa', 'admin@test')).toEqual({ ok: true });
      const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(sub.state).toBe('withdrawn');
      expect(sub.packetCid).toBeUndefined();
      const audit = await disseminationPersistence.getAuditForReport(trackingId);
      expect(audit.some((e) => ['packet_destroyed', 'packet_unpinned'].includes(e.event))).toBe(false);
      expect(audit.find((e) => e.event === 'packet_unpin_failed')?.detail)
        .toMatchObject({ packetCid: 'private-packet-cid', unpinned: false });
      const logged = JSON.stringify(warning.mock.calls);
      expect(logged).toContain('cleanup remains unverified');
      for (const secret of ['provider-secret', trackingId, 'private-packet-cid']) expect(logged).not.toContain(secret);
      await dispatchWorker.tick();
      expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe('withdrawn');
    } finally {
      warning.mockRestore();
    }
  });

  it('withdrawal without a pinned packet skips destruction cleanly', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['cisa'], 'admin@test');

    const withdrawal = await disseminationService.withdraw(trackingId, 'cisa', 'admin@test');
    expect(withdrawal.ok).toBe(true);

    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'packet_destroyed')).toBe(false);
  });

  it('status projection exposes per-channel state without admin internals', async () => {
    const trackingId = await seedReport();
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    await dispatchWorker.tick();

    const channels = await disseminationService.status(trackingId);
    expect(channels).toHaveLength(1);
    expect(channels[0]).toMatchObject({
      entityId: 'psst-safe',
      entityName: 'Psst.org Safe',
      state: 'dispatched',
    });
  });
});

describe('packet integration through the worker view', () => {
  it('uses the persisted narrative and evidence manifest in the packet', async () => {
    const trackingId = await seedReport({
      encryptedDescription: encryptContactValue('Persisted report narrative'),
    });
    await reportPersistenceService.saveEvidenceParams(`${trackingId}/evidence.pdf`, {
      encryptionKey: 'k',
      originalCID: 'QmFileCid',
      pinataIv: 'iv',
      pinataAuthTag: 'tag',
      evidenceSalt: 's',
      evidenceIv: 'eiv',
      evidenceAuthTag: 'etag',
      mimetype: 'application/pdf',
    });
    const loaded = await disseminationService.buildView(trackingId);
    expect(loaded).not.toBeNull();
    expect(loaded!.view.narrative).toBe('Persisted report narrative');
    expect(loaded!.view.evidence.files).toEqual([{ name: 'evidence-1.pdf', cid: 'QmFileCid', mimetype: 'application/pdf', size: undefined }]);

    const packet = await packetGenerator.generate(loaded!.view, 'cisa');
    expect(packet.sidecar.narrative).toBe('Persisted report narrative');
    expect(JSON.stringify(packet.sidecar)).not.toContain('0xnull');
  });
});

it('omits the reporter bearer credential from completeness warnings', async () => {
  const trackingId = await seedReport();
  const warning = jest.spyOn(logger, 'warn').mockImplementation(() => {});
  try {
    await disseminationService.approve(trackingId, ['psst-safe'], 'admin@test');
    await dispatchWorker.tick();
    const messages = warning.mock.calls.map(call => String(call[0])).filter(message => message.includes('internal checklist gaps'));
    expect(messages).toHaveLength(1);
    expect(messages[0]).not.toContain(trackingId);
    expect(messages[0]).toContain('advisory only');
    const [submission] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(submission.state).toBe('dispatched');
  } finally { warning.mockRestore(); }
});
