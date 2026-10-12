import { receiptTracker } from '../../../../src/services/dissemination/receiptTracker';
/**
 * Tier C counsel tests (Phase 3a/3b): bench CRUD as routing data, the
 * matter-code identity firewall, scoped workspace tokens, and attestation
 * receipts.
 */

import crypto from 'node:crypto';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import { counselService, generateMatterCode } from '../../../../src/services/dissemination/counselService';
import {
  makeWorkspaceToken,
  verifyWorkspaceToken,
} from '../../../../src/services/dissemination/counselWorkspace';
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
  emailNotificationService: { sendAlert: jest.fn().mockResolvedValue(undefined) },
}));

process.env.DISSEMINATION_WEBHOOK_SECRET = 'test-webhook-secret';

async function seedDiscriminationReport(): Promise<string> {
  const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  await reportPersistenceService.upsert({
    trackingId,
    status: 'verified',
    categories: ['discrimination-harassment'],
    consent: {
      psst: { granted: false },
      agency: true,
      capturedAt: new Date(),
      textVersion: 'v1',
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return trackingId;
}

describe('counsel bench CRUD (Phase 3a)', () => {
  it('creates, updates, and deactivates partners as routing data', async () => {
    const created = await counselService.upsertPartner({
      name: 'Psst Legal',
      contactHandle: 'Signal: @psst.legal.01',
      channels: ['eeoc', 'sec-tcr'],
      engagementModel: 'psst-legal',
    });
    expect(created.partner).toBeDefined();
    expect(created.partner!.active).toBe(true);
    // Unknown channels are dropped, valid ones kept.
    const withBadChannel = await counselService.upsertPartner({
      name: 'Panel Firm A',
      contactHandle: 'Signal: @panel.a',
      channels: ['osha', 'not-a-channel'],
    });
    expect(withBadChannel.partner!.channels).toEqual(['osha']);

    // Deactivation removes a partner from assignment without deleting it.
    const deactivated = await counselService.upsertPartner({
      counselId: created.partner!.counselId,
      name: created.partner!.name,
      contactHandle: created.partner!.contactHandle,
      channels: created.partner!.channels,
      engagementModel: created.partner!.engagementModel,
      active: false,
    });
    expect(deactivated.partner!.active).toBe(false);
    expect(deactivated.partner!.counselId).toBe(created.partner!.counselId);

    const active = await counselService.listPartners(true);
    expect(active.some((p) => p.counselId === created.partner!.counselId)).toBe(false);

    const rejected = await counselService.upsertPartner({ name: '', contactHandle: '' });
    expect(rejected.error).toBeDefined();
  });
});

describe('matter-code flow (Phase 3b)', () => {
  it('generates matter codes in the M-XXXX shape', () => {
    for (let i = 0; i < 20; i++) {
      expect(generateMatterCode()).toMatch(/^M-[A-F0-9]{6}$/);
    }
  });

  it('assign stamps the submission, audits the code, and relays the reporter notice', async () => {
    const partner = (
      await counselService.upsertPartner({
        name: 'EEOC Panel Firm',
        contactHandle: 'Signal: @eeoc.panel',
        channels: ['eeoc'],
        engagementModel: 'panel',
      })
    ).partner!;

    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await dispatchWorker.tick();

    const [before] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(before.state).toBe('dispatched'); // counsel handoff
    expect(before.handoff?.depositBody).toContain('counsel-mediated');

    const result = await counselService.assign(trackingId, 'eeoc', 'admin@test');
    expect(result.assignment).toBeDefined();
    expect(result.assignment!.counselId).toBe(partner.counselId);
    expect(result.assignment!.matterCode).toMatch(/^M-[A-F0-9]{6}$/);

    // Double assignment refused.
    const again = await counselService.assign(trackingId, 'eeoc', 'admin@test');
    expect(again.assignment).toEqual(result.assignment);

    // Reporter-facing relay message quotes handle + matter code, no identity.
    const thread = await disseminationPersistence.getRelayThread(trackingId);
    expect(thread).toHaveLength(1);
    expect(thread[0].direction).toBe('to-reporter');
    expect(thread[0].body).toContain(result.assignment!.matterCode);
    expect(thread[0].body).toContain('Signal: @eeoc.panel');

    // Attestation records the receipt and stops the ack clock.
    const attested = await counselService.attest(trackingId, 'eeoc', 'EEOC charge 846-2026-11223', 'admin@test');
    expect(attested.ok).toBe(true);
    const [after] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(after.state).toBe('acknowledged');

    const receipts = await disseminationPersistence.getReceiptsForReport(trackingId);
    const attestation = receipts.find((r) => r.note?.includes('counsel attestation'));
    expect(attestation?.value).toBe('EEOC charge 846-2026-11223');
    expect(attestation?.note).toContain(result.assignment!.matterCode);
  });

  it('refuses assignment when no active counsel covers the channel', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['osc'], 'admin@test');
    const result = await counselService.assign(trackingId, 'osc', 'admin@test');
    expect(result.error).toBe('no_active_counsel_for_channel');
  });

  it('refuses a selected partner outside their configured channels', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    const { partner } = await counselService.upsertPartner({
      name: 'Other Channel Firm', contactHandle: 'Signal: other', channels: ['sec-tcr'],
    });
    expect(await counselService.assign(trackingId, 'eeoc', 'admin@test', partner!.counselId))
      .toEqual({ error: 'counsel_does_not_cover_channel' });
  });

  it('refuses empty receipts and withdrawn matters without acknowledging them', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await counselService.assign(trackingId, 'eeoc', 'admin@test');
    expect(await counselService.attest(trackingId, 'eeoc', '   ', 'admin@test'))
      .toEqual({ ok: false, error: 'receipt_required' });
    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    await disseminationPersistence.patchSubmission(sub.submissionId, { state: 'withdrawn' });
    expect(await counselService.attest(trackingId, 'eeoc', 'receipt', 'admin@test'))
      .toEqual({ ok: false, error: 'cannot_attest_in_state_withdrawn' });
    expect(await disseminationPersistence.getReceiptsForReport(trackingId)).toHaveLength(0);
  });

  it('refuses attestation without an assignment', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    const result = await counselService.attest(trackingId, 'eeoc', 'x', 'admin@test');
    expect(result).toEqual({ ok: false, error: 'no_counsel_assigned' });
  });
});

describe('workspace tokens (Phase 3b)', () => {
  it('round-trips a valid token scoped to one report/channel', () => {
    const token = makeWorkspaceToken('VRA-0000000000000001', 'eeoc', 'assignment-1');
    const scope = verifyWorkspaceToken(token);
    expect(scope).toMatchObject({ trackingId: 'VRA-0000000000000001', entityId: 'eeoc' });
    expect(scope!.exp).toBeGreaterThan(Date.now());
  });

  it('rejects tampering and expiry', () => {
    const token = makeWorkspaceToken('VRA-0000000000000001', 'eeoc', 'assignment-1');
    const [payload, sig] = [token.slice(0, token.lastIndexOf('.')), token.slice(token.lastIndexOf('.') + 1)];

    // Tampered payload (different entity) with the old signature.
    const forged = Buffer.from(
      JSON.stringify({ trackingId: 'VRA-0000000000000001', entityId: 'sec-tcr', exp: Date.now() + 1e7 }),
    ).toString('base64url');
    expect(verifyWorkspaceToken(`${forged}.${sig}`)).toBeNull();

    // Expired token.
    const expired = makeWorkspaceToken('VRA-0000000000000001', 'eeoc', 'assignment-1', -1);
    expect(verifyWorkspaceToken(expired)).toBeNull();

    // Garbage.
    expect(verifyWorkspaceToken('not-a-token')).toBeNull();
    expect(verifyWorkspaceToken(`${payload}.AAAA`)).toBeNull();
  });
});

afterAll(() => {
  dispatchWorker.stop();
});

describe('assignment recovery after durable partial progress', () => {
  it.each(['ensureCounselAssignment', 'appendAudit', 'insertRelayMessage'] as const)(
    'resumes after %s commits but its acknowledgement is lost', async method => {
      const trackingId = await seedDiscriminationReport();
      const { partner } = await counselService.upsertPartner({ name: 'Recovery counsel', contactHandle: 'Signal: recovery', channels: ['eeoc'] });
      await disseminationService.approve(trackingId, ['eeoc'], 'admin');
      const original = (disseminationPersistence[method] as any).bind(disseminationPersistence);
      const spy = jest.spyOn(disseminationPersistence, method as any).mockImplementationOnce(async (...args: any[]) => {
        await original(...args);
        throw new Error('lost acknowledgement');
      });
      await expect(counselService.assign(trackingId, 'eeoc', 'admin', partner!.counselId)).rejects.toThrow('lost acknowledgement');
      spy.mockRestore();
      const first = (await disseminationPersistence.getSubmissionsForReport(trackingId))[0].counsel;
      const retry = await counselService.assign(trackingId, 'eeoc', 'admin', partner!.counselId);
      expect(retry.assignment).toEqual(first);
      await counselService.assign(trackingId, 'eeoc', 'admin', partner!.counselId);
      expect((await disseminationPersistence.getAuditForReport(trackingId)).filter(e => e.event === 'counsel_assigned')).toHaveLength(1);
      expect(await disseminationPersistence.getRelayThread(trackingId)).toHaveLength(1);
    },
  );
});

it.each(['insertReceipt', 'advanceReceiptSubmission', 'advanceReceiptChannel', 'appendAudit'] as const)(
  'resumes attestation after %s commits without duplicate receipts or audit', async method => {
    const trackingId = await seedDiscriminationReport();
    await counselService.upsertPartner({ name: 'Attestation counsel', contactHandle: 'Signal: attest', channels: ['eeoc'] });
    await disseminationService.approve(trackingId, ['eeoc'], 'admin');
    await counselService.assign(trackingId, 'eeoc', 'admin');
    const original = (disseminationPersistence[method] as any).bind(disseminationPersistence);
    const spy = jest.spyOn(disseminationPersistence, method as any).mockImplementationOnce(async (...args: any[]) => {
      await original(...args); throw new Error('lost attestation acknowledgement');
    });
    await expect(counselService.attest(trackingId, 'eeoc', 'CONFIRMED-1', 'admin')).rejects.toThrow('lost attestation acknowledgement');
    spy.mockRestore();
    expect(await counselService.attest(trackingId, 'eeoc', 'CONFIRMED-1', 'admin')).toEqual({ ok: true });
    expect(await disseminationPersistence.getReceiptsForReport(trackingId)).toHaveLength(1);
    expect((await disseminationPersistence.getAuditForReport(trackingId)).filter(e => e.event === 'receipt_ack')).toHaveLength(1);
    expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe('acknowledged');
  },
);

for (const terminal of ['withdrawn', 'failed', 'feedback_received'] as const) {
  for (const kind of ['receipt', 'ack', 'feedback'] as const) {
    it(`keeps ${terminal} when stale ${kind} arrives after its submission read`, async () => {
      const trackingId = await seedDiscriminationReport();
      await disseminationService.approve(trackingId, ['eeoc'], 'admin');
      const [stale] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      const feedbackAt = new Date('2026-01-01');
      await disseminationPersistence.patchSubmission(stale.submissionId, { state: terminal, sla: {
        ackDueAt: null, feedbackDueAt: null, ackBreached: false, feedbackBreached: false,
        ackReceivedAt: feedbackAt, feedbackReceivedAt: feedbackAt,
      } });
      await disseminationPersistence.setDispositionChannelState(trackingId, 'eeoc', terminal);
      await receiptTracker.recordReceipt(stale, { type: 'manual', value: 'late', receivedAt: new Date() }, 'admin', kind);
      const [actual] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(actual.state).toBe(terminal);
      expect(actual.sla?.feedbackReceivedAt).toEqual(feedbackAt);
      expect((await disseminationPersistence.getDisposition(trackingId))?.channels[0].state).toBe(terminal);
    });
  }
  it(`keeps disposition ${terminal} changed between the two receipt writes`, async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin');
    const [stale] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    const advance = disseminationPersistence.advanceReceiptSubmission.bind(disseminationPersistence);
    const spy = jest.spyOn(disseminationPersistence, 'advanceReceiptSubmission').mockImplementationOnce(async (...args) => {
      await advance(...args);
      await disseminationPersistence.patchSubmission(stale.submissionId, { state: terminal });
      await disseminationPersistence.setDispositionChannelState(trackingId, 'eeoc', terminal);
    });
    await receiptTracker.recordReceipt(stale, { type: 'manual', value: 'late', receivedAt: new Date() }, 'admin', 'ack');
    spy.mockRestore();
    expect((await disseminationPersistence.getSubmissionsForReport(trackingId))[0].state).toBe(terminal);
    expect((await disseminationPersistence.getDisposition(trackingId))?.channels[0].state).toBe(terminal);
  });
}

it('uses guarded plain updates and preserves earlier SLA timestamps', async () => {
  const trackingId = await seedDiscriminationReport();
  await disseminationService.approve(trackingId, ['eeoc'], 'admin');
  const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  const earlier = new Date('2026-01-01');
  await disseminationPersistence.patchSubmission(sub.submissionId, { sla: {
    ackDueAt: null, feedbackDueAt: null, ackBreached: false, feedbackBreached: false, ackReceivedAt: earlier,
  } });
  const collection = (disseminationPersistence as any).submissions;
  const spy = jest.spyOn(collection, 'updateOne');
  const receivedAt = new Date();
  await disseminationPersistence.advanceReceiptSubmission(sub.submissionId, 'feedback_received', receivedAt);
  expect(spy.mock.calls).toHaveLength(3);
  for (const [filter, update] of spy.mock.calls as any[]) {
    expect(Array.isArray(update)).toBe(false);
    expect(Object.keys(update)).toEqual(['$set']);
    expect(filter.state.$in).not.toContain('withdrawn');
    expect(filter.state.$in).not.toContain('failed');
  }
  spy.mockRestore();
  const [actual] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  expect(actual.sla?.ackReceivedAt).toEqual(earlier);
  expect(actual.sla?.feedbackReceivedAt).toEqual(receivedAt);
  expect(actual.state).toBe('feedback_received');
});

it('does not reopen a submission withdrawn between SLA stamping and state advancement', async () => {
  const trackingId = await seedDiscriminationReport();
  await disseminationService.approve(trackingId, ['eeoc'], 'admin');
  const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  await disseminationPersistence.patchSubmission(sub.submissionId, { sla: {
    ackDueAt: null, feedbackDueAt: null, ackBreached: false, feedbackBreached: false,
  } });
  const collection = (disseminationPersistence as any).submissions;
  const update = collection.updateOne.bind(collection);
  const spy = jest.spyOn(collection, 'updateOne').mockImplementationOnce(async (...args: any[]) => {
    const result = await update(...args);
    await update({ submissionId: sub.submissionId }, { $set: { state: 'withdrawn' } });
    await disseminationPersistence.setDispositionChannelState(trackingId, 'eeoc', 'withdrawn');
    return result;
  });
  await receiptTracker.recordReceipt(sub, { type: 'manual', value: 'late', receivedAt: new Date() }, 'admin', 'feedback');
  spy.mockRestore();
  const [actual] = await disseminationPersistence.getSubmissionsForReport(trackingId);
  expect(actual.state).toBe('withdrawn');
  expect(actual.sla?.feedbackReceivedAt).toBeUndefined();
  expect((await disseminationPersistence.getDisposition(trackingId))?.channels[0].state).toBe('withdrawn');
});

describe('consent gates on counsel and dispatch (#926)', () => {
  const legalReviewOnly = { psst: { granted: false }, agency: true, capturedAt: new Date(), textVersion: 'v3-legal-review-default' };

  it('refuses counsel assignment once the channel is no longer consented', async () => {
    await counselService.upsertPartner({ name: 'Consent Gate Firm', contactHandle: 'Signal: @gate', channels: ['eeoc'], engagementModel: 'panel' });
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await dispatchWorker.tick();
    await reportPersistenceService.patch(trackingId, { consent: legalReviewOnly });

    expect(await counselService.assign(trackingId, 'eeoc', 'admin@test')).toEqual({ error: 'reporter_consent_missing' });
    const [submission] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(submission.counsel).toBeUndefined();
    expect(await disseminationPersistence.getRelayThread(trackingId)).toEqual([]);
  });

  it('withdraws, with an audit record, an approved channel whose consent is gone instead of deferring it forever', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await reportPersistenceService.patch(trackingId, { consent: legalReviewOnly });
    await dispatchWorker.tick();

    const [submission] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(submission).toMatchObject({ state: 'withdrawn', lastError: 'reporter_consent_missing' });
    expect((await disseminationPersistence.getDisposition(trackingId))!.channels).toContainEqual(expect.objectContaining({ entityId: 'eeoc', state: 'withdrawn' }));
    expect(await disseminationPersistence.getAuditForReport(trackingId)).toContainEqual(
      expect.objectContaining({ event: 'channel_withdrawn', actor: 'system', detail: { reason: 'reporter_consent_missing' } }));
    // Re-approval is refused rather than recreating the channel.
    expect(await disseminationService.approve(trackingId, ['eeoc'], 'admin@test')).toEqual({ error: 'no_channels_approved: eeoc(reporter_consent_missing)' });
  });

  it('withdraws before the live narrative-review gate could park the row forever', async () => {
    const previous = process.env.DISSEMINATION_MODE;
    process.env.DISSEMINATION_MODE = 'live';
    try {
      const trackingId = await seedDiscriminationReport();
      await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
      await reportPersistenceService.patch(trackingId, { consent: legalReviewOnly });
      await dispatchWorker.tick();
      const [submission] = await disseminationPersistence.getSubmissionsForReport(trackingId);
      expect(submission).toMatchObject({ state: 'withdrawn', lastError: 'reporter_consent_missing' });
    } finally { process.env.DISSEMINATION_MODE = previous; }
  });

  it('keeps a withdrawal fenced when later bookkeeping fails, without a retry or duplicate audit', async () => {
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await reportPersistenceService.patch(trackingId, { consent: legalReviewOnly });
    const setState = jest.spyOn(disseminationPersistence, 'setDispositionChannelState').mockRejectedValueOnce(new Error('synthetic write failure'));
    try { await dispatchWorker.tick(); } finally { setState.mockRestore(); }
    const [submission] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(submission.state).toBe('withdrawn');
    await dispatchWorker.tick();
    const audits = (await disseminationPersistence.getAuditForReport(trackingId)).filter(a => a.event === 'channel_withdrawn');
    expect(audits.length).toBeLessThanOrEqual(1);
    expect((await disseminationPersistence.getAuditForReport(trackingId)).some(a => a.event === 'dispatch_retry_scheduled')).toBe(false);
  });

  it('refuses counsel for a missing or dismissed report with the specific reason', async () => {
    expect(await counselService.assign('VRA-FFFFFFFFFFFFFFFF', 'eeoc', 'admin@test')).toEqual({ error: 'submission_not_found' });
    const trackingId = await seedDiscriminationReport();
    await disseminationService.approve(trackingId, ['eeoc'], 'admin@test');
    await dispatchWorker.tick();
    await reportPersistenceService.patch(trackingId, { status: 'dismissed' });
    expect(await counselService.assign(trackingId, 'eeoc', 'admin@test')).toEqual({ error: 'report_not_eligible' });
  });
});
