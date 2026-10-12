/**
 * AI redaction pass (§7.2): accepting an override freezes it onto the
 * disposition and every packet generated afterwards uses it; clearing
 * reverts to the raw narrative. The propose step (Venice AI call) is
 * exercised only for its gate, not the network call.
 */

import crypto from 'node:crypto';
import { generateSecurePacket } from '../../../../src/services/dissemination/securePacketSender';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import { redactionService } from '../../../../src/services/dissemination/redactionService';
import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { packetGenerator } from '../../../../src/services/dissemination/packetGenerator';
import { reportPersistenceService } from '../../../../src/services/reportPersistence';
import { encryptContactValue } from '../../../../src/services/reportFieldCrypto';

jest.mock('../../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: {
    uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'QmPacketCid' }),
  },
}));

const ORIGINAL_ENV = { ...process.env };
afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

const LEGAL_REVIEW_CONSENT = { psst: { granted: false }, agency: false, legalReview: true, capturedAt: new Date(), textVersion: 'v4-legal-review' };

async function seedApprovedReport(approve = true): Promise<string> {
  const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
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
  if (approve) {
    const result = await disseminationService.approve(trackingId, ['cisa'], 'admin@test');
    if ('error' in result) throw new Error(`approve failed: ${result.error}`);
  }
  return trackingId;
}

describe('redaction service', () => {
  it('propose refuses to run without a Venice API key', async () => {
    delete process.env.VENICE_API_KEY;
    await expect(redactionService.propose('some narrative')).rejects.toThrow(
      'VENICE_API_KEY not configured',
    );
  });

  it('accept requires an existing report', async () => {
    const result = await redactionService.accept('VRA-DEADBEEFDEADBEEF', 'text', [], 'admin@test');
    expect(result).toEqual({ ok: false, error: 'report_not_found' });
  });

  it('reviews a standalone link without approving or queueing any agency channel', async () => {
    const trackingId = await seedApprovedReport(false);
    // Secure legal packets run on legal-review consent, not agency consent (#926).
    await reportPersistenceService.patch(trackingId, { consent: LEGAL_REVIEW_CONSENT });
    expect(await generateSecurePacket({ trackingId, actor: 'admin@test' })).toEqual({ error: 'narrative_review_required' });
    expect(await redactionService.markReviewedClean(trackingId, 'admin@test')).toEqual({ ok: true });
    const review = await disseminationPersistence.getDisposition(trackingId);
    expect(review).toMatchObject({ channels: [], approvedBy: '', narrativeReviewedBy: 'admin@test' });
    expect(await disseminationPersistence.getSubmissionsForReport(trackingId)).toEqual([]);
    expect((await generateSecurePacket({ trackingId, actor: 'admin@test' })).url).toBeTruthy();
    const report = (await reportPersistenceService.get(trackingId))!;
    await reportPersistenceService.patch(trackingId, { consent: { ...report.consent!, legalReview: false } });
    expect(await generateSecurePacket({ trackingId, actor: 'admin@test' })).toEqual({ error: 'reporter_consent_missing' });
  });

  it('preserves review on later approval and channel state on later review', async () => {
    const trackingId = await seedApprovedReport(false);
    expect((await redactionService.accept(trackingId, 'Reviewed version', [], 'admin@test')).ok).toBe(true);
    await disseminationService.approve(trackingId, ['cisa'], 'routing-admin');
    const approved = (await disseminationPersistence.getDisposition(trackingId))!;
    expect(approved.narrativeOverride?.narrative).toBe('Reviewed version');
    await redactionService.markReviewedClean(trackingId, 'review-admin');
    expect((await disseminationPersistence.getDisposition(trackingId))!.channels).toEqual(approved.channels);
    await redactionService.clear(trackingId, 'review-admin');
    const cleared = (await disseminationPersistence.getDisposition(trackingId))!;
    expect(cleared.narrativeOverride).toBeUndefined();
    expect(cleared.narrativeReviewedAt).toBeUndefined();
    await reportPersistenceService.patch(trackingId, { consent: LEGAL_REVIEW_CONSENT });
    expect(await generateSecurePacket({ trackingId, actor: 'admin@test' })).toEqual({ error: 'narrative_review_required' });
  });

  it('cannot mark an unreadable original clean', async () => {
    const trackingId = await seedApprovedReport(false);
    await reportPersistenceService.patch(trackingId, { encryptedDescription: 'enc:broken' });
    expect(await redactionService.markReviewedClean(trackingId, 'admin@test')).toEqual({ ok: false, error: 'narrative_unavailable' });
    expect(await disseminationPersistence.getDisposition(trackingId)).toBeNull();
  });

  it('accepted override is frozen into subsequently generated packets', async () => {
    const trackingId = await seedApprovedReport();

    // Before override: the view carries the raw Eliza narrative.
    let loaded = await disseminationService.buildView(trackingId);
    expect(loaded!.view.narrative).toContain('only engineer hired last March');

    const accepted = await redactionService.accept(
      trackingId,
      '[ROLE], I saw the CFO falsify invoices.',
      ['Removed self-identifying hiring detail'],
      'admin@test',
    );
    expect(accepted.ok).toBe(true);

    // After override: view and packet both use the redacted narrative.
    loaded = await disseminationService.buildView(trackingId);
    expect(loaded!.view.narrative).toBe('[ROLE], I saw the CFO falsify invoices.');

    const packet = await packetGenerator.generate(loaded!.view, 'cisa');
    expect(packet.sidecar.narrative).toBe('[ROLE], I saw the CFO falsify invoices.');
    expect(JSON.stringify(packet.sidecar)).not.toContain('only engineer hired last March');

    // Audit trail records the redaction.
    const audit = await disseminationPersistence.getAuditForReport(trackingId);
    expect(audit.some((e) => e.event === 'narrative_redacted')).toBe(true);

    // Clearing reverts to the raw narrative.
    const cleared = await redactionService.clear(trackingId, 'admin@test');
    expect(cleared.ok).toBe(true);
    loaded = await disseminationService.buildView(trackingId);
    expect(loaded!.view.narrative).toContain('only engineer hired last March');
    expect(audit.concat(await disseminationPersistence.getAuditForReport(trackingId)).some(
      (e) => e.event === 'narrative_redaction_cleared',
    )).toBe(true);
  });

  it('rejects an empty override', async () => {
    const trackingId = await seedApprovedReport();
    const result = await redactionService.accept(trackingId, '   ', [], 'admin@test');
    expect(result).toEqual({ ok: false, error: 'narrative_empty' });
  });
});
