/**
 * Tier B tests (Phase 2c): the shared TCR model, portal companions in
 * portal question order, printable form PDFs, the companion adapter
 * handoff lifecycle, receipt parsing, and the one-channel-per-entity rule.
 */

import crypto from 'node:crypto';
import { useDisseminationMongo } from '../../../helpers/disseminationMongo';
useDisseminationMongo();
import {
  buildTcrModel,
  renderCompanionFields,
  renderCompanionText,
  PORTAL_PROFILES,
} from '../../../../src/services/dissemination/tcrModel';
import { renderCompanionPdf } from '../../../../src/services/dissemination/companionPdf';
import {
  secTcrAdapter,
  cftcTcrAdapter,
  fincenAdapter,
  irs211Adapter,
  fbiIc3Adapter,
  epaViolationAdapter,
  ftcAdapter,
  dojAdapter,
  euOlafAdapter,
  ecCompetitionAdapter,
} from '../../../../src/services/dissemination/adapters/companionAdapter';
import { hasAdapter } from '../../../../src/services/dissemination/adapters/registry';
import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import { dispatchWorker } from '../../../../src/services/dissemination/dispatchWorker';
import { routingEngine } from '../../../../src/services/dissemination/routingEngine';
import { buildDisseminationView } from '../../../../src/services/dissemination/disseminationView';
import { reportPersistenceService } from '../../../../src/services/reportPersistence';
import type { DisseminationView } from '../../../../src/services/dissemination/types';

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

function makeView(overrides: Partial<DisseminationView> = {}): DisseminationView {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    categories: ['financial-fraud'],
    rawCategories: ['financial-fraud'],
    narrative: 'The CFO falsified quarterly filings.',
    urgency: 'high',
    dateOfIncident: '2026-05-15',
    location: 'New York',
    evidence: {
      evidenceHash: 'e'.repeat(64),
      files: [{ name: 'ledger.xlsx', cid: 'QmLedgerCid' }],
    },
    zkProof: { proofHash: '0xproof', txHash: '0xtx', verified: true },
    ...overrides,
  };
}

async function seedFraudReport(): Promise<string> {
  const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
  await reportPersistenceService.upsert({
    trackingId,
    status: 'verified',
    categories: ['financial-fraud'],
    consent: {
      psst: { granted: true, treatment: 'hold-encrypted' },
      agency: true,
      capturedAt: new Date(),
      textVersion: 'v1',
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  return trackingId;
}

describe('TCR model', () => {
  it('is identity-free and always an anonymous filing', () => {
    const model = buildTcrModel(makeView());
    expect(model.anonymousFiling).toBe(true);
    const json = JSON.stringify(model);
    for (const banned of ['nullifier', 'contactValue', 'contactMethod', 'wantsReward']) {
      expect(json).not.toContain(banned);
    }
    expect(model.attorneyNote).toContain('Rule 21F-9');
    expect(model.evidenceSummary).toContain('QmLedgerCid');
    expect(model.existenceProof).toContain('0xproof');
  });
});

describe('portal companions', () => {
  it('one TCR model covers SEC, CFTC, and FinCEN with per-agency ordering', () => {
    for (const entityId of ['sec-tcr', 'cftc-tcr', 'fincen']) {
      const fields = renderCompanionFields(makeView(), entityId);
      expect(fields[0].answer).toContain('ANONYMOUS');
      expect(fields.map((f) => f.question)).toContain('Describe the facts of your complaint');
      const narrative = fields.find((f) => f.question === 'Describe the facts of your complaint');
      expect(narrative?.answer).toBe('The CFO falsified quarterly filings.');
    }
  });

  it('IRS Form 211 uses its own question list with the counsel identity placeholder', () => {
    const fields = renderCompanionFields(makeView(), 'irs-211');
    const identity = fields.find((f) => f.section.includes('Claimant'));
    expect(identity?.answer).toContain('outside Vera.Report');
    expect(PORTAL_PROFILES['irs-211'].filingNotes.join(' ')).toContain('MAIL-ONLY');
  });

  it('renders paste-ready text in portal question order with filing notes', () => {
    const text = renderCompanionText(makeView(), 'sec-tcr');
    expect(text).toContain('SEC Form TCR — filing companion for VRA-ABCDEF0123456789');
    expect(text).toContain('https://www.sec.gov/tcr');
    expect(text).toContain('ONE method of transmission');
    expect(text.indexOf('Section A')).toBeLessThan(text.indexOf('Section G'));
    expect(text).not.toContain('nullifier');
  });

  it('EU channels (Phase 4c) render anonymous, identity-free companions', async () => {
    for (const adapter of [euOlafAdapter, ecCompetitionAdapter]) {
      expect(hasAdapter(adapter.entityId)).toBe(true);
      const text = renderCompanionText(makeView(), adapter.entityId);
      expect(text).toContain(PORTAL_PROFILES[adapter.entityId].portalUrl);
      expect(text).not.toContain('nullifier');
      expect(text).not.toContain('attorney of record required');

      const prep = await adapter.prepare(makeView(), {} as never);
      expect(prep.mode).toBe('deep-link');
      const result = await adapter.dispatch(prep);
      expect(result.outcome).toBe('handoff');
    }
    expect(euOlafAdapter.parseReceipt('Case reference: OC/2026/0421')).toMatchObject({
      type: 'portal-confirmation',
      value: 'OC/2026/0421',
    });
  });

  it('US registry breadth channels render identity-free companions and hand off', async () => {
    for (const adapter of [fbiIc3Adapter, epaViolationAdapter, ftcAdapter, dojAdapter]) {
      expect(hasAdapter(adapter.entityId)).toBe(true);
      const text = renderCompanionText(makeView(), adapter.entityId);
      expect(text).toContain(PORTAL_PROFILES[adapter.entityId].portalUrl);
      expect(text).not.toContain('nullifier');

      const prep = await adapter.prepare(makeView(), {} as never);
      expect(prep.mode).toBe('deep-link');
      const result = await adapter.dispatch(prep);
      expect(result.outcome).toBe('handoff');
    }
    expect(fbiIc3Adapter.parseReceipt('Complaint ID: I2607081234567890')).toMatchObject({
      type: 'portal-confirmation',
      value: 'I2607081234567890',
    });
    expect(ftcAdapter.parseReceipt('Your report number: 178842251')).toMatchObject({
      type: 'portal-confirmation',
      value: '178842251',
    });
    // Manual free text still records for the no-confirmation portals.
    expect(dojAdapter.parseReceipt('Filed with Fraud Section web intake 7/8/2026')).toMatchObject({
      type: 'portal-confirmation',
    });
  });

  it('renders a printable PDF form', async () => {
    const pdf = await renderCompanionPdf(makeView(), 'sec-tcr');
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    expect(pdf.length).toBeGreaterThan(1000);
    await expect(renderCompanionPdf(makeView(), 'not-an-entity')).rejects.toThrow('No portal profile');
  });
});

describe('companion adapter receipts', () => {
  it('recognizes portal confirmation artifacts', () => {
    expect(secTcrAdapter.parseReceipt('Your TCR confirmation: TCR-2026-88421')).toMatchObject({
      type: 'portal-confirmation',
      value: 'TCR-2026-88421',
    });
    expect(fincenAdapter.parseReceipt('Reference number: FIN-3321')).toMatchObject({
      type: 'control-number',
      value: 'FIN-3321',
    });
    expect(irs211Adapter.parseReceipt('certified mail number 7016 2140 0000 6266')).toMatchObject({
      type: 'manual',
    });
    // Free text from the filing admin still counts as a portal confirmation.
    expect(cftcTcrAdapter.parseReceipt('filed 7/8, confirmation shown on screen')).toMatchObject({
      type: 'portal-confirmation',
    });
    expect(secTcrAdapter.parseReceipt('')).toBeNull();
  });
});

describe('routing + registry', () => {
  it('financial-fraud now recommends dispatchable Tier B channels', async () => {
    for (const entityId of ['sec-tcr', 'cftc-tcr', 'fincen', 'irs-211']) {
      expect(hasAdapter(entityId)).toBe(true);
    }

    const view = buildDisseminationView(
      {
        trackingId: 'VRA-0000000000000001',
        status: 'verified',
        categories: ['financial-fraud'],
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      '',
    );
    const plan = await routingEngine.recommend(view, {
      psst: { granted: true },
      agency: true,
      capturedAt: new Date(),
      textVersion: 'v1',
    });
    const sec = plan.channels.find((c) => c.entityId === 'sec-tcr');
    expect(sec?.supported).toBe(true);
  });
});

describe('companion filing lifecycle', () => {
  it('approve → worker tick → filing session handoff with the companion text', async () => {
    const trackingId = await seedFraudReport();
    const result = await disseminationService.approve(trackingId, ['sec-tcr'], 'admin@test');
    expect('error' in result).toBe(false);

    await dispatchWorker.tick();

    const [sub] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(sub.state).toBe('dispatched');
    expect(sub.handoff?.url).toBe('https://www.sec.gov/tcr');
    expect(sub.handoff?.depositBody).toContain('SEC Form TCR — filing companion');
    expect(sub.handoff?.depositBody).not.toContain(trackingId);
    expect(sub.handoff?.depositBody).toContain('CASE-');
    // SEC acknowledges immediately at filing; the 7-day clock applies.
    expect(sub.sla?.ackDueAt).not.toBeNull();

    const receipt = await disseminationService.recordManualReceipt(
      trackingId,
      'sec-tcr',
      'TCR confirmation: TCR-2026-11223',
      'admin@test',
      'ack',
    );
    expect(receipt.ok).toBe(true);
    const [after] = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(after.state).toBe('acknowledged');
  });

  it('enforces one channel per entity while live, and allows re-approval after withdrawal', async () => {
    const trackingId = await seedFraudReport();
    await disseminationService.approve(trackingId, ['sec-tcr'], 'admin@test');

    // Live submission → second approval refused under the one-channel rule.
    const second = await disseminationService.approve(trackingId, ['sec-tcr'], 'admin@test');
    expect(second).toMatchObject({ error: expect.stringContaining('already_filed_one_channel_rule') });

    // Withdraw, then re-approve: the submission is resurrected, not duplicated.
    await disseminationService.withdraw(trackingId, 'sec-tcr', 'admin@test');
    const third = await disseminationService.approve(trackingId, ['sec-tcr'], 'admin@test');
    expect('error' in third).toBe(false);

    const subs = await disseminationPersistence.getSubmissionsForReport(trackingId);
    expect(subs).toHaveLength(1);
    expect(subs[0].state).toBe('approved');
    expect(subs[0].attempts).toBe(0);
  });
});

afterAll(() => {
  dispatchWorker.stop();
});
