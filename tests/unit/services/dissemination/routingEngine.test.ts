/**
 * Routing engine + dissemination view (identity firewall) tests.
 *
 * MONGODB_URI is blank in tests, so disseminationPersistence uses its
 * in-memory fallback and rules are seeded from the taxonomy defaults.
 */

import { routingEngine } from '../../../../src/services/dissemination/routingEngine';
import { buildDisseminationView } from '../../../../src/services/dissemination/disseminationView';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import type { ReportRecord } from '../../../../src/services/reportPersistence';
import type { ConsentSnapshot } from '../../../../src/services/dissemination/types';

function makeReport(overrides: Partial<ReportRecord> = {}): ReportRecord {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    evidenceHash: 'a'.repeat(64),
    status: 'verified',
    categories: ['cyber-security'],
    urgency: 'high',
    location: 'Test City',
    dateOfIncident: '2026-06-01',
    reward: {
      wantsReward: true,
      contactMethod: 'email',
      encryptedContactValue: 'iv:tag:ciphertext',
    },
    zkProof: {
      proofHash: '0xproofhash',
      nullifier: '0xsecret-nullifier',
      publicSignals: ['1', '2'],
      verified: true,
      txHash: '0xtxhash',
    },
    verification: { isLegitimate: true, credibilityScore: 82, category: 'corruption' },
    createdAt: new Date('2026-06-02T00:00:00Z'),
    updatedAt: new Date('2026-06-02T00:00:00Z'),
    ...overrides,
  };
}

function fullConsent(): ConsentSnapshot {
  return {
    psst: { granted: true, treatment: 'hold-encrypted' },
    agency: true,
    capturedAt: new Date(),
    textVersion: 'v1',
  };
}

describe('buildDisseminationView (identity firewall)', () => {
  it('structurally excludes reporter identity fields', () => {
    const view = buildDisseminationView(makeReport(), 'narrative text', [
      { name: 'doc.pdf', cid: 'QmTestCid' },
    ]);

    const serialized = JSON.stringify(view);
    expect(serialized).not.toContain('nullifier');
    expect(serialized).not.toContain('encryptedContactValue');
    expect(serialized).not.toContain('contactMethod');
    expect(serialized).not.toContain('wantsReward');
    expect((view as Record<string, unknown>).reward).toBeUndefined();
    expect((view.zkProof as Record<string, unknown>).nullifier).toBeUndefined();
  });

  it('neutralizes reporter-chosen evidence filenames (anonymity)', () => {
    const view = buildDisseminationView(makeReport(), 'narrative', [
      { name: 'JaneDoe_paystub.pdf', cid: 'QmA' },
      { name: 'badge_10432.JPG', cid: 'QmB' },
      { name: 'noextension', cid: 'QmC' },
    ]);

    // Filenames are replaced with neutral evidence-N.<ext> (extension is a
    // non-identifying type hint; base name — which can de-anonymize — is dropped).
    expect(view.evidence.files.map((f) => f.name)).toEqual([
      'evidence-1.pdf',
      'evidence-2.jpg',
      'evidence-3',
    ]);
    // The identifying original names must not survive anywhere in the outbound view.
    const serialized = JSON.stringify(view);
    expect(serialized).not.toContain('JaneDoe');
    expect(serialized).not.toContain('paystub');
    expect(serialized).not.toContain('badge_10432');
    // CID (the real retrieval handle) is preserved so evidence stays downloadable.
    expect(view.evidence.files.map((f) => f.cid)).toEqual(['QmA', 'QmB', 'QmC']);
  });

  it('keeps the dissemination-relevant facts', () => {
    const view = buildDisseminationView(makeReport(), 'what happened', [
      { name: 'doc.pdf', cid: 'QmTestCid' },
    ]);

    expect(view.trackingId).toBe('VRA-ABCDEF0123456789');
    expect(view.narrative).toBe('what happened');
    expect(view.evidence.evidenceHash).toBe('a'.repeat(64));
    expect(view.evidence.files).toEqual([{ name: 'evidence-1.pdf', cid: 'QmTestCid', mimetype: undefined, size: undefined }]);
    expect(view.zkProof?.proofHash).toBe('0xproofhash');
    expect(view.zkProof?.txHash).toBe('0xtxhash');
  });

  it('carries AI-extracted org facts (FR-2) without identity', () => {
    const view = buildDisseminationView(
      makeReport({
        verification: {
          isLegitimate: true,
          credibilityScore: 82,
          category: 'corruption',
          organizationType: 'for-profit',
          namedOrganization: 'Acme Corp',
        },
      }),
      '',
    );
    expect(view.orgType).toBe('for-profit');
    expect(view.subjectOrganization).toBe('Acme Corp');
  });

  it('folds taxonomy, legacy, and AI categories into slugs without duplicates', () => {
    const view = buildDisseminationView(
      makeReport({ categories: ['cyber-security'], category: 'fraud' }),
      '',
    );
    // verification.category 'corruption' → government-accountability
    expect(view.categories).toEqual(['cyber-security', 'financial-fraud', 'government-accountability']);
  });
});

describe('routingEngine.recommend', () => {
  it('recommends the seeded route for a cyber-security report', async () => {
    const view = buildDisseminationView(makeReport({ verification: undefined, category: undefined }), '');
    const plan = await routingEngine.recommend(view, fullConsent());

    const entityIds = plan.channels.map((c) => c.entityId);
    expect(entityIds).toContain('cisa');
    expect(entityIds).toContain('psst-safe');

    const cisa = plan.channels.find((c) => c.entityId === 'cisa')!;
    expect(cisa.supported).toBe(true);
    expect(cisa.consentSatisfied).toBe(true);
  });

  it('flags channels without consent instead of hiding them', async () => {
    const view = buildDisseminationView(makeReport({ verification: undefined, category: undefined }), '');
    const consent: ConsentSnapshot = { ...fullConsent(), agency: false };
    const plan = await routingEngine.recommend(view, consent);

    const cisa = plan.channels.find((c) => c.entityId === 'cisa')!;
    const psst = plan.channels.find((c) => c.entityId === 'psst-safe')!;
    expect(cisa.consentSatisfied).toBe(false);
    expect(psst.consentSatisfied).toBe(true);
  });

  it('treats missing consent as no consent for every channel', async () => {
    const view = buildDisseminationView(makeReport({ verification: undefined, category: undefined }), '');
    const plan = await routingEngine.recommend(view, null);
    expect(plan.channels.every((c) => !c.consentSatisfied)).toBe(true);
  });

  it('returns no channels when the report has no mappable category', async () => {
    const view = buildDisseminationView(
      makeReport({ categories: [], category: 'other', verification: undefined }),
      '',
    );
    const plan = await routingEngine.recommend(view, fullConsent());
    expect(plan.channels).toHaveLength(0);
  });

  it('does not route to EU Directive channels without EU jurisdiction (Phase 4c)', async () => {
    // No jurisdiction recorded (pre-4c report) → US-default routing.
    const noJurisdiction = buildDisseminationView(
      makeReport({ categories: ['financial-fraud'], verification: undefined, category: undefined }),
      '',
    );
    let plan = await routingEngine.recommend(noJurisdiction, fullConsent());
    let entityIds = plan.channels.map((c) => c.entityId);
    expect(entityIds).not.toContain('eu-olaf');
    expect(entityIds).not.toContain('de-external');

    // Explicit US jurisdiction → same.
    const usView = buildDisseminationView(
      makeReport({ categories: ['financial-fraud'], jurisdiction: 'us', verification: undefined, category: undefined }),
      '',
    );
    plan = await routingEngine.recommend(usView, fullConsent());
    entityIds = plan.channels.map((c) => c.entityId);
    expect(entityIds).not.toContain('eu-olaf');
  });

  it('adds EU Directive channels for EU-jurisdiction reports (Phase 4c)', async () => {
    const euView = buildDisseminationView(
      makeReport({ categories: ['financial-fraud'], jurisdiction: 'eu', verification: undefined, category: undefined }),
      '',
    );
    const plan = await routingEngine.recommend(euView, fullConsent());
    const entityIds = plan.channels.map((c) => c.entityId);

    // OLAF and DG COMP fire on the category; member-state channels are
    // category-agnostic. US routing still applies alongside.
    expect(entityIds).toContain('eu-olaf');
    expect(entityIds).toContain('ec-competition');
    expect(entityIds).toContain('de-external');
    expect(entityIds).toContain('sec-tcr');

    const olaf = plan.channels.find((c) => c.entityId === 'eu-olaf')!;
    expect(olaf.supported).toBe(true);
    const memberState = plan.channels.find((c) => c.entityId === 'de-external')!;
    expect(memberState.supported).toBe(false);
  });

  it('applies the orgType dimension (FR-2) via editable rules', async () => {
    // An admin-authored rule: for-profit financial fraud also routes to DOJ.
    await disseminationPersistence.upsertRoutingRule({
      ruleId: 'test-orgtype-forprofit-v1',
      match: { categories: ['financial-fraud'], orgType: ['for-profit'] },
      route: [{ entityId: 'doj', tier: 'B' }],
      active: true,
    });

    const base = {
      categories: ['financial-fraud'] as string[],
      category: undefined,
    };
    const forProfit = buildDisseminationView(
      makeReport({
        ...base,
        verification: {
          isLegitimate: true, credibilityScore: 80, category: 'fraud',
          organizationType: 'for-profit', namedOrganization: 'Acme Corp',
        },
      }),
      '',
    );
    const government = buildDisseminationView(
      makeReport({
        ...base,
        verification: {
          isLegitimate: true, credibilityScore: 80, category: 'fraud',
          organizationType: 'us-federal-government',
        },
      }),
      '',
    );
    const unknown = buildDisseminationView(
      makeReport({ ...base, verification: undefined }),
      '',
    );

    const planFor = await routingEngine.recommend(forProfit, fullConsent());
    // Matched via the orgType-constrained rule (doj is also in the default
    // financial-fraud matrix, so assert the rule itself matched by reason).
    const dojChannel = planFor.channels.find((c) => c.entityId === 'doj');
    expect(dojChannel).toBeDefined();

    // orgType-constrained rules never fire for other/unknown org types.
    // Deactivate the default matrix noise by checking rule matching directly:
    const rules = await disseminationPersistence.listAllRules();
    const rule = rules.find((r) => r.ruleId === 'test-orgtype-forprofit-v1')!;
    expect(rule.version).toBe(1);
    const matches = (view: typeof forProfit) =>
      (routingEngine as unknown as {
        ruleMatches: (m: typeof rule.match, v: typeof forProfit) => boolean;
      }).ruleMatches(rule.match, view);
    expect(matches(forProfit)).toBe(true);
    expect(matches(government)).toBe(false);
    expect(matches(unknown)).toBe(false);

    // Cleanup: deactivate so other tests are unaffected; version bumps.
    const updated = await disseminationPersistence.upsertRoutingRule({
      ruleId: 'test-orgtype-forprofit-v1',
      match: rule.match,
      route: rule.route,
      active: false,
    });
    expect(updated.version).toBe(2);
    const active = await disseminationPersistence.getActiveRules();
    expect(active.some((r) => r.ruleId === 'test-orgtype-forprofit-v1')).toBe(false);
  });

  it('lists dispatchable channels before unimplemented ones', async () => {
    const view = buildDisseminationView(
      makeReport({ categories: ['financial-fraud'], verification: undefined, category: undefined }),
      '',
    );
    const plan = await routingEngine.recommend(view, fullConsent());

    const firstUnsupported = plan.channels.findIndex((c) => !c.supported);
    const lastSupported = plan.channels.map((c) => c.supported).lastIndexOf(true);
    if (firstUnsupported !== -1) {
      expect(lastSupported).toBeLessThan(firstUnsupported);
    }
  });
});
