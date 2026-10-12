/**
 * Per-recipient packet completeness (ALPHA-098): a report is graded against a
 * per-entity checklist so admins/dispatch are warned when a packet reaches a
 * recipient missing something that entity needs. `required` gaps fail `ok`;
 * `recommended` gaps are surfaced but never fail it.
 */

import { checkPacketCompleteness } from '../../../../src/services/dissemination/packetCompleteness';
import { SECURE_LINK_ENTITY_ID } from '../../../../src/services/dissemination/secureLink';
import type { DisseminationView } from '../../../../src/services/dissemination/types';

function view(overrides: Partial<DisseminationView> = {}): DisseminationView {
  return {
    trackingId: 'VRA-TEST0123456789',
    categories: ['cyber-security'],
    rawCategories: [],
    narrative: 'A detailed account of the wrongdoing observed at the agency.',
    subjectOrganization: 'Acme Federal Contractor',
    dateOfIncident: '2026-06-01',
    evidence: { evidenceHash: 'e'.repeat(64), files: [{ name: 'proof.pdf' }] },
    zkProof: { proofHash: '0xabc', verified: true, proofType: 'compact_circuit', txHash: 'transaction', contractAddress: 'contract' },
    submittedAt: new Date('2026-06-02T00:00:00Z'),
    jurisdiction: 'us',
    ...overrides,
  };
}

const keys = (r: ReturnType<typeof checkPacketCompleteness>) => r.missing.map((m) => m.key);

describe('checkPacketCompleteness', () => {
  it('passes a complete cyber report for CISA with nothing missing', () => {
    const r = checkPacketCompleteness(view(), 'cisa');
    expect(r.ok).toBe(true);
    expect(r.missing).toHaveLength(0);
    expect(r.entityName).toBe('CISA Incident Reporting');
  });

  it('fails when the narrative is missing (required, every entity)', () => {
    const r = checkPacketCompleteness(view({ narrative: '   ' }), 'cisa');
    expect(r.ok).toBe(false);
    expect(r.missing.find((m) => m.key === 'narrative')?.severity).toBe('required');
  });

  it('fails when categories are empty (required)', () => {
    const r = checkPacketCompleteness(view({ categories: [] }), 'cisa');
    expect(r.ok).toBe(false);
    expect(keys(r)).toContain('categories');
  });

  it('requires the subject organisation for GAO FraudNet', () => {
    const r = checkPacketCompleteness(view({ subjectOrganization: undefined }), 'gao-fraudnet');
    expect(r.ok).toBe(false);
    expect(r.missing.find((m) => m.key === 'subjectOrganization')?.severity).toBe('required');
  });

  it('passes GAO once the subject organisation is present', () => {
    expect(checkPacketCompleteness(view(), 'gao-fraudnet').ok).toBe(true);
  });

  it('treats subject organisation as only recommended for the generic secure-link recipient', () => {
    const r = checkPacketCompleteness(view({ subjectOrganization: undefined }), SECURE_LINK_ENTITY_ID);
    expect(r.ok).toBe(true); // a recommended gap never fails ok
    expect(r.missing.find((m) => m.key === 'subjectOrganization')?.severity).toBe('recommended');
    expect(r.entityName).toBe(SECURE_LINK_ENTITY_ID); // unknown entity → falls back to the id
  });

  it('flags a non-cyber category for CISA as a recommendation, not a failure', () => {
    const r = checkPacketCompleteness(view({ categories: ['financial-fraud'] }), 'cisa');
    expect(r.ok).toBe(true);
    expect(r.missing.find((m) => m.key === 'cyberCategory')?.severity).toBe('recommended');
  });

  it('does not add the cyber check for non-CISA entities', () => {
    const r = checkPacketCompleteness(view({ categories: ['financial-fraud'] }), 'gao-fraudnet');
    expect(keys(r)).not.toContain('cyberCategory');
  });

  it('orders missing items required-first', () => {
    const r = checkPacketCompleteness(view({ narrative: '', dateOfIncident: undefined }), 'cisa');
    expect(r.missing.length).toBeGreaterThanOrEqual(2);
    expect(r.missing[0].severity).toBe('required');
  });

  it('counts evidence present when only a digest exists (no files)', () => {
    const r = checkPacketCompleteness(view({ evidence: { evidenceHash: 'e'.repeat(64), files: [] } }), 'cisa');
    expect(keys(r)).not.toContain('evidence');
  });

  it('flags missing evidence as recommended, not a failure', () => {
    const r = checkPacketCompleteness(view({ evidence: { files: [] } }), 'cisa');
    expect(r.ok).toBe(true);
    expect(r.missing.find((m) => m.key === 'evidence')?.severity).toBe('recommended');
  });

  it('flags an unverified proof as a recommended existence-proof gap', () => {
    const r = checkPacketCompleteness(view({ zkProof: { proofHash: '0x', verified: false } }), 'cisa');
    expect(keys(r)).toContain('existenceProof');
    expect(r.ok).toBe(true);
  });
});

it.each([
  { proofHash: 'fallback', verified: true, proofType: 'hash_commitment' as const },
  { proofHash: 'incomplete', verified: true, proofType: 'compact_circuit' as const },
])('does not certify a verified blockchain reference from incomplete or fallback proof', zkProof => {
  expect(keys(checkPacketCompleteness(view({ zkProof }), 'cisa'))).toContain('existenceProof');
});
