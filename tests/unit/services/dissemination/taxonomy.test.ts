/**
 * Taxonomy tests: ten Psst categories, legacy mapping, routing matrix shape.
 */

import {
  CATEGORIES,
  CATEGORY_SLUGS,
  DEFAULT_ROUTING_MATRIX,
  ENTITIES,
  EU_ROUTING_RULES,
  getEntity,
  isCategorySlug,
  isJurisdiction,
  normalizeCategory,
} from '../../../../src/services/dissemination/taxonomy';

describe('dissemination taxonomy', () => {
  it('defines exactly the ten Psst categories', () => {
    expect(CATEGORIES).toHaveLength(10);
    expect(CATEGORY_SLUGS).toEqual([
      'ai-safety',
      'trust-safety',
      'encryption',
      'financial-fraud',
      'discrimination-harassment',
      'cyber-security',
      'crypto',
      'environment-climate',
      'government-accountability',
      'illegal-government-activity',
    ]);
  });

  it('recognizes taxonomy slugs', () => {
    expect(isCategorySlug('cyber-security')).toBe(true);
    expect(isCategorySlug('fraud')).toBe(false);
    expect(isCategorySlug('')).toBe(false);
  });

  it('maps legacy web-form categories onto the taxonomy', () => {
    expect(normalizeCategory('harassment')).toBe('discrimination-harassment');
    expect(normalizeCategory('discrimination')).toBe('discrimination-harassment');
    expect(normalizeCategory('fraud')).toBe('financial-fraud');
    expect(normalizeCategory('safety')).toBe('trust-safety');
    expect(normalizeCategory('policy')).toBe('government-accountability');
  });

  it('maps Venice AI verification categories', () => {
    expect(normalizeCategory('corruption')).toBe('government-accountability');
    expect(normalizeCategory('environmental')).toBe('environment-climate');
  });

  it('passes through taxonomy slugs and normalizes case', () => {
    expect(normalizeCategory('crypto')).toBe('crypto');
    expect(normalizeCategory('  Cyber-Security ')).toBe('cyber-security');
  });

  it('returns null for unmappable values', () => {
    expect(normalizeCategory('other')).toBeNull();
    expect(normalizeCategory('')).toBeNull();
    expect(normalizeCategory(undefined)).toBeNull();
    expect(normalizeCategory(null)).toBeNull();
  });

  it('has a routing entry for every category, each pointing at known entities', () => {
    for (const slug of CATEGORY_SLUGS) {
      const routes = DEFAULT_ROUTING_MATRIX[slug];
      expect(routes.length).toBeGreaterThan(0);
      for (const route of routes) {
        expect(getEntity(route.entityId)).not.toBeNull();
      }
    }
  });

  it('every category routes to Psst Safe except none excluded by design', () => {
    // Psst is the partner channel across the taxonomy (PDR §6 matrix).
    for (const slug of CATEGORY_SLUGS) {
      const entityIds = DEFAULT_ROUTING_MATRIX[slug].map((r) => r.entityId);
      expect(entityIds).toContain('psst-safe');
    }
  });

  it('marks exactly the shipped channels as implemented (Tiers A/B/C + Psst + EU)', () => {
    const implemented = ENTITIES.filter((e) => e.implemented).map((e) => e.entityId).sort();
    expect(implemented).toEqual([
      'agency-oig',
      'cftc-tcr',
      'cisa',
      'doj',
      'ec-competition',
      'eeoc',
      'epa-oig',
      'epa-violation',
      'eu-olaf',
      'fbi-ic3',
      'fincen',
      'ftc',
      'gao-fraudnet',
      'irs-211',
      'osc',
      'osha',
      'psst-safe',
      'sec-tcr',
      'securedrop',
    ]);
  });

  it('EU routing rules only target known entities and are all EU-scoped', () => {
    for (const rule of EU_ROUTING_RULES) {
      expect(rule.jurisdiction).toEqual(['eu']);
      for (const target of rule.route) {
        expect(getEntity(target.entityId)).not.toBeNull();
      }
    }
  });

  it('recognizes jurisdictions', () => {
    expect(isJurisdiction('us')).toBe(true);
    expect(isJurisdiction('eu')).toBe(true);
    expect(isJurisdiction('other')).toBe(true);
    expect(isJurisdiction('uk')).toBe(false);
    expect(isJurisdiction('')).toBe(false);
  });
});
