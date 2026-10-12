/**
 * Dissemination taxonomy (VERA-PDR-001 §6).
 *
 * The ten concern categories are adopted verbatim from Psst Safe so that
 * Vera↔Psst handoffs are lossless. Each category maps to a default set of
 * U.S. receiving entities; the routing engine may add or remove entities
 * based on facts. Routing rules themselves are data (routing_rules
 * collection) — this module provides the seed defaults and the entity
 * registry.
 */

export type CategorySlug =
  | 'ai-safety'
  | 'trust-safety'
  | 'encryption'
  | 'financial-fraud'
  | 'discrimination-harassment'
  | 'cyber-security'
  | 'crypto'
  | 'environment-climate'
  | 'government-accountability'
  | 'illegal-government-activity';

export interface CategoryDef {
  slug: CategorySlug;
  /** Display label — verbatim Psst Safe wording. */
  label: string;
}

/** The ten Psst Safe categories, in Psst's display order (PDR §6). */
export const CATEGORIES: readonly CategoryDef[] = [
  { slug: 'ai-safety', label: 'AI Safety' },
  { slug: 'trust-safety', label: 'Trust & Safety' },
  { slug: 'encryption', label: 'Encryption' },
  { slug: 'financial-fraud', label: 'Financial Fraud' },
  { slug: 'discrimination-harassment', label: 'Discrimination/Harassment' },
  { slug: 'cyber-security', label: 'Cyber security' },
  { slug: 'crypto', label: 'Crypto' },
  { slug: 'environment-climate', label: 'Environment or climate issues' },
  { slug: 'government-accountability', label: 'Government accountability' },
  { slug: 'illegal-government-activity', label: 'Illegal government activity' },
] as const;

export const CATEGORY_SLUGS: readonly CategorySlug[] = CATEGORIES.map((c) => c.slug);

export function isCategorySlug(value: string): value is CategorySlug {
  return (CATEGORY_SLUGS as readonly string[]).includes(value);
}

export function categoryLabel(slug: CategorySlug): string {
  return CATEGORIES.find((c) => c.slug === slug)?.label ?? slug;
}

/**
 * Map legacy category values (pre-taxonomy web form, Venice AI output,
 * Eliza display names) onto the ten-category taxonomy. Used when routing
 * reports submitted before the taxonomy shipped, and to fold AI-derived
 * categories into routing facts.
 */
const LEGACY_CATEGORY_MAP: Record<string, CategorySlug> = {
  // Legacy web form slugs (pages/report.tsx before this change)
  harassment: 'discrimination-harassment',
  discrimination: 'discrimination-harassment',
  safety: 'trust-safety',
  fraud: 'financial-fraud',
  policy: 'government-accountability',
  // Venice AI verification categories
  corruption: 'government-accountability',
  environmental: 'environment-climate',
  // Eliza display names
  'financial fraud': 'financial-fraud',
  'safety violation': 'trust-safety',
  'environmental crime': 'environment-climate',
  // Historical report category aliases
  ethics: 'government-accountability',
};

/**
 * Normalize any category value (legacy slug, AI label, taxonomy slug) to a
 * taxonomy slug, or null when there is no meaningful mapping (e.g. 'other').
 */
export function normalizeCategory(value: unknown): CategorySlug | null {
  if (typeof value !== 'string' || !value) return null;
  const lowered = value.trim().toLowerCase();
  if (isCategorySlug(lowered)) return lowered;
  return Object.prototype.hasOwnProperty.call(LEGACY_CATEGORY_MAP, lowered) ? LEGACY_CATEGORY_MAP[lowered] : null;
}

// ── Jurisdictions (Phase 4c) ────────────────────────────────────────

/**
 * Where the reported conduct is governed. Drives the routing dimension:
 * EU Directive 2019/1937 external-reporting channels only apply to EU
 * jurisdiction reports. 'us' is the default posture (all pre-4c reports
 * have no jurisdiction recorded and route as US).
 */
export type Jurisdiction = 'us' | 'eu' | 'other';

export const JURISDICTIONS: readonly { value: Jurisdiction; label: string }[] = [
  { value: 'us', label: 'United States' },
  { value: 'eu', label: 'European Union (member state)' },
  { value: 'other', label: 'Other / not sure' },
] as const;

export function isJurisdiction(value: string): value is Jurisdiction {
  return JURISDICTIONS.some((j) => j.value === value);
}

// ── Organization types (FR-2, mirrors Psst's taxonomy) ──────────────

/**
 * Type of the organization a report concerns. Proposed by Venice AI
 * triage at verification time; drives the orgType routing dimension.
 */
export type OrgType =
  | 'us-federal-government'
  | 'state-government'
  | 'local-government'
  | 'other-government'
  | 'for-profit'
  | 'nonprofit'
  | 'unknown';

export const ORG_TYPES: readonly OrgType[] = [
  'us-federal-government',
  'state-government',
  'local-government',
  'other-government',
  'for-profit',
  'nonprofit',
  'unknown',
] as const;

export function isOrgType(value: string): value is OrgType {
  return (ORG_TYPES as readonly string[]).includes(value);
}

// ── Receiving entities ──────────────────────────────────────────────

export type Tier = 'A' | 'B' | 'C';

export interface EntityDef {
  entityId: string;
  name: string;
  tier: Tier;
  /** True when a dispatchable adapter ships in this phase (Tier A + Psst Stage-1). */
  implemented: boolean;
  /** SLA profile: some entities never acknowledge (PDR §14). */
  ackExpected: boolean;
  /**
   * Whether the entity ever sends substantive feedback (EU Directive 3-month
   * clock). Defaults to `ackExpected` when unset — an entity that never even
   * acknowledges won't send feedback, so it raises no feedback-SLA breach
   * (PDR §14: avoid alert fatigue for non-responding agencies).
   */
  feedbackExpected?: boolean;
  notes?: string;
}

/**
 * Registry of receiving entities (PDR §2, §7.3). Tier assignment reflects
 * the anonymous-reporter path — the same entity can be Tier B for a named
 * reporter, but Vera's default posture is anonymity.
 */
export const ENTITIES: readonly EntityDef[] = [
  // Tier A — automated (implemented this phase)
  { entityId: 'cisa', name: 'CISA Incident Reporting', tier: 'A', implemented: true, ackExpected: true },
  { entityId: 'gao-fraudnet', name: 'GAO FraudNet', tier: 'A', implemented: true, ackExpected: true },
  { entityId: 'epa-oig', name: 'EPA Office of Inspector General', tier: 'A', implemented: true, ackExpected: false },
  // Partner channel — Stage-1 deep-link handoff (implemented this phase)
  { entityId: 'psst-safe', name: 'Psst.org Safe', tier: 'A', implemented: true, ackExpected: false, notes: 'Stage-1 deep-link handoff; partner-not-roadblock invariant (FR-9)' },
  // Tier B — assisted portal companions (Phase 2c: prepared filing session, human submits)
  { entityId: 'sec-tcr', name: 'SEC Office of the Whistleblower (Form TCR)', tier: 'B', implemented: true, ackExpected: true, notes: 'Anonymous filing requires attorney of record (Rule 21F-9)' },
  { entityId: 'cftc-tcr', name: 'CFTC Whistleblower Office (Form TCR)', tier: 'B', implemented: true, ackExpected: true, notes: 'Anonymous filing requires attorney of record' },
  { entityId: 'fincen', name: 'FinCEN Office of the Whistleblower', tier: 'B', implemented: true, ackExpected: true },
  { entityId: 'irs-211', name: 'IRS Whistleblower Office (Form 211)', tier: 'B', implemented: true, ackExpected: false, notes: 'Mail-only intake; identity required — file through counsel' },
  // US registry breadth (PDR completion) — public web-form portals as companions
  { entityId: 'fbi-ic3', name: 'FBI Internet Crime Complaint Center (IC3)', tier: 'B', implemented: true, ackExpected: false, notes: 'Public complaint portal; complaint ID shown at submission is the receipt' },
  { entityId: 'epa-violation', name: 'EPA Violation Reporting', tier: 'B', implemented: true, ackExpected: false, notes: 'Anonymous-friendly web form; no confirmation number — manual receipt' },
  { entityId: 'ftc', name: 'Federal Trade Commission', tier: 'B', implemented: true, ackExpected: false, notes: 'ReportFraud.ftc.gov; report number at end of flow is the receipt' },
  { entityId: 'doj', name: 'Department of Justice', tier: 'B', implemented: true, ackExpected: false, notes: 'Component-specific intake; qui tam/FCA matters must go through counsel instead' },
  // US placeholders without adapters yet
  { entityId: 'irs-ci', name: 'IRS Criminal Investigation (Form 3949-A)', tier: 'B', implemented: false, ackExpected: false, notes: 'Tax fraud information referral; no acknowledgment by policy' },
  { entityId: 'state-ag', name: 'State Attorney General (relevant state)', tier: 'C', implemented: false, ackExpected: false, notes: 'State-level consumer protection / fraud; intake varies by state — counsel-mediated' },
  { entityId: 'congressional-committee', name: 'Congressional Oversight Committee', tier: 'C', implemented: false, ackExpected: false, notes: 'Whistleblower disclosures to Congress; counsel-first (5 U.S.C. §2302 routes apply)' },
  // Tier C — counsel-mediated (Phase 3: matter-code flow, identity leg off-platform)
  { entityId: 'eeoc', name: 'EEOC', tier: 'C', implemented: true, ackExpected: true, notes: 'Identity required for charges; counsel-first' },
  { entityId: 'osha', name: 'OSHA Whistleblower Protection', tier: 'C', implemented: true, ackExpected: true, notes: 'Identity required; counsel-first' },
  { entityId: 'osc', name: 'Office of Special Counsel', tier: 'C', implemented: true, ackExpected: true, notes: 'Identity required but statutorily protected' },
  { entityId: 'agency-oig', name: 'Relevant Agency OIG', tier: 'C', implemented: true, ackExpected: false, notes: 'Counsel-mediated referral' },
  // EU Directive 2019/1937 external-reporting channels (Phase 4c).
  // The 7-day-ack / 3-month-feedback SLA clocks in receiptTracker were
  // modeled on the Directive and apply to these entities as-is.
  { entityId: 'eu-olaf', name: 'European Anti-Fraud Office (OLAF)', tier: 'B', implemented: true, ackExpected: true, notes: 'Anonymous Notification System portal; EU-budget fraud, corruption, and serious misconduct in EU institutions' },
  { entityId: 'ec-competition', name: 'European Commission — Competition Whistleblower Tool', tier: 'B', implemented: true, ackExpected: false, notes: 'Anonymous tool for cartel/antitrust information; no acknowledgment guaranteed' },
  { entityId: 'de-external', name: 'Germany — Federal Office of Justice External Reporting Office', tier: 'B', implemented: false, ackExpected: true, notes: 'HinSchG external channel; 7-day ack / 3-month feedback per Directive' },
  { entityId: 'fr-external', name: 'France — Défenseur des droits', tier: 'B', implemented: false, ackExpected: true, notes: 'Sapin II / Waserman external channel' },
  { entityId: 'ie-external', name: 'Ireland — Office of the Protected Disclosures Commissioner', tier: 'B', implemented: false, ackExpected: true, notes: 'Protected Disclosures (Amendment) Act 2022 external channel' },
  { entityId: 'nl-external', name: 'Netherlands — Huis voor Klokkenluiders', tier: 'B', implemented: false, ackExpected: true, notes: 'Wet bescherming klokkenluiders external channel' },
  // Press / media disclosure (reporter-elected, opt-in). No API — per-newsroom Tor
  // onion instances from the FPF directory; MVP is a single Stage-1 deep-link handoff
  // to securedrop.org/directory (the Psst pattern; reporter picks a newsroom). Consent-
  // gated on consent.press in disseminationService.approve, so it never disseminates
  // without an explicit press election; it appears in the routing matrix like psst-safe
  // but only dispatches with that consent + admin approval. Per-newsroom seeding is
  // deferred. See docs/pdr/VERA-PDR-001-A2-securedrop-press-channel.md.
  { entityId: 'securedrop', name: 'SecureDrop (press/media disclosure)', tier: 'B', implemented: true, ackExpected: false, notes: 'MVP: Stage-1 deep-link handoff to the FPF directory (securedrop.org/directory); reporter picks a newsroom; consent.press-gated; manual/codename receipt. Per-newsroom seeding deferred.' },
] as const;

export function getEntity(entityId: string): EntityDef | null {
  return ENTITIES.find((e) => e.entityId === entityId) ?? null;
}

// ── Default routing matrix (PDR §6) ─────────────────────────────────

export interface RouteTarget {
  entityId: string;
  tier: Tier;
}

/**
 * Category → default receiving entities. Seeds the routing_rules
 * collection; routing_rules documents override these at runtime.
 */
export const DEFAULT_ROUTING_MATRIX: Record<CategorySlug, RouteTarget[]> = {
  'ai-safety': [
    { entityId: 'ftc', tier: 'B' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'trust-safety': [
    { entityId: 'ftc', tier: 'B' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  encryption: [
    // Frequently involves classified/export-control-adjacent facts; counsel-first.
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'financial-fraud': [
    { entityId: 'sec-tcr', tier: 'B' },
    { entityId: 'cftc-tcr', tier: 'B' },
    { entityId: 'fincen', tier: 'B' },
    { entityId: 'irs-211', tier: 'B' },
    { entityId: 'irs-ci', tier: 'B' },
    { entityId: 'doj', tier: 'B' },
    { entityId: 'ftc', tier: 'B' },
    { entityId: 'state-ag', tier: 'C' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'discrimination-harassment': [
    { entityId: 'eeoc', tier: 'C' },
    { entityId: 'osha', tier: 'C' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'cyber-security': [
    { entityId: 'cisa', tier: 'A' },
    { entityId: 'fbi-ic3', tier: 'B' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  crypto: [
    { entityId: 'sec-tcr', tier: 'B' },
    { entityId: 'cftc-tcr', tier: 'B' },
    { entityId: 'fincen', tier: 'B' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'environment-climate': [
    { entityId: 'epa-oig', tier: 'A' },
    { entityId: 'epa-violation', tier: 'B' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'government-accountability': [
    { entityId: 'agency-oig', tier: 'C' },
    { entityId: 'osc', tier: 'C' },
    { entityId: 'gao-fraudnet', tier: 'A' },
    { entityId: 'congressional-committee', tier: 'C' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
  'illegal-government-activity': [
    { entityId: 'agency-oig', tier: 'C' },
    { entityId: 'osc', tier: 'C' },
    { entityId: 'gao-fraudnet', tier: 'A' },
    { entityId: 'doj', tier: 'B' },
    { entityId: 'congressional-committee', tier: 'C' },
    { entityId: 'psst-safe', tier: 'A' },
    { entityId: 'securedrop', tier: 'B' },
  ],
};

/**
 * EU Directive routing rules (Phase 4c). Unlike the default matrix these
 * only fire when the report's jurisdiction is 'eu' — US routing stays the
 * default for everything else (including pre-4c reports with no
 * jurisdiction recorded).
 */
export interface JurisdictionRuleSeed {
  ruleId: string;
  categories?: CategorySlug[];
  jurisdiction: Jurisdiction[];
  route: RouteTarget[];
}

export const EU_ROUTING_RULES: readonly JurisdictionRuleSeed[] = [
  {
    // OLAF: EU-budget fraud, corruption, serious misconduct.
    ruleId: 'eu-olaf-v1',
    categories: ['financial-fraud', 'crypto', 'government-accountability', 'illegal-government-activity', 'environment-climate'],
    jurisdiction: ['eu'],
    route: [{ entityId: 'eu-olaf', tier: 'B' }],
  },
  {
    // DG COMP anonymous whistleblower tool: cartel/antitrust facts.
    ruleId: 'eu-competition-v1',
    categories: ['financial-fraud'],
    jurisdiction: ['eu'],
    route: [{ entityId: 'ec-competition', tier: 'B' }],
  },
  {
    // Member-state external channels are category-agnostic under the
    // Directive; surface them on every EU plan so admins see the options.
    ruleId: 'eu-directive-national-v1',
    jurisdiction: ['eu'],
    route: [
      { entityId: 'de-external', tier: 'B' },
      { entityId: 'fr-external', tier: 'B' },
      { entityId: 'ie-external', tier: 'B' },
      { entityId: 'nl-external', tier: 'B' },
    ],
  },
] as const;

/** Psst deposit-treatment election (mirrors Psst Safe's three options). */
export type PsstTreatment = 'contact-now' | 'contact-on-match' | 'hold-encrypted';

export const PSST_TREATMENTS: readonly { value: PsstTreatment; label: string }[] = [
  { value: 'contact-now', label: 'Contact me now — connect me with the Psst legal team' },
  { value: 'contact-on-match', label: 'Contact me if my report matches others about the same organization' },
  { value: 'hold-encrypted', label: 'Hold my deposit encrypted — do not read it unless I say so' },
] as const;

/**
 * Version tag of the consent language shown to reporters. Bump when the
 * consent wording changes so stored snapshots stay auditable (FR-8).
 */
export const CONSENT_TEXT_VERSION = 'v2';

export const CONSENT_QUESTIONS = {
  psst: 'May Vera share this report with partner legal counsel (Psst.org)?',
  agency: 'May Vera submit this report to the appropriate government agency on your behalf?',
} as const;
