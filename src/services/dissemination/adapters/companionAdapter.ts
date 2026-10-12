/**
 * Tier B companion adapter (Phase 2c, Option B1: packet + checklist).
 *
 * Tier B portals (SEC/CFTC TCR, FinCEN) have session flows, confirmations,
 * and perjury declarations that make unattended automation legally and
 * practically unwise. This adapter therefore prepares everything and
 * automates nothing: dispatch is a handoff that surfaces the portal URL
 * and a paste-ready, question-ordered answer sheet in the admin filing
 * session (the same handoff pathway as the Psst Stage-1 deep link, so the
 * worker and panel need no new states). The portal confirmation / control
 * number the human receives is recorded as the channel receipt.
 */

import { renderCompanionText, PORTAL_PROFILES } from '../tcrModel';
import type {
  DisseminationView,
  DispatchResult,
  Packet,
  PreparedSubmission,
  Receipt,
  SubmissionAdapter,
  Tier,
} from '../types';

export interface CompanionAdapterConfig {
  entityId: string;
  /** Regexes recognizing the portal's confirmation artifact. */
  receiptPatterns?: { pattern: RegExp; type: Receipt['type'] }[];
}

export class CompanionAdapter implements SubmissionAdapter {
  readonly entityId: string;
  readonly tier: Tier = 'B';
  private readonly config: CompanionAdapterConfig;

  constructor(config: CompanionAdapterConfig) {
    this.entityId = config.entityId;
    this.config = config;
    if (!PORTAL_PROFILES[config.entityId]) {
      throw new Error(`No portal profile for companion adapter ${config.entityId}`);
    }
  }

  /** Companion generation is local — no external service to trip. */
  allowsDispatch(): boolean {
    return true;
  }

  async prepare(view: DisseminationView, _packet: Packet): Promise<PreparedSubmission> {
    const profile = PORTAL_PROFILES[this.entityId];
    return {
      entityId: this.entityId,
      trackingId: view.trackingId,
      mode: 'deep-link',
      deepLink: {
        url: profile.portalUrl,
        fields: { form: profile.formName },
        depositBody: renderCompanionText(view, this.entityId),
      },
    };
  }

  async dispatch(_prep: PreparedSubmission): Promise<DispatchResult> {
    return {
      outcome: 'handoff',
      detail: `${this.entityId} filing companion prepared; awaiting human portal session + confirmation number`,
    };
  }

  parseReceipt(raw: unknown): Receipt | null {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    for (const { pattern, type } of this.config.receiptPatterns ?? []) {
      const match = raw.match(pattern);
      if (match) {
        return { type, value: match[1] ?? match[0], receivedAt: new Date() };
      }
    }
    // Portal confirmations are entered by the filing admin — trust them.
    return { type: 'portal-confirmation', value: raw.trim(), receivedAt: new Date() };
  }
}

/** SEC Form TCR — portal returns a TCR confirmation number. */
export const secTcrAdapter = new CompanionAdapter({
  entityId: 'sec-tcr',
  receiptPatterns: [
    { pattern: /TCR\s*(?:confirmation|number|#)?[:#\s]*([A-Z0-9-]{6,})/i, type: 'portal-confirmation' },
  ],
});

/** CFTC Form TCR — mirrors the SEC portal. */
export const cftcTcrAdapter = new CompanionAdapter({
  entityId: 'cftc-tcr',
  receiptPatterns: [
    { pattern: /TCR\s*(?:confirmation|number|#)?[:#\s]*([A-Z0-9-]{6,})/i, type: 'portal-confirmation' },
  ],
});

/** FinCEN whistleblower submission — receipt is a reference number. */
export const fincenAdapter = new CompanionAdapter({
  entityId: 'fincen',
  receiptPatterns: [
    { pattern: /reference\s*(?:number|no\.?|#)[:#\s]*([A-Z0-9-]{4,})/i, type: 'control-number' },
  ],
});

/** IRS Form 211 — mail-only; the receipt is the certified-mail artifact. */
export const irs211Adapter = new CompanionAdapter({
  entityId: 'irs-211',
  receiptPatterns: [
    { pattern: /certified\s*mail\s*(?:number|no\.?|#)?[:#\s]*([0-9 -]{10,})/i, type: 'manual' },
  ],
});

/** FBI IC3 — the portal shows a complaint ID at the end of the flow. */
export const fbiIc3Adapter = new CompanionAdapter({
  entityId: 'fbi-ic3',
  receiptPatterns: [
    { pattern: /(?:complaint|ic3)\s*(?:id|number|no\.?|#)[:#\s]*([A-Z0-9-]{6,})/i, type: 'portal-confirmation' },
  ],
});

/** EPA violation form — no confirmation number; the receipt is manual. */
export const epaViolationAdapter = new CompanionAdapter({
  entityId: 'epa-violation',
});

/** FTC ReportFraud — the flow ends with a report number. */
export const ftcAdapter = new CompanionAdapter({
  entityId: 'ftc',
  receiptPatterns: [
    { pattern: /report\s*(?:number|no\.?|#)[:#\s]*([A-Z0-9-]{5,})/i, type: 'portal-confirmation' },
  ],
});

/** DOJ component intake — receipts are manual (component + filing date). */
export const dojAdapter = new CompanionAdapter({
  entityId: 'doj',
});

/** OLAF Fraud Notification System — issues a case reference on submission (Phase 4c). */
export const euOlafAdapter = new CompanionAdapter({
  entityId: 'eu-olaf',
  receiptPatterns: [
    { pattern: /(?:case|notification)\s*(?:reference|number|no\.?|#)[:#\s]*([A-Z0-9\/.-]{4,})/i, type: 'portal-confirmation' },
  ],
});

/** EC competition whistleblower tool — mailbox reference, if any (Phase 4c). */
export const ecCompetitionAdapter = new CompanionAdapter({
  entityId: 'ec-competition',
  receiptPatterns: [
    { pattern: /mailbox\s*(?:reference|id|#)[:#\s]*([A-Z0-9-]{4,})/i, type: 'manual' },
  ],
});
