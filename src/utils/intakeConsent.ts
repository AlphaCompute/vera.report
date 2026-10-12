import type { ReportRecord } from '../services/reportPersistence';

export const LEGAL_REVIEW_NOTICE =
    'By submitting, you allow VERA administrators to share your report and evidence with trusted legal reviewers after review. Your report will not be sent automatically.';

/** Current intake snapshot: legal review is recorded separately and agency dispatch is never granted. */
export const INTAKE_CONSENT_VERSION = 'v4-legal-review';

/**
 * September 15 snapshots showed LEGAL_REVIEW_NOTICE but stored the election in
 * `agency`. Their `agency: true` means legal review only, never agency dispatch (#926).
 */
export const LEGACY_LEGAL_REVIEW_CONSENT_VERSION = 'v3-legal-review-default';

/** Consent versions whose intake actually asked the government-agency question. */
const AGENCY_QUESTION_VERSIONS: ReadonlySet<string> = new Set(['v1', 'v2']);

type StoredConsent = { agency?: unknown; legalReview?: unknown; textVersion?: unknown } | null | undefined;

/** Reporter agreed to submission to government agencies, in language that asked exactly that. */
export function agencyDispatchConsented(consent: StoredConsent): boolean {
    return consent?.agency === true && typeof consent.textVersion === 'string' &&
        AGENCY_QUESTION_VERSIONS.has(consent.textVersion);
}

/** Consent versions whose intake showed LEGAL_REVIEW_NOTICE. */
const LEGAL_REVIEW_VERSIONS: ReadonlySet<string> = new Set([LEGACY_LEGAL_REVIEW_CONSENT_VERSION, INTAKE_CONSENT_VERSION]);

/**
 * Reporter allowed admin-reviewed sharing with trusted legal reviewers (secure
 * packets). An explicit legalReview field counts only under the legal-review
 * notice versions; v1/v2 agency consent keeps the recipient flow it originally
 * gated (product decision on #962); unknown versions fail closed.
 */
export function legalReviewConsented(consent: StoredConsent): boolean {
    if (!consent || typeof consent.textVersion !== 'string') return false;
    if (LEGAL_REVIEW_VERSIONS.has(consent.textVersion)) {
        if (typeof consent.legalReview === 'boolean') return consent.legalReview;
        return consent.textVersion === LEGACY_LEGAL_REVIEW_CONSENT_VERSION && consent.agency === true;
    }
    return agencyDispatchConsented(consent);
}

/** September 15 MVP policy: legal review after admin review; no agency, Psst or press sharing. */
export function createIntakeConsent(legalReview: unknown = false): NonNullable<ReportRecord['consent']> {
    if (legalReview !== true && legalReview !== false && legalReview !== 'true' && legalReview !== 'false') {
        throw new Error('Invalid consentLegalReview. Must be true or false.');
    }
    return {
        psst: { granted: false },
        agency: false,
        legalReview: legalReview === true || legalReview === 'true',
        press: false,
        capturedAt: new Date(),
        textVersion: INTAKE_CONSENT_VERSION,
    };
}

/** Public listings contain the approved summary, opaque reference and optional signed submission facts. */
export const CONFIDENTIAL_INTAKE_CONSENT_VERSION = 'confidential-v4-submission-facts';
export const CONFIDENTIAL_ADMIN_VISIBLE_FIELDS = ['caseId', 'summary', 'publishedAt', 'hasAttachments'] as const;
