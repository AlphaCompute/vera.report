/**
 * Consent scope (#926): the legal-review notice must never authorize agency
 * dispatch, and agency consent only counts where the agency question was asked.
 */

import { channelConsented } from '../../../../src/services/dissemination/consentScope';
import { SECURE_LINK_ENTITY_ID } from '../../../../src/services/dissemination/secureLink';
import { disseminationService } from '../../../../src/services/dissemination/disseminationService';
import {
  agencyDispatchConsented,
  createIntakeConsent,
  legalReviewConsented,
} from '../../../../src/utils/intakeConsent';
import type { ReportRecord } from '../../../../src/services/reportPersistence';

const capturedAt = new Date('2026-09-20T00:00:00Z');
const legacyLegalReview = { psst: { granted: false }, agency: true, press: false, capturedAt, textVersion: 'v3-legal-review-default' };
const askedAgency = { psst: { granted: false }, agency: true, press: false, capturedAt, textVersion: 'v2' };

describe('consent scope (#926)', () => {
  it('reads legacy v3 agency consent as legal review only', () => {
    expect(agencyDispatchConsented(legacyLegalReview)).toBe(false);
    expect(legalReviewConsented(legacyLegalReview)).toBe(true);
    expect(channelConsented(legacyLegalReview, 'eeoc')).toBe(false);
    expect(channelConsented(legacyLegalReview, 'sec-tcr')).toBe(false);
    expect(channelConsented(legacyLegalReview, SECURE_LINK_ENTITY_ID)).toBe(true);
  });

  it('keeps agency consent captured by the agency question, including the recipient flow it gated', () => {
    for (const textVersion of ['v1', 'v2']) {
      expect(channelConsented({ ...askedAgency, textVersion }, 'eeoc')).toBe(true);
      expect(legalReviewConsented({ ...askedAgency, textVersion })).toBe(true);
      expect(legalReviewConsented({ ...askedAgency, textVersion, agency: false })).toBe(false);
    }
  });

  it('honours an explicit legalReview field only under legal-review consent versions', () => {
    expect(legalReviewConsented({ legalReview: true, textVersion: 'v9' })).toBe(false);
    expect(legalReviewConsented({ legalReview: true, textVersion: 'v2', agency: false })).toBe(false);
    expect(legalReviewConsented({ legalReview: false, textVersion: 'v3-legal-review-default', agency: true })).toBe(false);
  });

  it('never grants agency dispatch from new intake, whatever the election', () => {
    for (const election of [true, false]) {
      const consent = createIntakeConsent(election);
      expect(consent).toMatchObject({ agency: false, legalReview: election, textVersion: 'v4-legal-review' });
      expect(channelConsented(consent, 'eeoc')).toBe(false);
      expect(channelConsented(consent, SECURE_LINK_ENTITY_ID)).toBe(election);
    }
    expect(createIntakeConsent()).toMatchObject({ legalReview: false });
  });

  it.each([
    ['unknown version', { ...askedAgency, textVersion: 'v9' }],
    ['missing version', { agency: true }],
    ['v4 without an election', { agency: true, textVersion: 'v4-legal-review' }],
    ['no consent', null],
  ])('fails closed for %s', (_label, consent) => {
    expect(agencyDispatchConsented(consent)).toBe(false);
    expect(legalReviewConsented(consent)).toBe(false);
    expect(channelConsented(consent, 'eeoc')).toBe(false);
  });

  it('keeps Psst and press on their own opt-ins', () => {
    const consent = { ...askedAgency, psst: { granted: false }, press: false };
    expect(channelConsented(consent, 'psst-safe')).toBe(false);
    expect(channelConsented(consent, 'securedrop')).toBe(false);
    expect(channelConsented({ ...legacyLegalReview, press: true }, 'securedrop')).toBe(true);
  });

  it('snapshots effective consent, which the gates read the same way', () => {
    const snapshot = disseminationService.consentFromReport({ consent: legacyLegalReview } as ReportRecord)!;
    expect(snapshot).toMatchObject({ agency: false, legalReview: true, textVersion: 'v3-legal-review-default' });
    expect(channelConsented(snapshot, 'eeoc')).toBe(false);
    expect(channelConsented(snapshot, SECURE_LINK_ENTITY_ID)).toBe(true);
  });
});
