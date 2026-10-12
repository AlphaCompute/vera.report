import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  CONFIDENTIAL_ADMIN_VISIBLE_FIELDS, CONFIDENTIAL_INTAKE_CONSENT_VERSION, INTAKE_CONSENT_VERSION, LEGAL_REVIEW_NOTICE,
} from '../../../src/utils/intakeConsent';
import { CONFIDENTIAL_REVIEW_NOTICE } from '../../../lib/confidential/config';

const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');

test('confidential consent is a distinct text version: summary and submission facts', () => {
  expect(CONFIDENTIAL_INTAKE_CONSENT_VERSION).not.toBe(INTAKE_CONSENT_VERSION);
  expect([...CONFIDENTIAL_ADMIN_VISIBLE_FIELDS]).toEqual(['caseId', 'summary', 'publishedAt', 'hasAttachments']);
  // The confidential notice states what admins can and cannot see; it never
  // grants the legacy administrator sharing authority.
  expect(CONFIDENTIAL_REVIEW_NOTICE).toMatch(/administrators cannot read it/i);
  expect(CONFIDENTIAL_REVIEW_NOTICE).toMatch(/short summary, submission time and whether you included attachments/i);
  expect(CONFIDENTIAL_REVIEW_NOTICE).not.toMatch(/category|region/i);
  expect(CONFIDENTIAL_REVIEW_NOTICE).not.toContain(LEGAL_REVIEW_NOTICE);
  expect(CONFIDENTIAL_REVIEW_NOTICE).not.toMatch(/allow VERA administrators to share/i);
});

test('the intake page shows the legacy notice only outside confidential mode', () => {
  const uses = [...report.matchAll(/LEGAL_REVIEW_NOTICE/g)].length;
  // One import plus exactly one use, as the non-confidential branch of the ternary.
  expect(uses).toBe(2);
  expect(report).toContain('confidential ? CONFIDENTIAL_REVIEW_NOTICE : LEGAL_REVIEW_NOTICE');
});

test('confidential submit never reaches the legacy intake or its consent fields', () => {
  const start = report.indexOf('const handleConfidentialConfirm = async () => {');
  const end = report.indexOf('// Confirm', start);
  expect(start).toBeGreaterThan(0);
  const body = report.slice(start, end);
  expect(body).not.toMatch(/\/api\/whistleblower\/submit|consentAgency|FormData|LEGAL_REVIEW_NOTICE/);
  // The legacy handler delegates before building any plaintext multipart request.
  const legacy = report.slice(report.indexOf('const handleConfirm = async () => {'));
  expect(legacy.indexOf('if (confidential) return handleConfidentialConfirm();'))
    .toBeLessThan(legacy.indexOf("fetch('/api/whistleblower/submit'"));
});

test('residual metadata (counts, bucketed sizes, timing) is disclosed before submit and before allowing access', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { CONFIDENTIAL_METADATA_NOTICE } = require('../../../lib/confidential/config');
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/how many encrypted parts/);
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/sizes, rounded up to fixed steps/);
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/how many files you attached/);
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/when you send or change them/);
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/which kinds of information/);
  expect(CONFIDENTIAL_METADATA_NOTICE).toMatch(/contents stay encrypted/);
  // Shown on the confidential review step, next to the release identity.
  const review = report.slice(report.indexOf('<ConfidentialReview '), report.indexOf('<ConfidentialReleaseIdentity identity={releaseIdentity}'));
  expect(review).toContain('{CONFIDENTIAL_METADATA_NOTICE}');
  // And on every access request card, before the reporter chooses what to share.
  const sharing = readFileSync(path.resolve(__dirname, '../../../components/vera/confidential/AccessSharing.tsx'), 'utf8');
  const card = sharing.slice(sharing.indexOf('export function AccessRequestCard'), sharing.indexOf('Choose what to share'));
  expect(card.length).toBeGreaterThan(0);
  expect(sharing.slice(sharing.indexOf('export function AccessRequestCard'))).toMatch(/can also see which kinds of information your report includes/);
  expect(sharing.slice(sharing.indexOf('export function AccessRequestCard'))).toMatch(/storage can see when you allow access and how many encrypted parts you share/);
});
