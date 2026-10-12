import type { AccessGrant } from '../../../enclave/src/confidential/authorization';
import {
  AccessChoiceError, changeChoice, changeDecisionFromChoice, changeParts, choiceSummary, decisionFromChoice, defaultChoice,
  describeAccess, evidenceEntries, expiresAtFor, expiryState, expiryText, fileLabel, requestedParts, trustedWebsite,
  unsharedFiles, validateRequestForm, requestProfileFields,
} from '../../../lib/confidential/accessChoices';
import { parseRequestDetails } from '../../../enclave/src/confidential/accessRequest';
import { FIRM_JURISDICTION_MAX, FIRM_PRACTICE_AREAS } from '../../../enclave/src/confidential/firmProfile';
import type { FirmPracticeArea } from '../../../enclave/src/confidential/firmProfile';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const DAY = 86_400_000, now = Date.UTC(2026, 8, 27);
const manifest = { objects: [
  { objectId: hex(1), scope: 'narrative' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(90) },
  { objectId: hex(2), scope: 'evidence' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(91) },
  { objectId: hex(3), scope: 'evidence' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(92) },
  { objectId: hex(4), scope: 'contact' as const, objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(93) },
  { objectId: hex(5), scope: 'evidence' as const, objectRevision: 4, keyEpoch: 1, ciphertextDigest: hex(94) },
] };
const evidence = evidenceEntries(manifest);
const request = { requestId: hex(7), scopes: ['narrative', 'evidence', 'messages'] as AccessGrant['scopes'], objectRevisionLimit: null };
const grant = (change: Partial<AccessGrant>): AccessGrant => ({ kind: 'grant', caseId: hex(8), revision: 5, grantId: hex(7),
  organizationId: hex(9), recipientKeyId: hex(10), scopes: ['narrative', 'evidence', 'messages'], keyEpoch: 1,
  objectRevisionLimit: null, issuedAt: now - DAY, expiresAt: null, ...change });

describe('allow chooser', () => {
  test('evidence files are numbered in upload order and named only when known on this device', () => {
    expect(evidence.map(item => [item.ordinal, item.objectRevision])).toEqual([[1, 1], [2, 1], [3, 4]]);
    expect(fileLabel(evidence[0])).toBe('File 1 (sent with your report)');
    expect(fileLabel(evidence[2], new Map([[hex(5), 'memo.pdf']]))).toBe('memo.pdf (added later)');
  });

  test('default: what was asked for, all current files, no future files, until revoked', () => {
    const choice = defaultChoice(request, evidence);
    expect(choice).toEqual({ report: true, evidence: 'all', selected: [hex(2), hex(3), hex(5)], future: false, duration: 'until-revoked' });
    // Files added later need an explicit choice (architecture: default to current material).
    expect(decisionFromChoice(choice, request, evidence, 6, now)).toEqual({ grantId: hex(7),
      scopes: ['narrative', 'evidence'], objectRevisionLimit: 6, expiresAt: null });
    expect(decisionFromChoice({ ...choice, future: true }, request, evidence, 6, now)).toMatchObject({ objectRevisionLimit: null });
  });

  test('only some files, no future files, 90 days', () => {
    const decision = decisionFromChoice({ report: false, evidence: 'some', selected: [hex(3)], future: false, duration: '90-days' },
      request, evidence, 6, now);
    expect(decision).toEqual({ grantId: hex(7), scopes: ['evidence'], objectRevisionLimit: 6,
      expiresAt: now + 90 * DAY, excludedObjectIds: [hex(2), hex(5)] });
  });

  test('a request revision limit is never widened', () => {
    const limited = { ...request, objectRevisionLimit: 2 };
    expect(decisionFromChoice({ ...defaultChoice(limited, evidence), future: false }, limited, evidence, 6, now).objectRevisionLimit).toBe(2);
    expect(decisionFromChoice(defaultChoice(limited, evidence), limited, evidence, 6, now).objectRevisionLimit).toBe(2);
  });

  test('messages alone or nothing selected is refused with a plain message', () => {
    expect(() => decisionFromChoice({ report: false, evidence: 'none', selected: [], future: true, duration: 'until-revoked' },
      request, evidence, 6, now)).toThrow(AccessChoiceError);
    expect(() => decisionFromChoice({ report: true, evidence: 'some', selected: [], future: true, duration: 'until-revoked' },
      request, evidence, 6, now)).toThrow('Choose at least one file');
    expect(() => decisionFromChoice({ ...defaultChoice(request, evidence), duration: 'forever' as never }, request, evidence, 6, now))
      .toThrow('how long');
  });

  test('scopes the organization did not ask for are never granted, and contact never is', () => {
    const narrow = { ...request, scopes: ['narrative'] as AccessGrant['scopes'] };
    expect(decisionFromChoice(defaultChoice(narrow, evidence), narrow, evidence, 6, now).scopes).toEqual(['narrative']);
    const withContact = { ...request, scopes: ['narrative', 'contact', 'identity'] as AccessGrant['scopes'] };
    expect(decisionFromChoice(defaultChoice(withContact, evidence), withContact, evidence, 6, now).scopes).toEqual(['narrative']);
  });

  test('a renewal starts from the organization current choices', () => {
    const current = [grant({ excludedObjectIds: [hex(3)], objectRevisionLimit: 3 }), grant({ grantId: hex(11), scopes: ['contact'] })];
    // File 3 (hex 5) was added after the access (revision 4 > limit 3): not pre-selected.
    expect(defaultChoice(request, evidence, current)).toEqual({ report: true, evidence: 'some', selected: [hex(2)],
      future: false, duration: 'until-revoked' });
  });

  test('a renewal never pre-selects files added after the current access (regression)', () => {
    // Current material only at revision 3: the file added at revision 4 was deliberately not shared.
    const currentOnly = [grant({ objectRevisionLimit: 3 })];
    const choice = defaultChoice(request, evidence, currentOnly);
    expect(choice).toEqual({ report: true, evidence: 'some', selected: [hex(2), hex(3)], future: false, duration: 'until-revoked' });
    expect(decisionFromChoice(choice, request, evidence, 6, now).excludedObjectIds).toEqual([hex(5)]);
    // Several grants: only files some grant covers; 'all' only when every file is covered.
    const split = [grant({ objectRevisionLimit: 1, excludedObjectIds: [hex(3)] }), grant({ grantId: hex(12), objectRevisionLimit: 3,
      excludedObjectIds: [hex(2)] })];
    expect(defaultChoice(request, evidence, split)).toMatchObject({ evidence: 'some', selected: [hex(2), hex(3)], future: false });
    expect(defaultChoice(request, evidence, [...split, grant({ grantId: hex(13), objectRevisionLimit: 4, excludedObjectIds: [hex(2)] })]))
      .toMatchObject({ evidence: 'all', selected: [hex(2), hex(3), hex(5)], future: false });
    // A grant without evidence scope covers no files.
    expect(defaultChoice(request, evidence, [grant({ scopes: ['narrative', 'messages'] })]))
      .toMatchObject({ evidence: 'none', selected: [], future: false });
  });

  test('with no files yet, "share files I add later" alone shares evidence', () => {
    const decision = decisionFromChoice({ report: true, evidence: 'none', selected: [], future: true, duration: 'until-revoked' },
      request, [], 2, now);
    expect(decision).toMatchObject({ scopes: ['narrative', 'evidence'], objectRevisionLimit: null });
    expect(choiceSummary({ report: true, evidence: 'none', selected: [], future: true, duration: 'until-revoked' },
      requestedParts(request.scopes), [], 'Counsel LLP')).toBe(
      'Counsel LLP will be able to read your report, files you add later, until you revoke access.');
    // Without it, no evidence scope at all.
    expect(decisionFromChoice({ report: true, evidence: 'none', selected: [], future: false, duration: 'until-revoked' },
      request, [], 2, now).scopes).toEqual(['narrative']);
  });
});

describe('change what an organization can read', () => {
  // Allowed with no files and no later files; two files were added since (revisions 1 and 4 here).
  const reportOnly = [grant({ scopes: ['narrative', 'messages'], objectRevisionLimit: 1, expiresAt: now + 30 * DAY }),
    grant({ grantId: hex(11), scopes: ['contact'], expiresAt: now + 30 * DAY })];

  test('starts from exactly what they can read now, and counts files they cannot open', () => {
    expect(changeChoice(reportOnly, evidence)).toEqual({ report: true, evidence: 'none', selected: [], future: false,
      duration: 'until-revoked' });
    expect(unsharedFiles(reportOnly, evidence, now)).toBe(3);
    const limited = [grant({ objectRevisionLimit: 1 })];
    expect(changeChoice(limited, evidence)).toMatchObject({ evidence: 'some', selected: [hex(2), hex(3)] });
    expect(unsharedFiles(limited, evidence, now)).toBe(1);
    expect(unsharedFiles([grant({})], evidence, now)).toBe(0);
  });

  test('sharing later files keeps the end date and replaces with a fresh grant ID', () => {
    const decision = changeDecisionFromChoice({ ...changeChoice(reportOnly, evidence), evidence: 'all' }, reportOnly, evidence, 6, now, hex(40));
    expect(decision).toEqual({ grantId: hex(40), scopes: ['narrative', 'evidence'], objectRevisionLimit: 6,
      expiresAt: now + 30 * DAY });
    const random = changeDecisionFromChoice({ ...changeChoice(reportOnly, evidence), evidence: 'all' }, reportOnly, evidence, 6, now);
    expect(random.grantId).toMatch(/^[a-f0-9]{64}$/);
    expect(random.grantId).not.toBe(reportOnly[0].grantId);
  });

  test('never adds messages or contact, and refuses ended access or an empty choice', () => {
    const noMessages = [grant({ scopes: ['narrative'], expiresAt: null })];
    expect(changeParts(noMessages)).toEqual({ report: true, evidence: true, messages: false });
    expect(changeDecisionFromChoice({ ...changeChoice(noMessages, evidence), evidence: 'all' }, noMessages, evidence, 6, now, hex(40)))
      .toMatchObject({ scopes: ['narrative', 'evidence'], expiresAt: null });
    expect(() => changeDecisionFromChoice(changeChoice(reportOnly, evidence), [grant({ expiresAt: now - 1 })], evidence, 6, now))
      .toThrow('Renew it first');
    expect(() => changeDecisionFromChoice({ report: false, evidence: 'none', selected: [], future: false, duration: 'until-revoked' },
      reportOnly, evidence, 6, now)).toThrow(AccessChoiceError);
  });
});

describe('access summaries and expiry', () => {
  test('describes what an organization can read', () => {
    const current = [grant({ excludedObjectIds: [hex(3)] }), grant({ grantId: hex(11), scopes: ['contact'] })];
    expect(describeAccess(current, evidence, now)).toEqual({ items: ['Your report', '2 of 3 evidence files, and files you add later',
      'Your contact details'], expiresAt: null, active: true, contactShared: true });
    expect(describeAccess([grant({ scopes: ['evidence'], objectRevisionLimit: 1, expiresAt: now - 1 })], evidence, now))
      .toMatchObject({ items: ['2 of 3 evidence files'], active: false, expiresAt: now - 1 });
  });

  test('expiry states and wording', () => {
    expect(expiryState(null, now)).toEqual({ state: 'open-ended' });
    expect(expiryState(now + 20 * DAY, now)).toMatchObject({ state: 'active', daysLeft: 20 });
    expect(expiryState(now + 14 * DAY, now)).toMatchObject({ state: 'ending-soon', daysLeft: 14 });
    expect(expiryState(now, now)).toMatchObject({ state: 'ended' });
    expect(expiryText(null, now)).toBe('Until you revoke it');
    expect(expiryText(now + DAY, now)).toMatch(/\(1 day left\)$/);
    expect(expiresAtFor('until-revoked', now)).toBeNull();
    expect(expiresAtFor('1-year', now)).toBe(now + 365 * DAY);
  });

  test('a website is shown only on the verified domain', () => {
    expect(trustedWebsite('https://counsel.example/team', 'counsel.example')).toBe('https://counsel.example/team');
    expect(trustedWebsite('https://www.counsel.example/', 'counsel.example')).toBe('https://www.counsel.example/');
    expect(trustedWebsite('https://counsel.example.evil.test/', 'counsel.example')).toBeNull();
    expect(trustedWebsite('https://evilcounsel.example/', 'counsel.example')).toBeNull();
    expect(trustedWebsite(null, 'counsel.example')).toBeNull();
  });
});

describe('request form validation', () => {
  const valid = { purpose: ' We can help. ', conflicts: 'yes' as const, feeBasis: 'hourly', responseTime: 'one-week' };
  const signed = { practiceAreas: ['whistleblower', 'employment'] as FirmPracticeArea[], jurisdiction: 'Ontario',
    website: 'https://www.counsel.example/team' };
  test('the profile in the request is the signed domain profile, never typed into the form', () => {
    expect(validateRequestForm(valid, signed)).toEqual({ errors: {},
      details: { kind: 'new', conflictsChecked: true, feeBasis: 'hourly', responseTime: 'one-week',
        practiceAreas: ['Whistleblower representation', 'Employment and retaliation'], jurisdiction: 'Ontario',
        website: 'https://www.counsel.example/team' } });
    // Free-text profile fields are not accepted, even if a caller passes them.
    const smuggled = { ...valid, practiceAreas: 'Anything', jurisdiction: 'Elsewhere', website: 'https://other.example/' };
    expect(validateRequestForm(smuggled, signed).details).toMatchObject(requestProfileFields(signed));
  });
  test('without a signed profile the request carries no profile, and still parses as a signed request', () => {
    const { details } = validateRequestForm(valid, null);
    expect(details).toMatchObject({ practiceAreas: [], jurisdiction: '', website: null });
    expect(parseRequestDetails(details)).toEqual(details);
    expect(parseRequestDetails(validateRequestForm(valid, signed).details)).toEqual(validateRequestForm(valid, signed).details);
  });
  test('every coded practice area fits the signed request limits', () => {
    const all = Object.keys(FIRM_PRACTICE_AREAS) as FirmPracticeArea[];
    for (let index = 0; index < all.length; index += 6) {
      const profile = { ...signed, practiceAreas: all.slice(index, index + 6), jurisdiction: 'x'.repeat(FIRM_JURISDICTION_MAX) };
      expect(() => parseRequestDetails(validateRequestForm(valid, profile).details)).not.toThrow();
    }
  });
  test('each field reports its own problem', () => {
    const result = validateRequestForm({ purpose: ' ', conflicts: '', feeBasis: 'free', responseTime: '' }, signed);
    expect(Object.keys(result.errors).sort()).toEqual(['conflicts', 'feeBasis', 'purpose', 'responseTime']);
    expect(result.details).toBeUndefined();
  });
});
