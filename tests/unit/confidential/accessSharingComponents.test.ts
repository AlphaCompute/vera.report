import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { AccessGrant } from '../../../enclave/src/confidential/authorization';
import type { LegalAccessRequest } from '../../../enclave/src/confidential/accessRequest';
import type { CurrentGrantee, VerifiedOrganization, VerifiedRequest } from '../../../lib/confidential/ownerCase';
import { organizationKeyUnconfirmedText, revokeBlockedText } from '../../../lib/confidential/ownerCase';
import { choiceSummary, defaultChoice, evidenceEntries, requestedParts } from '../../../lib/confidential/accessChoices';
import {
  AccessChooser, AccessExpiryNotices, AccessManager, AccessRequestCard, allowLabel,
} from '../../../components/vera/confidential/AccessSharing';
import { DirectSharing } from '../../../components/vera/confidential/DirectSharing';

/** Static render checks for the reporter's access UI: what each state shows,
 * with no network, keys or storage involved. */
const hex = (n: number) => n.toString(16).padStart(64, '0');
const DAY = 86_400_000, now = Date.UTC(2026, 8, 27);
const evidence = evidenceEntries({ objects: [
  { objectId: hex(2), scope: 'evidence', objectRevision: 1, keyEpoch: 1, ciphertextDigest: hex(91) },
  { objectId: hex(3), scope: 'evidence', objectRevision: 3, keyEpoch: 1, ciphertextDigest: hex(92) },
] });
const organization = { organizationId: hex(9), displayName: 'Counsel LLP', domain: 'counsel.example', approved: true,
  publicKey: {} } as unknown as VerifiedOrganization;
const request = (change: Partial<LegalAccessRequest> = {}): LegalAccessRequest => ({
  format: 'vera-legal-access-request/v2', caseId: hex(8), ownerFingerprint: 'a'.repeat(40), organizationId: hex(9),
  recipientKeyId: hex(10), requestId: hex(7), scopes: ['narrative', 'evidence', 'messages'], objectRevisionLimit: null,
  purpose: 'We represent whistleblowers in fraud cases.', issuedAt: now - DAY, expiresAt: now + 29 * DAY,
  details: { kind: 'new', conflictsChecked: true, feeBasis: 'contingency', responseTime: 'two-days',
    practiceAreas: ['Whistleblowing', 'Employment'], jurisdiction: 'New York', website: 'https://counsel.example/team' },
  ...change,
});
const verified = (change: Partial<LegalAccessRequest> = {}) =>
  ({ delivery: {}, request: request(change), organization }) as unknown as VerifiedRequest;
const grant = (change: Partial<AccessGrant>): AccessGrant => ({ kind: 'grant', caseId: hex(8), revision: 5, grantId: hex(7),
  organizationId: hex(9), recipientKeyId: hex(10), scopes: ['narrative', 'evidence', 'messages'], keyEpoch: 1,
  objectRevisionLimit: null, issuedAt: now - DAY, expiresAt: null, ...change });
const grantee = (grants: AccessGrant[], org: VerifiedOrganization | null = organization): CurrentGrantee =>
  ({ grantDigests: grants.map((_, index) => hex(100 + index)), grants, organizationId: hex(9), organization: org });
const ok = async () => true;
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, ' ');

describe('available law firms', () => {
  test('shows published contacts before sharing and retains firms already shared with', () => {
    const listed: VerifiedOrganization[] = [
      { ...organization, profile: { practiceAreas: ['whistleblower'], jurisdiction: 'England and Wales',
        website: 'https://counsel.example/', contacts: { email: 'intake@counsel.example', phone: '+44 20 7946 0000' } } },
      { ...organization, organizationId: hex(11), displayName: 'Second Counsel', domain: 'second.example', profile: null },
    ];
    const onVerify = jest.fn(), onShare = jest.fn();
    const html = renderToStaticMarkup(React.createElement(DirectSharing, { organizations: listed,
      existingOrganizationIds: [organization.organizationId], busy: false, published: true, revision: 4, onVerify, onShare }));
    const shown = text(html);
    expect(shown).toContain('Available law firms');
    expect(shown).toContain('Counsel LLP');
    expect(shown).toContain('intake@counsel.example');
    expect(shown).toContain('+44 20 7946 0000');
    expect(shown).toContain('Second Counsel');
    expect(shown).toContain('Previously submitted');
    expect(html).toContain(`href="#firm-access-${organization.organizationId}"`);
    expect((html.match(/>Select organization<\/button>/g) ?? []).length).toBe(1);
    expect(shown).toContain('This firm has not published email or phone details.');
    expect(html).not.toContain('<details');
    expect(onVerify).not.toHaveBeenCalled();
    expect(onShare).not.toHaveBeenCalled();
  });

  test('keeps the directory visible when no firm is available', () => {
    const html = renderToStaticMarkup(React.createElement(DirectSharing, { organizations: [], existingOrganizationIds: [],
      busy: false, published: true, revision: 4, onVerify: jest.fn(), onShare: jest.fn() }));
    expect(text(html)).toContain('No approved law firms are available right now.');
    expect(html).not.toContain('Share report');
  });
});

describe('access request card', () => {
  const card = (item: VerifiedRequest, existing: AccessGrant[] = []) => renderToStaticMarkup(React.createElement(AccessRequestCard, {
    item, evidence, fileNames: new Map(), currentRevision: 4, existing, busy: false, panel: 'panel', onAllow: ok, onDecline: ok,
     }));

  test('the key publication line is an actionable trust hint in plain words', () => {
    const published = text(card({ ...verified(), organization: { ...organization, witness: 'recorded' } } as VerifiedRequest));
    expect(published).toContain("VERA approved this organization and its email domain.");
    const unpublished = text(card({ ...verified(), organization: { ...organization, witness: 'unrecorded' } } as unknown as VerifiedRequest));
    expect(unpublished).toContain('VERA approved this organization and its email domain.');
    for (const shown of [published, unpublished]) expect(shown).not.toMatch(/public key record|case keys?|backend release/i);
  });

  test('a request under a changed key says so and asks the reporter to confirm it independently', () => {
    const shown = text(renderToStaticMarkup(React.createElement(AccessRequestCard, {
      item: verified(), evidence, fileNames: new Map(), currentRevision: 4, existing: [], replacedKey: true, busy: false, panel: 'panel',
      onAllow: ok, onDecline: ok })));
    expect(shown).toContain('The key of Counsel LLP has changed since you allowed access.');
    expect(shown).toContain('The new key has received nothing you shared, and receives nothing unless you allow this request.');
    expect(shown).toContain('confirm with the organization, through a contact you already trust, that it replaced its key');
  });

  test('shows the organization profile and structured request, and nothing is chosen until the reporter opens the chooser', () => {
    const html = card(verified());
    const shown = text(html);
    expect(shown).toContain('Counsel LLP requests access');
    expect(shown).toContain('Website: counsel.example');
    // Key approval is rechecked when allowing access.
    expect(shown).not.toContain('Key confirmed');
    expect(shown).toContain('Your device confirms the approved organization key before sharing');
    expect(shown).toContain('Whistleblowing, Employment');
    expect(shown).toContain('New York');
    expect(shown).toContain('https://counsel.example/team');
    expect(shown).toContain('Checked: they say they have no conflict');
    expect(shown).toContain('Contingency (paid only if the case succeeds)');
    expect(shown).toContain('Within 2 days');
    expect(shown).toContain('We represent whistleblowers in fraud cases.');
    expect(shown).toContain('Choose what to share');
    expect(html).not.toContain('type="radio"');
  });

  // Replaces the retired AccessRequestPanel checks: the live card must keep a
  // contact- or identity-only request answerable (decline) without ever
  // making those details part of Allow, and without preselecting anything.
  test.each(['contact', 'identity'] as const)('a %s-only request can be declined and never shares it through Allow', scope => {
    const html = card(verified({ scopes: [scope] }));
    const shown = text(html);
    expect(shown).toContain('This request asks only for your contact or identity details. Those are never part of Allow');
    expect(shown).toContain('Decline');
    expect(html).not.toContain('checked=""');
    const offered = text(renderToStaticMarkup(React.createElement(AccessChooser, { id: 'c', asks: requestedParts([scope]), evidence,
      fileNames: new Map(), choice: defaultChoice(request({ scopes: [scope] }), evidence), onChange: () => undefined })));
    expect(offered).not.toMatch(/contact details|identity/i);
    expect(offered).not.toContain('Share my report');
  });

  test('the retired AccessRequestPanel (fixed 30 days, firm wording, contact inside Allow) stays deleted', () => {
    const { existsSync, readdirSync, readFileSync } = jest.requireActual<typeof import('node:fs')>('node:fs');
    const { join } = jest.requireActual<typeof import('node:path')>('node:path');
    const dir = join(__dirname, '../../../components/vera/confidential');
    expect(existsSync(join(dir, 'AccessRequestPanel.tsx'))).toBe(false);
    for (const file of readdirSync(dir)) {
      const source = readFileSync(join(dir, file), 'utf8');
      expect(source).not.toContain('AccessRequestPanel');
      expect(source).not.toMatch(/Choose what to share for 30 days/);
    }
  });

  test('once the signed domain profile is read, the copy carried in the request is not shown beside it', () => {
    const signed = { ...organization, profile: { practiceAreas: ['securities'], jurisdiction: 'Delaware',
      website: 'https://counsel.example/about' } } as unknown as VerifiedOrganization;
    const shown = text(card({ delivery: {}, request: request(), organization: signed } as unknown as VerifiedRequest));
    expect(shown).toContain('Securities and financial fraud');
    expect(shown).toContain('Delaware');
    expect(shown).not.toContain('Whistleblowing, Employment');
    expect(shown).not.toContain('New York');
    expect(shown).not.toContain('https://counsel.example/team');
    expect(shown.match(/Practice areas/g)).toHaveLength(1);
    expect(shown.match(/Jurisdiction/g)).toHaveLength(1);
  });

  test('a website off the verified domain is never shown, and a v1 request shows no structured fields', () => {
    const offDomain = request();
    offDomain.details = { ...offDomain.details!, website: 'https://counsel-example.net/' };
    expect(text(card(verified({ details: offDomain.details })))).not.toContain('counsel-example.net');
    const legacy = text(card(verified({ format: 'vera-legal-access-request/v1', details: null })));
    expect(legacy).not.toMatch(/Practice areas|Fees|Conflicts of interest/);
    expect(legacy).toContain('Counsel LLP requests access');
  });

  test('a renewal request (or a repeat request from an organization with access) says so', () => {
    const renewal = request();
    expect(text(card(verified({ details: { ...renewal.details!, kind: 'renewal' } })))).toContain('Counsel LLP asks to renew access');
    expect(text(card(verified(), [grant({})]))).toContain('Counsel LLP asks to renew access');
    // A contact-only grant is not report access, so this is still a first request.
    expect(text(card(verified(), [grant({ scopes: ['contact'] })]))).toContain('Counsel LLP requests access');
  });
});

describe('allow chooser', () => {
  const chooser = (choice = defaultChoice(request(), evidence), scopes = request().scopes, names = new Map<string, string>()) =>
    renderToStaticMarkup(React.createElement(AccessChooser, { id: 'c', asks: requestedParts(scopes), evidence, fileNames: names,
      choice, onChange: () => undefined }));

  test('offers report, evidence (all, some, none), future files and duration, defaulting to until revoked', () => {
    const html = chooser();
    const shown = text(html);
    for (const label of ['Share my report', "Don't share it", 'All files (2)', 'Only some files', 'No files',
      'Also share files I add later', 'Until I revoke it', '30 days', '90 days', '1 year']) expect(shown).toContain(label);
    expect(html).toMatch(/<input type="radio" class="mt-1" name="c-duration" checked=""[^>]*\/><span>Until I revoke it/);
    expect(html).not.toContain('aria-label="Files to share"');
  });

  test('"only some files" lists each file with a checkbox, by name when known', () => {
    const choice = { ...defaultChoice(request(), evidence), evidence: 'some' as const, selected: [hex(3)] };
    const html = chooser(choice, request().scopes, new Map([[hex(3), 'memo.pdf']]));
    expect(html).toContain('aria-label="Files to share"');
    expect(text(html)).toContain('File 1 (sent with your report)');
    expect(text(html)).toContain('memo.pdf (added later)');
    expect(text(html)).toContain('File names stay encrypted');
    expect(html.match(/type="checkbox"/g)).toHaveLength(3); // two files + future files
  });

  test('only what the organization asked for is offered', () => {
    const html = text(chooser(defaultChoice(request({ scopes: ['narrative'] }), evidence), ['narrative']));
    expect(html).toContain('Share my report');
    expect(html).not.toContain('Evidence files');
  });

  test('the summary restates the choice in one sentence', () => {
    const asks = requestedParts(request().scopes);
    expect(choiceSummary(defaultChoice(request(), evidence), asks, evidence, 'Counsel LLP'))
      .toBe('Counsel LLP will be able to read your report, all your evidence files, until you revoke access.');
    expect(choiceSummary({ report: false, evidence: 'some', selected: [hex(2)], future: false, duration: '30-days' }, asks, evidence, 'Counsel LLP'))
      .toBe('Counsel LLP will be able to read 1 evidence file, for 30 days.');
    expect(choiceSummary({ report: false, evidence: 'none', selected: [], future: false, duration: '30-days' }, asks, evidence, 'Counsel LLP'))
      .toBe('Nothing is selected yet.');
  });
});

describe('who has access', () => {
  const manager = (grantees: CurrentGrantee[], contactLabel: string | null = 'contact details',
    extra: Partial<React.ComponentProps<typeof AccessManager>> = {}) =>
    renderToStaticMarkup(React.createElement(AccessManager, { grantees, evidence, contactLabel, busy: false, now,
      currentRevision: 4,  onChangeAccess: ok,
      onRenew: ok, onShareContact: ok, onStopContact: ok, onRevoke: ok, ...extra }));

  test('lists what each organization can read, until when, with renew, contact sharing and revoke', () => {
    const shown = text(manager([grantee([grant({ excludedObjectIds: [hex(3)], objectRevisionLimit: 2 })])]));
    expect(shown).toContain('Can read: Your report, 1 of 2 evidence files.');
    expect(shown).toContain('Until you revoke it');
    expect(shown).toContain('Renew access');
    expect(shown).toContain('Share my contact details with Counsel LLP');
    expect(shown).toContain('Not shared. Counsel LLP cannot see how to reach you.');
    expect(shown).toContain('Revoke access');
  });

  test('files added after an Allow can be shared with an organization that already has access', () => {
    // Allowed when the report had no files, without later files: both files are unshared now.
    const shown = text(manager([grantee([grant({ scopes: ['narrative', 'messages'], objectRevisionLimit: 0 })])]));
    expect(shown).toContain('Some of your files are not shared with Counsel LLP. Use "Change what they can read"');
    expect(shown).toContain('Change what they can read');
    expect(shown).toContain('including files you added after you allowed access');
    expect(shown).toContain('To share more, use "Change what they can read"');
    // Everything shared: no nudge, but the control is still there to narrow access.
    const all = text(manager([grantee([grant({})])]));
    expect(all).not.toContain('Some of your files are not shared');
    expect(all).toContain('Change what they can read');
    // Ended access is renewed first.
    expect(text(manager([grantee([grant({ expiresAt: now - DAY })])]))).not.toContain('Share your report or files with');
  });

  test('a blocked revoke names the organization that blocked it and offers the ways out', () => {
    const bravo = { ...organization, organizationId: hex(12), displayName: 'Bravo Law', domain: 'bravo.example' } as VerifiedOrganization;
    const rows = [grantee([grant({})]), { ...grantee([grant({ organizationId: hex(12) })], bravo), organizationId: hex(12) }];
    const failed = text(manager(rows, null, { revokeProblem: { organizationIds: [hex(9)],
      blockers: [{ organizationId: hex(12), name: 'Bravo Law', domain: 'bravo.example', reason: 'failed' }] } }));
    expect(failed).toContain('Access for Counsel LLP was not revoked');
    expect(failed).toContain('current approved keys could not be confirmed');
    expect(failed).toContain('Revoke Counsel LLP and Bravo Law together');
    expect(failed).toContain('Try again');
    expect(failed).not.toContain('Nothing was shared');
    const notAllowed = text(manager(rows, null, { revokeProblem: { organizationIds: [hex(9)],
      blockers: [{ organizationId: hex(12), name: 'Bravo Law', domain: 'bravo.example', reason: 'not-allowed' }] } }));
    expect(notAllowed).toContain('current approved keys could not be confirmed');
    expect(notAllowed).not.toContain('Allow website checks');
    const replaced = text(manager([grantee([grant({})]), { ...grantee([grant({ organizationId: hex(12) })], null), organizationId: hex(12) }],
      null, { roster: [{ organizationId: hex(12), displayName: 'Bravo Law' }], revokeProblem: { organizationIds: [hex(9)],
        blockers: [{ organizationId: hex(12), name: 'Bravo Law', domain: null, reason: 'replaced' }] } }));
    expect(replaced).toContain('Bravo Law replaced its key, so it cannot receive the new key');
    expect(replaced).not.toContain('Allow website checks and revoke');
    expect(replaced).toContain('Revoke Counsel LLP and Bravo Law together');
  });

  test('shared contact details can be stopped; no contact option when the report has none', () => {
    const shared = grantee([grant({ expiresAt: now + 40 * DAY }), grant({ grantId: hex(20), scopes: ['contact'], expiresAt: now + 40 * DAY })]);
    const shown = text(manager([shared]));
    expect(shown).toContain('Your contact details');
    expect(shown).toContain('You are sharing your contact details with Counsel LLP.');
    expect(shown).toContain('Stop sharing contact details');
    expect(text(manager([grantee([grant({})])], null))).not.toMatch(/contact details with/);
  });

  test('an organization no longer confirmed by its website can only be revoked', () => {
    const shown = text(manager([grantee([grant({})], null)]));
    expect(shown).toContain('An organization that can no longer be verified');
    expect(shown).toContain('nothing new can be shared with it');
    expect(shown).not.toContain('Renew access');
    expect(shown).not.toContain('Share my contact details');
    expect(shown).toContain('Revoke access');
  });

  test('end dates are shown and warned about 14 days ahead; ended access is called out', () => {
    expect(text(manager([grantee([grant({ expiresAt: now + 10 * DAY })])]))).toContain('(10 days left)');
    const notices = (grants: AccessGrant[]) => renderToStaticMarkup(React.createElement(AccessExpiryNotices, { grantees: [grantee(grants)], now }));
    expect(notices([grant({ expiresAt: now + 60 * DAY })])).toBe('');
    expect(notices([grant({ expiresAt: null })])).toBe('');
    expect(text(notices([grant({ expiresAt: now + 10 * DAY })]))).toMatch(/Access for Counsel LLP ends on Oct \d+, 2026\. Renew it/);
    expect(text(notices([grant({ expiresAt: now - DAY })]))).toMatch(/Access for Counsel LLP ended on Sep \d+, 2026\./);
    // Contact sharing alone never produces an access notice.
    expect(notices([grant({ scopes: ['contact'], expiresAt: now + DAY })])).toBe('');
  });
});

describe('blocked revoke wording', () => {
  test('a replaced key asks to revoke that organization too; a site problem names the site and offers both ways out', () => {
    const replaced = revokeBlockedText(['Counsel LLP'], [{ organizationId: hex(12), name: 'Bravo Law', domain: null, reason: 'replaced' }]);
    expect(replaced).toBe('Access for Counsel LLP was not revoked. Nothing changed. Revoking gives a new key to every legal organization ' +
      'that keeps access, so it can keep reading. Bravo Law replaced its key, so this device cannot give it the new key. ' +
      'Revoke Bravo Law as well, in the same step, or first.');
    const mixed = revokeBlockedText(['Counsel LLP'], [
      { organizationId: hex(12), name: 'Bravo Law', domain: 'bravo.example', reason: 'not-allowed' },
      { organizationId: hex(13), name: 'Charlie PC', domain: 'charlie.example', reason: 'failed' }]);
    expect(mixed).toContain('could not confirm the approved key of Bravo Law and Charlie PC');
    expect(mixed).toContain('Or revoke Bravo Law and Charlie PC at the same time; then no check is needed.');
    expect(mixed).not.toMatch(/Nothing was shared|To share with/);
  });
});

describe('key check wording names the action that did not happen', () => {
  test('each action says what did not happen, and another organization is named with why it is checked', () => {
    const contact = organizationKeyUnconfirmedText('bravo.example', 'not-allowed', { operation: 'contact', target: 'Counsel LLP' }, 'Bravo Law');
    expect(contact).toContain("Your contact details were not shared with Counsel LLP.");
    expect(contact).toContain("could not confirm the approved key of Bravo Law");
    expect(contact).not.toContain('To share with');
    const renew = organizationKeyUnconfirmedText('counsel.example', 'failed', { operation: 'renew', target: 'Counsel LLP' }, 'Counsel LLP');
    expect(renew).toMatch(/^Access for Counsel LLP was not renewed\. Nothing changed\. This device could not confirm the approved key of Counsel LLP/);
    expect(renew).not.toContain('Nothing was shared');
    expect(renew).not.toContain('which keeps access');
    expect(organizationKeyUnconfirmedText('counsel.example', 'failed', { operation: 'message', target: 'Counsel LLP' }, 'Counsel LLP'))
      .toMatch(/^Your message to Counsel LLP was not sent\./);
    expect(organizationKeyUnconfirmedText('counsel.example', 'not-allowed', { operation: 'allow', target: 'Counsel LLP' }, 'Counsel LLP'))
      .toMatch(/^Access for Counsel LLP was not allowed\. Nothing was shared\./);
    expect(organizationKeyUnconfirmedText('counsel.example', 'failed', { operation: 'change', target: 'Counsel LLP' }, 'Counsel LLP'))
      .toMatch(/^What Counsel LLP can read was not changed\./);
  });

  test('renewing without website checks allowed says so on the button that gives the permission', () => {
    const render = (websiteChecksAllowed: boolean) => text(renderToStaticMarkup(React.createElement(AccessManager, {
      grantees: [grantee([grant({})])], evidence, contactLabel: null, busy: false, now, currentRevision: 4,
       onChangeAccess: ok, onRenew: ok, onShareContact: ok,
      onStopContact: ok, onRevoke: ok })));
    const blocked = render(false);
    expect(blocked).toContain('Renew access');
    expect(blocked).not.toContain('website checks');
    const allowed = render(true);
    expect(allowed).not.toContain('Allow website checks and renew access');
    expect(allowed).toContain('Renew access');
  });
});

describe('sharing uses approval without a website-permission step', () => {
  test('sharing labels name only the participant decision', () => {
    expect(allowLabel(false)).toBe('Allow access');
    expect(allowLabel(true)).toBe('Allow and replace current access');
  });


  test('a failed Allow or Decline is shown on the card as an alert', () => {
    const render = (actionError: string | null) => renderToStaticMarkup(React.createElement(AccessRequestCard, {
      item: verified(), evidence, fileNames: new Map(), currentRevision: 4, existing: [], busy: false, panel: 'panel',
      onAllow: ok, onDecline: ok,  actionError }));
    expect(render('Access for Counsel LLP was not allowed. Nothing was shared.'))
      .toMatch(/role="alert"[^>]*>Access for Counsel LLP was not allowed\. Nothing was shared\./);
    expect(render(null)).not.toContain('role="alert"');
  });


});
