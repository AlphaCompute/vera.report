import React from 'react';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { RequestForm } from '../../../components/vera/confidential/FirmRequests';
import type { DirectoryListing, FirmSession } from '../../../lib/confidential/firmCase';

/** The request form carries the organization's approved signed profile, never a
 * second free-text one, and removing a request says it affects every lawyer. */
const hex = (n: number) => n.toString(16).padStart(64, '0');
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/\s+/g, ' ');
const read = (file: string) => readFileSync(path.join(__dirname, '../../..', file), 'utf8');
const session = { firm: { domain: 'counsel.example', organizationId: hex(9), recipientKeyId: hex(10) } } as unknown as FirmSession;
const listing = { caseId: hex(8), summary: 'Summary', owner: { caseId: hex(8), ownerFingerprint: 'a'.repeat(40), ownerPublicKey: {} } } as
  unknown as DirectoryListing;

describe('request form profile', () => {
  test('asks for no free-text profile and waits for the approved signed profile before sending', () => {
    const html = renderToStaticMarkup(React.createElement(RequestForm, { session, listing, kind: 'new', onCancel: () => {} }));
    const shown = text(html);
    expect(shown).not.toMatch(/Practice areas \(separated by commas\)|Website \(optional/);
    expect(html).not.toMatch(/-(practiceAreas|jurisdiction|website)"/);
    expect(shown).toContain('Reading your approved organization profile');
    expect(html).toMatch(/<button type="submit"[^>]*disabled=""/);
  });

  test('the form reads the approved signed profile and no longer keeps a per-device copy', () => {
    const source = read('components/vera/confidential/FirmRequests.tsx');
    expect(source).toMatch(/checkFirmDomain/);
    expect(source).toMatch(/<FirmProfileSummary profile=\{signed\.profile\}/);
    expect(source).not.toMatch(/currentFirmProfile|saveFirmProfile/);
  });
});

describe('request message privacy', () => {
  // The message names the lawyer and says which identifying items they need; the
  // form promises VERA cannot read it, so no browser cloud spell check either.
  test.each(['new', 'renewal'] as const)('keeps the %s message out of browser spell check', kind => {
    const html = renderToStaticMarkup(React.createElement(RequestForm, { session, listing, kind, onCancel: () => {} }));
    const textarea = html.match(/<textarea[^>]*-purpose"[^>]*>|<textarea[^>]*>/)?.[0] ?? '';
    expect(textarea).toMatch(/-purpose"/);
    expect(textarea).toMatch(/spellcheck="false"/i);
    expect(textarea).toMatch(/autocorrect="off"/i);
    expect(textarea).toMatch(/autocapitalize="off"/i);
  });
});

describe('removing a request from the organization list', () => {
  const page = read('pages/legal/index.tsx');
  test('the confirmation says every lawyer loses the entry, not only this workspace', () => {
    expect(page).not.toMatch(/Remove this report from this workspace/);
    expect(page).toContain("Remove this report from your organization's list? Every lawyer in your organization will stop seeing it.");
  });
  test('every "Remove from this list" button only opens the confirmation', () => {
    const buttons = page.match(/<button[^\n]*?>Remove from this list<\/button>/g) ?? [];
    expect(buttons).toHaveLength(2);
    for (const button of buttons) {
      expect(button).not.toMatch(/onForget/);
      expect(button).toMatch(/onClick=\{\(\) => setRemoving\(/);
    }
    // onForget runs only from a "Yes, remove" button placed after the shared confirmation text.
    const calls = page.match(/<span>\{REMOVE_CONFIRMATION\}<\/span>\s*<button[^\n]*?onForget\(item\)[^\n]*?>Yes, remove<\/button>/g) ?? [];
    expect(calls).toHaveLength(2);
    // Otherwise only the "Try again" of a removal that already failed after that confirmation.
    const lines = page.split('\n').filter(line => /onForget\(item\)/.test(line));
    expect(lines.filter(line => !/Yes, remove/.test(line))).toEqual([
      expect.stringMatching(/onRetry=\{\(\) => void \(actionFailures\.get\(item\.caseId\)\?\.action === "remove" \? onForget\(item\)/),
      expect.stringMatching(/<ActionFailure failure=\{actionFailure\}[^\n]*onRetry=\{\(\) => void onForget\(item\)\}/),
    ]);
  });
});
