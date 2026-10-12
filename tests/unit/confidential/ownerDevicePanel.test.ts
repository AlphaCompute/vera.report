import { readFileSync } from 'node:fs';
import path from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  DEVICE_CHOICES, deviceChoiceOf, deviceChoiceSteps, OwnerDevicePanel,
} from '../../../components/vera/confidential/OwnerDevice';
import { OtherWaysToOpen, ownerWords, SAVED_COPY, SavedWorkspaces, showSavedSection } from '../../../components/vera/confidential/DeviceWorkspaces';
import type { UnlockedVault } from '../../../lib/confidential/deviceVault';

const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, '\'').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const source = (file: string) => readFileSync(path.join(__dirname, '../../../components/vera/confidential', file), 'utf8');
// Firm and internal terms that reporters never see (agreed vocabulary: recovery
// code, report, legal organization, approve update, access).
const FIRM_TERMS = /workspace|case references?|key file/i;
const noop = async () => {};
const checkedValue = (html: string) => (html.match(/<input type="radio"[^>]*>/g) ?? [])
  .filter(input => input.includes('checked=""')).map(input => /value="([a-z]+)"/.exec(input)?.[1]);
const payload = async () => ({});
const vault = { id: 'v', role: 'owner', protection: 'passphrase' } as unknown as UnlockedVault;

describe('reporter "This device" panel', () => {
  test('the status page has one "This device" panel and one backup section', () => {
    const status = source('ConfidentialCaseStatus.tsx');
    expect(status).not.toContain('RememberWorkspace');
    expect(status).not.toContain('device-memory-title');
    expect(status).not.toContain('Remember only the report history check');
    expect(status.match(/<OwnerDevicePanel\b/g)).toHaveLength(1);
    expect(status.match(/aria-label="Recovery code and file"/g)).toHaveLength(1);
    expect(source('RecoveryReceipt.tsx')).not.toContain('RememberWorkspace');
  });

  test('renders a single choice, off by default, with the freshness note inside it', () => {
    const html = renderToStaticMarkup(createElement(OwnerDevicePanel, { className: 'p', vault: null, onVaultChange: () => {},
      getPayload: payload, history: { on: false, set: noop }, freshness: 'unconfirmed' }));
    const shown = text(html);
    expect(html.match(/<h[1-6][^>]*>This device<\/h[1-6]>/g)).toHaveLength(1);
    expect(html.match(/type="radio"/g)).toHaveLength(4);
    expect(checkedValue(html)).toEqual(['none']);
    expect(shown).toContain('Newest state: not confirmed on this device');
    for (const choice of Object.values(DEVICE_CHOICES)) expect(shown).toContain(choice.title);
    // No separate "remember" button, device backup download or second backup concept.
    expect(shown).not.toMatch(/Remember this|Download encrypted|temporary/i);
    expect(shown).not.toMatch(FIRM_TERMS);
  });

  test('reflects what is saved: a saved report, or only the history check', () => {
    const saved = renderToStaticMarkup(createElement(OwnerDevicePanel, { className: 'p', vault, onVaultChange: () => {},
      getPayload: payload, history: { on: true, set: noop } }));
    expect(checkedValue(saved)).toEqual(['report']);
    expect(text(saved)).toContain('Your report is saved in this browser');
    const history = renderToStaticMarkup(createElement(OwnerDevicePanel, { className: 'p', vault: null, onVaultChange: () => {},
      getPayload: payload, history: { on: true, set: noop } }));
    expect(checkedValue(history)).toEqual(['history']);
  });

  test('without a history check (receipt page) the history-only choice is absent; locked views cannot change it', () => {
    const html = renderToStaticMarkup(createElement(OwnerDevicePanel, { className: 'p', vault: null, onVaultChange: () => {},
      getPayload: payload, locked: true }));
    expect(html.match(/type="radio"/g)).toHaveLength(3);
    expect(html).not.toContain('value="history"');
    expect(html).toMatch(/<fieldset[^>]*disabled=""/);
  });

  test('changing the choice removes, saves and keeps the history check consistently', () => {
    expect(deviceChoiceOf(false, false)).toBe('none');
    expect(deviceChoiceOf(false, true)).toBe('history');
    expect(deviceChoiceOf(true, false)).toBe('report');
    expect(deviceChoiceSteps('none', 'history', false)).toEqual({ removeReport: false, saveReport: false, historyCheck: true });
    expect(deviceChoiceSteps('history', 'none', true)).toEqual({ removeReport: false, saveReport: false, historyCheck: false });
    expect(deviceChoiceSteps('none', 'report', false)).toEqual({ removeReport: false, saveReport: true, historyCheck: true });
    expect(deviceChoiceSteps('history', 'report', true)).toEqual({ removeReport: false, saveReport: true, historyCheck: null });
    expect(deviceChoiceSteps('report', 'history', true)).toEqual({ removeReport: true, saveReport: false, historyCheck: null });
    // A report saved before the history check existed keeps the check when moving down to it.
    expect(deviceChoiceSteps('report', 'history', false)).toEqual({ removeReport: true, saveReport: false, historyCheck: true });
    expect(deviceChoiceSteps('report', 'none', true)).toEqual({ removeReport: true, saveReport: false, historyCheck: false });
    expect(deviceChoiceSteps('report', 'report', true)).toEqual({ removeReport: false, saveReport: false, historyCheck: null });
  });
});

describe('reporter copy uses report and recovery file, not firm terms', () => {
  test('the saved-report sign-in on the status page', () => {
    for (const value of Object.values(SAVED_COPY.owner)) expect(value).not.toMatch(FIRM_TERMS);
    // Legal organizations keep their own terms.
    expect(text(renderToStaticMarkup(createElement(SavedWorkspaces, { role: 'legal', onUnlocked: noop, onRecovered: noop }))))
      .toContain('Return to a saved workspace');
  });

  test('shared device-storage errors are reworded for reporters', () => {
    for (const shared of [
      'The saved workspace could not be unlocked. Check your passphrase or use your recovery backup.',
      'Saved workspace data is damaged. Use a recovery backup or forget this device.',
      'This browser already has 20 saved workspaces. Keep your recovery backups and use this workspace temporarily.',
      'This saved workspace is damaged. Use your key file.',
    ]) expect(ownerWords(shared)).not.toMatch(FIRM_TERMS);
    expect(ownerWords('The saved workspace could not be unlocked. Check your passphrase or use your recovery backup.'))
      .toBe('The saved report could not be unlocked. Check your passphrase or use your recovery file.');
  });

  test('owner-role copy in the device components avoids firm terms', () => {
    const owner = source('OwnerDevice.tsx').split('\n').filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*') &&
      !line.includes('import ') && !line.includes('ownerWords'));
    expect(owner.join('\n')).not.toMatch(FIRM_TERMS);
  });
});

describe('status page empty state: nothing saved on this device', () => {
  const status = readFileSync(path.join(__dirname, '../../../pages/status.tsx'), 'utf8');

  test('the saved-report section only shows when this browser holds a saved report', () => {
    expect(showSavedSection('owner', null)).toBe(false);
    expect(showSavedSection('owner', [])).toBe(false);
    expect(showSavedSection('owner', [{ role: 'legal' }])).toBe(false);
    expect(showSavedSection('owner', [{ role: 'owner' }])).toBe(true);
    // Legal organizations keep their section (it also restores workspace backups).
    expect(showSavedSection('legal', [])).toBe(true);
    expect(showSavedSection('legal', null)).toBe(true);
  });

  test('a reporter with nothing saved sees no saved-report box, older-backup importer or "Forget this device"', () => {
    // Before device storage is read (and when nothing is found) the owner section renders nothing.
    const html = renderToStaticMarkup(createElement(SavedWorkspaces, { role: 'owner', onUnlocked: noop, onRecovered: noop }));
    expect(html).toBe('');
    const legal = text(renderToStaticMarkup(createElement(SavedWorkspaces, { role: 'legal', onUnlocked: noop, onRecovered: noop })));
    expect(legal).toContain('Restore an encrypted workspace backup');
    expect(legal).toContain('Forget this device');
  });

  test('the older backup importer sits behind one "Other ways to open" disclosure', () => {
    const html = renderToStaticMarkup(createElement(OtherWaysToOpen, { onRecovered: noop }));
    expect(html.match(/<details/g)).toHaveLength(1);
    expect(html).not.toMatch(/<details[^>]*open/);
    expect(text(html)).toMatch(/^ ?Other ways to open/);
    expect(text(html)).toContain('Open an older encrypted backup file');
    expect(text(html)).not.toContain('Forget this device');
    expect(text(html)).not.toMatch(FIRM_TERMS);
    // The status page places it with the recovery file control, and the saved-report section no longer carries it.
    const drop = status.indexOf('<RecoveryFileDrop'), other = status.indexOf('<OtherWaysToOpen'), saved = status.indexOf('<SavedWorkspaces');
    expect(drop).toBeGreaterThan(-1);
    expect(other).toBeGreaterThan(drop);
    expect(saved).toBeGreaterThan(other);
    expect(status.match(/<OtherWaysToOpen\b/g)).toHaveLength(1);
  });
});
