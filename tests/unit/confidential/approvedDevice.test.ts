import React from 'react';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { ApprovedDevice } from '../../../components/vera/confidential/ApprovedDevice';
import type { UnlockedVault } from '../../../lib/confidential/deviceVault';

/** After approval the organization key lives only in this tab's memory. The
 * invitation link usually opens in a new tab, so the page must not send the
 * lawyer there until the workspace is kept on this device or backed up. */
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/\s+/g, ' ');
const render = (vault: UnlockedVault | null, initiallyBackedUp = false) => renderToStaticMarkup(React.createElement(ApprovedDevice, {
  notice: 'Your device was approved.', vault, onRemembered: () => {}, getPayload: async () => ({}), initiallyBackedUp }));

describe('approved device screen', () => {
  test('keeps the invitation step closed until the workspace is kept or backed up', () => {
    const html = render(null);
    const shown = text(html);
    expect(html).not.toContain('href="/legal/enroll"');
    expect(html).toMatch(/<button type="button"[^>]*disabled=""[^>]*>Open workspace<\/button>/);
    expect(shown).toContain('Keep this workspace before you continue');
    expect(shown).toContain('steward to approve this device again');
    expect(shown).not.toContain('Next, open the private invitation link');
    // Both ways to keep it are offered right here.
    expect(shown).toContain('Keep this workspace on this device');
    expect(shown).toContain('Back up this temporary workspace');
  });

  test('opens the invitation step once the workspace is saved on this device', () => {
    const vault = { role: 'legal', protection: 'device' } as unknown as UnlockedVault;
    const html = render(vault);
    expect(html).toContain('href="/legal"');
    expect(html).not.toMatch(/disabled=""[^>]*>Open workspace/);
    expect(text(html)).toContain('Your membership is ready.');
  });

  test('opens the invitation step once a backup file was downloaded', () => {
    const html = render(null, true);
    expect(html).toContain('href="/legal"');
    expect(text(html)).toContain('Your membership is ready.');
  });

  test('both backup downloads report back so the join page can open the next step', () => {
    const source = readFileSync(path.join(__dirname, '../../../components/vera/confidential/DeviceWorkspaces.tsx'), 'utf8');
    expect(source.match(/onBackedUp\?\.\(\)/g)).toHaveLength(2);
    const join = readFileSync(path.join(__dirname, '../../../pages/legal/join.tsx'), 'utf8');
    expect(join).toMatch(/<ApprovedDevice /);
    expect(join).not.toContain('href="/legal/enroll"');
  });
});
