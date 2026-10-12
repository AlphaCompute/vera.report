import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ContinueToWorkspace } from '../../../components/vera/confidential/FirmOnboarding';

const render = (props: Partial<React.ComponentProps<typeof ContinueToWorkspace>>) => renderToStaticMarkup(
  React.createElement(ContinueToWorkspace, { saved: true, busy: false, error: null, onContinue: () => undefined, ...props }));

describe('new organization key: Continue failure', () => {
  test('shows the failure as an alert directly under the Continue button', () => {
    const html = render({ error: 'The workspace could not be opened. Keep your backup and try again.' });
    expect(html).toMatch(/<button[^>]*>Continue<\/button><p role="alert"[^>]*>The workspace could not be opened\. Keep your backup and try again\.<\/p>/);
  });

  test('no alert without a failure; disabled until the backup is verified and while opening', () => {
    expect(render({})).not.toContain('role="alert"');
    expect(render({ saved: false })).toMatch(/<button[^>]*disabled=""[^>]*>Continue<\/button>/);
    expect(render({ saved: false })).toContain('Save and verify your key file and recovery code to continue.');
    expect(render({ busy: true })).toMatch(/<button[^>]*disabled=""[^>]*>Opening…<\/button>/);
  });

  test('the enroll page keeps the Continue failure out of the shared key-backup error', () => {
    const page = readFileSync(join(__dirname, '../../../pages/legal/enroll.tsx'), 'utf8');
    const open = page.slice(page.indexOf('const openWorkspace'), page.indexOf('if (!firm) {'));
    expect(open).toMatch(/catch\s*\{\s*setContinueError\('/);
    expect(open).not.toMatch(/\bsetError\(/);
    expect(page).toMatch(/continueError && <p role="alert"[^>]*>\{continueError\}<\/p>/);
    expect(page).not.toMatch(/startFirmSession\(config, firm\)[^;]*setError\(/);
  });
});
