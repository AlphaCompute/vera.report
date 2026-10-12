import React from 'react';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { ENDED_REQUEST_STATUS, EndedMembershipRequests } from '../../../components/vera/confidential/EndedMembershipRequests';

/** With an ended membership the portal keeps showing the organization's
 * requests saved on this device, read-only, instead of rendering nothing. */
const hex = (n: number) => n.toString(16).padStart(64, '0');
const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;|&apos;/g, "'").replace(/\s+/g, ' ');
const request = (n: number, summary: string, requestedAt: number) =>
  ({ caseId: hex(n), requestId: hex(n + 100), ownerPublicKey: 'owner-key', summary, requestedAt });

describe('requests while the membership has ended', () => {
  test('lists this device\'s saved requests, newest first, as unavailable and with no actions', () => {
    const html = renderToStaticMarkup(React.createElement(EndedMembershipRequests, {
      requests: [request(1, 'Older report', Date.UTC(2026, 0, 5)), request(2, 'Newer report', Date.UTC(2026, 5, 5))],
    }));
    const shown = text(html);
    expect(shown).toContain("Your organization's requests");
    expect(shown).toContain('see the notice above');
    expect(shown.indexOf('Newer report')).toBeLessThan(shown.indexOf('Older report'));
    expect(shown.split(ENDED_REQUEST_STATUS).length - 1).toBe(2);
    expect(html).not.toMatch(/<button|<a |<form/);
    // No case IDs, request IDs or keys in the markup.
    expect(html).not.toContain(hex(1));
    expect(html).not.toContain(hex(101));
    expect(html).not.toContain('owner-key');
  });

  test('explains the empty state instead of rendering nothing', () => {
    const shown = text(renderToStaticMarkup(React.createElement(EndedMembershipRequests, { requests: [] })));
    expect(shown).toContain('This device has no saved requests for your organization');
    expect(shown).toContain('once you accept a new invitation');
  });

  test('the portal renders something for every membership view, including ended', () => {
    const root = path.join(__dirname, '../../..');
    const onboarding = readFileSync(path.join(root, 'lib/confidential/firmOnboarding.ts'), 'utf8');
    const views = [...(onboarding.match(/export type PortalView = ([^;]+);/)?.[1] ?? '').matchAll(/'([a-z-]+)'/g)].map(m => m[1]);
    expect(views).toContain('ended');
    const page = readFileSync(path.join(root, 'pages/legal/index.tsx'), 'utf8');
    const portal = page.slice(page.indexOf('function Portal('), page.indexOf('function RequestsAndDirectory'));
    for (const view of views) expect(portal).toContain(`view === "${view}"`);
    expect(portal).toMatch(/view === "ended" && <EndedMembershipRequests requests=\{rememberedRequests\(session\.firm\.organizationId\)\} \/>/);
  });
});
