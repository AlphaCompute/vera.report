import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { SecurityDetails, SecurityDetailsPanel, formatVerifiedAt } from '../../../components/vera/confidential/SecurityDetails';
import { lastVerification, recordVerification, resetVerificationRecord, subscribeVerification } from '../../../lib/confidential/verificationRecord';

const DIGEST = 'ab'.repeat(32);
const identity = { sourceCommit: '1'.repeat(40), sourceUrl: `https://github.com/example/vera/commit/${'1'.repeat(40)}`, digest: DIGEST };
const NOW = Date.UTC(2026, 8, 27, 12, 0, 0);

describe('security details disclosure', () => {
  test('closed by default: one accessible button, no release data until opened', () => {
    const html = renderToStaticMarkup(React.createElement(SecurityDetails));
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('>Security details</button>');
    expect(html).not.toContain('Secure service release');
  });

  test('shows website version, source, verified release and last verification time', () => {
    const html = renderToStaticMarkup(React.createElement(SecurityDetailsPanel, {
      id: 'details', identity, now: NOW, websiteCommit: 'c'.repeat(40),
      verification: { releaseDigest: DIGEST, sourceCommit: identity.sourceCommit, sourceRepository: 'https://github.com/example/vera', verifiedAt: NOW - 5 * 60_000 },
      withdrawals: { configured: true, checkedAt: NOW - 60_000, expiresAt: NOW + 7 * 86_400_000, paused: false },
    }));
    expect(html).toContain('Website version');
    expect(html).toContain(`href="https://github.com/example/vera/commit/${'c'.repeat(40)}"`);
    expect(html).toContain('>https://github.com/example/vera</a>');
    expect(html).toContain(DIGEST);
    expect(html).toContain('5 min ago');
    expect(html).not.toContain('against release');
    expect(html).toContain('Current (list valid until');
    // External links never send a referrer from a private screen.
    expect(html.match(/<a /g)!.length).toBe(html.match(/rel="noopener noreferrer" referrerPolicy="no-referrer"|rel="noopener noreferrer" referrerpolicy="no-referrer"/g)!.length);
  });

  test('flags a verification against another release, a paused release and an unconfigured build', () => {
    const html = renderToStaticMarkup(React.createElement(SecurityDetailsPanel, {
      identity, now: NOW, websiteCommit: '',
      verification: { releaseDigest: 'cd'.repeat(32), sourceCommit: '2'.repeat(40), sourceRepository: 'https://github.com/example/vera', verifiedAt: NOW },
      withdrawals: { configured: true, checkedAt: NOW, expiresAt: null, paused: true },
    }));
    expect(html).toContain('Not recorded in this build');
    expect(html).toContain(`against release ${'cd'.repeat(6)}`);
    expect(html).toContain('Paused: this release is withdrawn or could not be confirmed.');
    const none = renderToStaticMarkup(React.createElement(SecurityDetailsPanel, {
      identity: 'invalid', now: NOW, websiteCommit: '', verification: null, withdrawals: { configured: false },
    }));
    expect(none).toContain('This build has no valid release. Nothing can be sent.');
    expect(none).toContain('Not yet in this tab.');
    expect(none).toContain('Not configured for this build.');
  });

  test('formats relative verification time', () => {
    expect(formatVerifiedAt(NOW, NOW + 10_000)).toMatch(/just now\)$/);
    expect(formatVerifiedAt(NOW, NOW + 2 * 3_600_000)).toMatch(/2 h ago\)$/);
  });
});

describe('verification record', () => {
  afterEach(() => resetVerificationRecord());

  test('keeps only the public release and time, and notifies subscribers', () => {
    const listener = jest.fn();
    const unsubscribe = subscribeVerification(listener);
    recordVerification({ releaseDigest: DIGEST, sourceCommit: '1'.repeat(40), sourceRepository: 'https://github.com/example/vera', verifiedAt: NOW });
    expect(listener).toHaveBeenCalledTimes(1);
    expect(Object.keys(lastVerification()!).sort()).toEqual(['releaseDigest', 'sourceCommit', 'sourceRepository', 'verifiedAt']);
    recordVerification({ releaseDigest: 'not-a-digest', sourceCommit: '', sourceRepository: '', verifiedAt: NOW });
    expect(lastVerification()!.releaseDigest).toBe(DIGEST);
    unsubscribe();
  });
});
