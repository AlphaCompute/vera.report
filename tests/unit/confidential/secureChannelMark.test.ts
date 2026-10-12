import { readFileSync } from 'node:fs';
import path from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ConfidentialLoading, SecureChannelMarkView, secureChannelState } from '../../../components/vera/confidential/SecureChannelMark';

const DIGEST = 'ab'.repeat(32);
const record = (releaseDigest: string) => ({ releaseDigest, sourceCommit: '1'.repeat(40), sourceRepository: 'https://github.com/example/vera', verifiedAt: 1 });
const report = readFileSync(path.resolve(__dirname, '../../../pages/report.tsx'), 'utf8');

describe('secure channel header mark', () => {
  test('is not verified before any attestation has run', () => {
    expect(secureChannelState({ releaseIdentity: 'loading', connectionState: 'verified', verification: null })).toBe('pending');
    expect(secureChannelState({ releaseIdentity: { digest: DIGEST }, connectionState: 'verified', verification: null })).toBe('pending');
  });

  test('is verified only after this tab verified the expected release', () => {
    expect(secureChannelState({ releaseIdentity: { digest: DIGEST }, connectionState: 'verified', verification: record(DIGEST) })).toBe('verified');
    expect(secureChannelState({ releaseIdentity: { digest: DIGEST }, connectionState: 'verified', verification: record('cd'.repeat(32)) })).toBe('pending');
  });

  test('a pending encrypted challenge overrides an attestation record or earlier success', () => {
    expect(secureChannelState({ releaseIdentity: { digest: DIGEST }, connectionState: 'pending', verification: record(DIGEST) })).toBe('pending');
  });

  test('warns when the release identity is unavailable or verification failed, even after an earlier success', () => {
    expect(secureChannelState({ releaseIdentity: 'failed', connectionState: 'verified', verification: null })).toBe('failed');
    expect(secureChannelState({ releaseIdentity: { digest: DIGEST }, connectionState: 'failed', verification: record(DIGEST) })).toBe('failed');
  });

  test('pulses red until verified and respects reduced motion in every state', () => {
    const pending = renderToStaticMarkup(React.createElement(SecureChannelMarkView, { state: 'pending' }));
    const failed = renderToStaticMarkup(React.createElement(SecureChannelMarkView, { state: 'failed' }));
    const verified = renderToStaticMarkup(React.createElement(SecureChannelMarkView, { state: 'verified' }));
    for (const html of [pending, failed]) {
      expect(html).toContain('#dc2626');
      expect(html).not.toContain('var(--color-green-600)');
      expect(html).not.toContain('Secure Channel');
    }
    for (const html of [pending, failed, verified]) {
      expect(html).toContain('motion-safe:animate-pulse');
      expect(html).toContain('Confidential');
      expect(html).toContain('role="status"');
    }
    expect(pending).toContain('Checking enclave');
    expect(pending).not.toContain('>Verified<');
    expect(failed).toContain('Not verified');
    expect(verified).toContain('var(--color-green-600)');
    expect(verified).toContain('Enclave verified');
    expect(verified).toContain('motion-safe:animate-ping');
    expect(pending).not.toContain('motion-safe:animate-ping');
    expect(failed).not.toContain('motion-safe:animate-ping');
  });

  test('the entry loader does not claim verification while the check is pending', () => {
    const loading = renderToStaticMarkup(React.createElement(ConfidentialLoading, { ready: false, failed: false, onComplete: jest.fn() }));
    expect(loading).toContain('Confidential workspace');
    expect(loading).toContain('Opening your private space');
    expect(loading).not.toContain('The enclave is checked before you send');
    expect(loading).toContain('role="status"');
    expect(loading).not.toContain('Enclave verified');
    expect(loading).not.toContain('bg-green-600');
  });

  test('the report page drives the mark from state, not a static badge', () => {
    expect(report).not.toMatch(/function SecureChannelMark\(/);
    expect(report).not.toContain('<SecureChannelMark />');
    expect(report).toContain('connectionState={channelState}');
    expect(report).toMatch(/const secureChannelMark = confidential \?/);
  });
});
