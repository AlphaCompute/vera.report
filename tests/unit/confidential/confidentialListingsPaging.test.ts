import { readFileSync } from 'fs';
import path from 'path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ConfidentialListingsFailure } from '../../../components/vera/admin/ConfidentialListingsView';
import {
  createLatestConfidentialListingsLoader,
  fetchConfidentialListingsPage,
  type ConfidentialListingsLoadResult,
} from '../../../lib/confidentialAdminListings';

// Regression: the admin Encrypted tab had no abort or sequence guard, so pressing
// Next then Previous (or Try again) quickly let an older response resolve last and
// overwrite the rows and Next cursor shown for the current page number.

const id = (c: string) => c.repeat(64);
type Pending = { after: string | null; signal: AbortSignal; resolve: (body: unknown) => void };

function deferredFetch() {
  const pending: Pending[] = [];
  const fetchImpl = (_input: string, init: RequestInit) => new Promise<Pick<Response, 'ok' | 'status' | 'json'>>((resolve) => {
    const body = JSON.parse(String(init.body)) as { after?: string };
    pending.push({
      after: body.after ?? null,
      signal: init.signal as AbortSignal,
      resolve: (json) => resolve({ ok: true, status: 200, json: async () => json }),
    });
  });
  return { pending, fetchImpl };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('admin Encrypted tab paging', () => {
  it('drops a page response that resolves after a newer page was requested', async () => {
    const { pending, fetchImpl } = deferredFetch();
    const loader = createLatestConfidentialListingsLoader(fetchImpl);
    const shown: ConfidentialListingsLoadResult[] = [];

    loader.load(id('b'), (result) => shown.push(result)); // Next: page 2
    loader.load(null, (result) => shown.push(result)); // Previous: page 1
    expect(pending).toHaveLength(2);
    expect(pending[0].signal.aborted).toBe(true);
    expect(pending[1].signal.aborted).toBe(false);

    pending[1].resolve({ listings: [{ caseId: id('a'), summary: 'page one' }], next: id('b') });
    await flush();
    pending[0].resolve({ listings: [{ caseId: id('c'), summary: 'page two' }], next: id('d') });
    await flush();

    expect(shown).toEqual([{ status: 'ready', page: { listings: [{ caseId: id('a'), summary: 'page one' }], next: id('b') } }]);
  });

  it('delivers nothing after cancel (effect cleanup on unmount or page change)', async () => {
    const { pending, fetchImpl } = deferredFetch();
    const loader = createLatestConfidentialListingsLoader(fetchImpl);
    const onResult = jest.fn();
    loader.load(null, onResult);
    loader.cancel();
    expect(pending[0].signal.aborted).toBe(true);
    pending[0].resolve({ listings: [], next: null });
    await flush();
    expect(onResult).not.toHaveBeenCalled();
  });

  it('keeps the cursor in the POST body with an abort signal, never in the URL', async () => {
    const fetchImpl = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ listings: [], next: null }) }));
    const signal = new AbortController().signal;
    await expect(fetchConfidentialListingsPage(id('e'), signal, fetchImpl)).resolves.toEqual({ status: 'ready', page: { listings: [], next: null } });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/admin/confidential/listings');
    expect(url).not.toContain(id('e'));
    expect(init.signal).toBe(signal);
    expect(JSON.parse(String(init.body))).toEqual({ limit: 25, after: id('e') });
  });

  it('maps 404 to disabled and other failures to error', async () => {
    const signal = new AbortController().signal;
    await expect(fetchConfidentialListingsPage(null, signal, async () => ({ ok: false, status: 404, json: async () => ({}) }))).resolves.toEqual({ status: 'disabled' });
    await expect(fetchConfidentialListingsPage(null, signal, async () => ({ ok: false, status: 500, json: async () => ({}) }))).resolves.toEqual({ status: 'error' });
    await expect(fetchConfidentialListingsPage(null, signal, async () => { throw new Error('aborted'); })).resolves.toEqual({ status: 'error' });
  });

  // Regression: 401, 403 and 429 all showed "Unable to load encrypted reports"
  // with a Try again that repeated the same failure, unlike the Legal
  // organizations tab.
  it('maps 401, 403 and 429 to signed-out, forbidden and busy', async () => {
    const signal = new AbortController().signal;
    const reply = (status: number) => async () => ({ ok: false, status, json: async () => ({}) });
    await expect(fetchConfidentialListingsPage(null, signal, reply(401))).resolves.toEqual({ status: 'signed-out' });
    await expect(fetchConfidentialListingsPage(null, signal, reply(403))).resolves.toEqual({ status: 'forbidden' });
    await expect(fetchConfidentialListingsPage(null, signal, reply(429))).resolves.toEqual({ status: 'busy' });
    await expect(fetchConfidentialListingsPage(null, signal, reply(503))).resolves.toEqual({ status: 'error' });
  });

  it('renders sign-in, forbidden, wait and retry notices like the Legal organizations tab', () => {
    const render = (status: 'signed-out' | 'forbidden' | 'busy' | 'error') =>
      renderToStaticMarkup(React.createElement(ConfidentialListingsFailure, { result: { status }, onRetry: () => {} }));
    const signedOut = render('signed-out');
    expect(signedOut).toContain('role="alert"');
    expect(signedOut).toContain('Sign in again');
    expect(signedOut).toContain('admin session has ended');
    expect(signedOut).not.toContain('Try again');
    const forbidden = render('forbidden');
    expect(forbidden).toContain('Only VERA administrators can view encrypted reports.');
    expect(forbidden).not.toContain('Try again');
    expect(forbidden).not.toContain('Sign in again');
    const busy = render('busy');
    expect(busy).toContain('Wait a moment');
    expect(busy).toContain('Try again');
    const error = render('error');
    expect(error).toContain('Unable to load encrypted reports.');
    expect(error).toContain('Try again');
  });

  it('the view loads pages only through the guarded loader, and retries through the same effect', () => {
    const source = readFileSync(path.join(__dirname, '../../../components/vera/admin/ConfidentialListingsView.tsx'), 'utf8');
    expect(source).toContain('createLatestConfidentialListingsLoader');
    expect(source).toContain('return () => loader.cancel();');
    expect(source).not.toMatch(/\bfetch\(/);
    expect(source).toContain('setAttempt((value) => value + 1)');
    expect(source).toContain('<ConfidentialListingsFailure result={failure}');
  });
});
