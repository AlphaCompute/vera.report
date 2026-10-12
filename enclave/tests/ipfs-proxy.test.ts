import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { createIpfsProxy, IMPORT_PROFILE, listenAddress } from '../src/ipfs-proxy';

const v0 = 'QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN';
const v1 = 'bafybeid7nyfwpy6j5zzyqyt5f4mwmvpcguhb42w4jcebqkfl72pqqpg4nu';

function post(port: number, path: string, body: Buffer) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-length': body.length } }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function withProxy(hash: string, run: (port: number, calls: { url: string; body: Buffer }[]) => Promise<void>) {
  const calls: { url: string; body: Buffer }[] = [];
  jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const chunks: Buffer[] = [];
    const body = init?.body as ReadableStream<Uint8Array>;
    for await (const chunk of body as unknown as AsyncIterable<Uint8Array>) chunks.push(Buffer.from(chunk));
    calls.push({ url: String(input), body: Buffer.concat(chunks) });
    return new Response(JSON.stringify({ Name: 'encrypted.bin', Hash: hash, Size: '14' }), { status: 200 });
  });
  const server = createIpfsProxy();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run((server.address() as AddressInfo).port, calls); }
  finally { await new Promise<void>(resolve => server.close(() => resolve())); }
}

afterEach(() => jest.restoreAllMocks());

it('pins the complete CIDv0 import profile that reproduces historical Pinata CIDs', () => {
  expect(IMPORT_PROFILE).toEqual({
    'cid-version': '0',
    'raw-leaves': 'false',
    chunker: 'size-262144',
    hash: 'sha2-256',
    trickle: 'false',
    'wrap-with-directory': 'false',
  });
  expect(Object.isFrozen(IMPORT_PROFILE)).toBe(true);
});

it('adds ciphertext to Kubo with every profile setting explicit and returns the CIDv0 root', async () => {
  await withProxy(v0, async (port, calls) => {
    const result = await post(port, '/add', Buffer.from('ciphertext'));
    expect(result).toEqual({ status: 200, body: JSON.stringify({ cid: v0 }) });
    expect(calls).toHaveLength(1);
    const url = new URL(calls[0].url);
    expect(`${url.origin}${url.pathname}`).toBe('http://127.0.0.1:5001/api/v0/add');
    expect(Object.fromEntries(url.searchParams)).toEqual({ pin: 'true', ...IMPORT_PROFILE });
    expect(url.searchParams.getAll('cid-version')).toEqual(['0']);
    expect(calls[0].body.includes(Buffer.from('ciphertext'))).toBe(true);
  });
});

it('refuses a CIDv1 root so a profile regression cannot mint unmigratable CIDs', async () => {
  await withProxy(v1, async port => {
    expect((await post(port, '/add', Buffer.from('ciphertext'))).status).toBe(502);
  });
});

async function withKubo(kubo: (url: URL) => Response, run: (port: number, urls: URL[]) => Promise<void>) {
  const urls: URL[] = [];
  jest.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = new URL(String(input));
    urls.push(url);
    return kubo(url);
  });
  const server = createIpfsProxy();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await run((server.address() as AddressInfo).port, urls); }
  finally { await new Promise<void>(resolve => server.close(() => resolve())); }
}
const gcStream = (lines: string[]) => new Response(new ReadableStream({
  start(controller) { for (const line of lines) controller.enqueue(new TextEncoder().encode(line)); controller.close(); },
}), { status: 200 });

it('removes a pinned CID then collects its blocks', async () => {
  await withKubo(url => url.pathname.endsWith('/pin/rm')
    ? new Response(JSON.stringify({ Pins: [v0] }))
    : gcStream(['{"Key":{"/":"bafk', 'rei"}}\n{"Key":{"/":"b"}}\n']), async (port, urls) => {
    expect(await post(port, '/rm', Buffer.from(v0))).toEqual({ status: 200, body: JSON.stringify({ cid: v0, unpinned: true }) });
    expect(urls.map(u => `${u.origin}${u.pathname}`)).toEqual(['http://127.0.0.1:5001/api/v0/pin/rm', 'http://127.0.0.1:5001/api/v0/repo/gc']);
    expect(urls[0].searchParams.get('arg')).toBe(v0);
    expect(urls[1].searchParams.get('stream-errors')).toBe('true');
  });
});

it('treats an already removed CID as success so withdrawal can be retried', async () => {
  await withKubo(url => url.pathname.endsWith('/pin/rm')
    ? new Response(JSON.stringify({ Message: 'not pinned or pinned indirectly', Code: 0, Type: 'error' }), { status: 500 })
    : gcStream([]), async port => {
    expect(await post(port, '/rm', Buffer.from(v0))).toEqual({ status: 200, body: JSON.stringify({ cid: v0, unpinned: false }) });
  });
});

it('fails removal on other Kubo errors and on streamed garbage collection errors', async () => {
  await withKubo(() => new Response(JSON.stringify({ Message: 'repo locked' }), { status: 500 }), async (port, urls) => {
    expect((await post(port, '/rm', Buffer.from(v0))).status).toBe(502);
    expect(urls).toHaveLength(1);
  });
  await withKubo(url => url.pathname.endsWith('/pin/rm') ? new Response('{}') : gcStream(['{"Error":"datastore failure"}\n']), async port => {
    expect((await post(port, '/rm', Buffer.from(v0))).status).toBe(502);
  });
});

it('rejects malformed removal targets and anything outside add, cat and rm', async () => {
  await withKubo(() => new Response('{}'), async (port, urls) => {
    expect((await post(port, '/rm', Buffer.from('../config'))).status).toBe(400);
    for (const path of ['/api/v0/pin/rm', '/api/v0/repo/gc', '/unpin', '/shutdown']) {
      expect((await post(port, path, Buffer.from(v0))).status).toBe(404);
    }
    expect(urls).toHaveLength(0);
  });
});

function captureStderr() {
  const lines: string[] = [];
  jest.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => { lines.push(String(chunk)); return true; });
  return lines;
}
const failureLine = /^IPFS proxy request failed op=(add|cat|rm) status=(\d{3}|none) code=[a-z0-9_A-Z]+ duration_ms=\d+\n$/;

it('logs one line per Kubo failure with operation, status, code and duration but no CID', async () => {
  const lines = captureStderr();
  await withKubo(() => new Response(JSON.stringify({ Message: 'repo locked' }), { status: 500 }), async port => {
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
    expect((await post(port, '/rm', Buffer.from(v0))).status).toBe(502);
    expect((await post(port, '/add', Buffer.from('ciphertext'))).status).toBe(502);
  });
  expect(lines).toHaveLength(3);
  for (const line of lines) expect(line).toMatch(failureLine);
  expect(lines[0]).toContain('op=cat status=502 code=kubo_cat_500 ');
  expect(lines[1]).toContain('op=rm status=502 code=kubo_pin_rm_500 ');
  expect(lines[2]).toContain('op=add status=502 code=kubo_add_500 ');
  expect(lines.join('')).not.toContain(v0);
  expect(lines.join('')).not.toContain('ciphertext');
});

it('logs a block missing from the ephemeral repo as cat_miss, not a Kubo failure', async () => {
  const lines = captureStderr();
  const miss = JSON.stringify({ Message: `block was not found locally (offline): ipld: could not find ${v0}`, Code: 0, Type: 'error' });
  await withKubo(() => new Response(miss, { status: 500 }), async port => {
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
  });
  // A different 500, an unparseable body and a non-500 status stay Kubo failures.
  await withKubo(() => new Response(JSON.stringify({ Message: 'datastore failure' }), { status: 500 }), async port => {
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
  });
  await withKubo(() => new Response(`not json ${v0}`, { status: 500 }), async port => {
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
  });
  await withKubo(() => new Response(miss, { status: 400 }), async port => {
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
  });
  expect(lines).toHaveLength(4);
  for (const line of lines) expect(line).toMatch(failureLine);
  expect(lines[0]).toContain('op=cat status=502 code=cat_miss ');
  expect(lines[1]).toContain('op=cat status=502 code=kubo_cat_500 ');
  expect(lines[2]).toContain('op=cat status=502 code=kubo_cat_500 ');
  expect(lines[3]).toContain('op=cat status=502 code=kubo_cat_400 ');
  expect(lines.join('')).not.toContain(v0);
});

it('logs network and parsing failures by code, never the underlying message', async () => {
  const lines = captureStderr();
  jest.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    if (String(input).includes('/cat')) {
      throw new TypeError(`fetch failed for ${String(input)}`, { cause: Object.assign(new Error(`connect ECONNREFUSED ${v0}`), { code: 'ECONNREFUSED' }) });
    }
    return new Response(`not json ${v0}`);
  });
  const server = createIpfsProxy();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const port = (server.address() as AddressInfo).port;
    expect((await post(port, '/cat', Buffer.from(v0))).status).toBe(502);
    expect((await post(port, '/add', Buffer.from('ciphertext'))).status).toBe(502);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  expect(lines).toHaveLength(2);
  expect(lines[0]).toMatch(failureLine);
  expect(lines[0]).toContain('op=cat status=502 code=ECONNREFUSED ');
  expect(lines[1]).toContain('op=add status=502 code=invalid_response ');
  expect(lines.join('')).not.toContain(v0);
});

it('logs rejected requests and a refused CIDv1 root, and stays silent on success', async () => {
  const lines = captureStderr();
  await withKubo(() => new Response('{}'), async port => {
    expect((await post(port, '/cat', Buffer.from('../config'))).status).toBe(400);
  });
  await withProxy(v1, async port => { expect((await post(port, '/add', Buffer.from('ciphertext'))).status).toBe(502); });
  await withProxy(v0, async port => { expect((await post(port, '/add', Buffer.from('ciphertext'))).status).toBe(200); });
  expect(lines).toHaveLength(2);
  expect(lines[0]).toContain('op=cat status=400 code=invalid_cid ');
  expect(lines[1]).toContain('op=add status=502 code=invalid_cid_version ');
  expect(lines.join('')).not.toContain('config');
  expect(lines.join('')).not.toContain(v1);
});

it('reports health on /health and /healthz from the Kubo version endpoint', async () => {
  let up = true;
  await withKubo(() => new Response('{}', { status: up ? 200 : 500 }), async port => {
    // The global fetch is the Kubo mock here, so probe the proxy with node:http.
    const get = (path: string) => new Promise<number>((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path }, res => { res.resume(); resolve(res.statusCode ?? 0); }).on('error', reject);
    });
    expect(await get('/health')).toBe(204);
    expect(await get('/healthz')).toBe(204);
    up = false;
    expect(await get('/healthz')).toBe(503);
  });
});

it('keeps the enclave listener on loopback unless the sidecar opts into bridge mode', () => {
  expect(listenAddress({})).toEqual({ port: 5002, host: '127.0.0.1' });
  expect(listenAddress({ ENCLAVE_LOCAL_IPFS_TEST: '1' })).toEqual({ port: 5002, host: '0.0.0.0' });
  expect(listenAddress({ IPFS_PROXY_PORT: '15002' })).toEqual({ port: 15002, host: '127.0.0.1' });
  expect(listenAddress({ IPFS_PROXY_PORT: '15002', IPFS_PROXY_BIND: '0.0.0.0' })).toEqual({ port: 15002, host: '0.0.0.0' });
  for (const env of [{ IPFS_PROXY_BIND: '10.0.0.5' }, { IPFS_PROXY_BIND: 'ipfs' }, { IPFS_PROXY_PORT: '80' }, { IPFS_PROXY_PORT: 'x' }]) {
    expect(() => listenAddress(env)).toThrow(/IPFS_PROXY/);
  }
});
