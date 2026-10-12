import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { installFatalHandlers } from './fatal.js';

// Matches API MAX_STORED_EVIDENCE_BYTES; separate enclave build has its own rootDir.
const LIMIT = 264 * 1024 * 1024;
const TIMEOUT = 15 * 60 * 1000;
const cidPattern = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})$/;
const cidV0Pattern = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
// Import profile that reproduces every historical Pinata CID (all CIDv0). Kubo only
// defaults raw-leaves off for CIDv0, so every setting that shapes the DAG is explicit.
// Keep in sync with integrations/ipfs/migration/check-profiles.cjs.
export const IMPORT_PROFILE = Object.freeze({
  'cid-version': '0',
  'raw-leaves': 'false',
  chunker: 'size-262144',
  hash: 'sha2-256',
  trickle: 'false',
  'wrap-with-directory': 'false',
});
const KUBO = 'http://127.0.0.1:5001/api/v0';
const addUrl = `${KUBO}/add?${new URLSearchParams({ pin: 'true', ...IMPORT_PROFILE })}`;
const ROUTES = ['/add', '/cat', '/rm'];

// Failure codes are fixed strings: Kubo and fetch error messages can quote the CID.
class ProxyFailure extends Error {
  constructor(readonly code: string) { super(code); }
}
function failureCode(error: unknown, timedOut = false): string {
  if (timedOut) return 'timeout';
  for (let e: any = error, depth = 0; e && depth < 4; e = e.cause, depth++) {
    if (e instanceof ProxyFailure) return e.code;
    if (e.name === 'TimeoutError') return 'timeout';
    if (e.name === 'AbortError') return 'aborted';
    if (e instanceof SyntaxError) return 'invalid_response';
    if (typeof e.code === 'string' && /^[A-Z][A-Z0-9_]{1,40}$/.test(e.code)) return e.code;
  }
  return 'unknown';
}
// One line per failed add/cat/rm for the IpfsStorageErrors alarm: never the CID or payload.
function logFailure(op: string, status: number | 'none', code: string, started: number): void {
  process.stderr.write(`IPFS proxy request failed op=${op} status=${status} code=${code} duration_ms=${Math.round(performance.now() - started)}\n`);
}

async function kuboReady(): Promise<boolean> {
  try {
    const ready = await fetch(`${KUBO}/version`, { method: 'POST', signal: AbortSignal.timeout(1000) });
    await ready.body?.cancel();
    return ready.ok;
  } catch { return false; }
}

async function readSmall(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) throw new ProxyFailure('oversized_response');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString('utf8');
}

// Offline Kubo answers a CID it does not hold with a 500 whose Message reads
// "block was not found locally (offline): ipld: could not find <cid>". The repo
// is ephemeral per task, so after a deploy every older CID misses here and the
// API falls back to the S3 archive: an expected miss, not a Kubo failure.
const missPattern = /not found locally|could not find|merkledag: not found/;
// Consumes or cancels the error body either way.
async function kuboFailureCode(op: string, response: Response): Promise<string> {
  if (op === 'cat' && response.status === 500) {
    try {
      if (missPattern.test(String(JSON.parse(await readSmall(response.body) || '{}').Message || ''))) return 'cat_miss';
    } catch { /* unreadable body: an ordinary Kubo failure */ }
  } else await response.body?.cancel();
  return `kubo_${op}_${response.status}`;
}

// Unpin, then collect garbage so the blocks leave the datastore. Repeating the
// request for an already removed CID succeeds, so consent withdrawal can retry.
async function removeCiphertext(cid: string, signal: AbortSignal): Promise<boolean> {
  const unpin = await fetch(`${KUBO}/pin/rm?arg=${cid}`, { method: 'POST', redirect: 'error', signal });
  let unpinned = true;
  if (!unpin.ok) {
    const message = String(JSON.parse(await readSmall(unpin.body) || '{}').Message || '');
    if (!/not pinned/.test(message)) throw new ProxyFailure(`kubo_pin_rm_${unpin.status}`);
    unpinned = false;
  } else await unpin.body?.cancel();
  const gc = await fetch(`${KUBO}/repo/gc?quiet=true&stream-errors=true`, { method: 'POST', redirect: 'error', signal });
  if (!gc.ok || !gc.body) { await gc.body?.cancel(); throw new ProxyFailure(gc.ok ? 'empty_response' : `kubo_gc_${gc.status}`); }
  // The stream lists every removed block; inspect it line by line without retaining it.
  let pending = '';
  const decoder = new TextDecoder();
  const inspect = (line: string) => { if (line.trim() && JSON.parse(line).Error) throw new ProxyFailure('kubo_gc_error'); };
  for await (const chunk of gc.body as unknown as AsyncIterable<Uint8Array>) {
    const lines = (pending + decoder.decode(chunk, { stream: true })).split('\n');
    pending = lines.pop() || '';
    if (pending.length > 65536) throw new ProxyFailure('oversized_response');
    lines.forEach(inspect);
  }
  inspect(pending + decoder.decode());
  return unpinned;
}

// Only encrypted add/read/remove, with backpressure; never buffer large files in the 2 GiB enclave.
export function createIpfsProxy() {
  let active = false;
  return http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
      res.writeHead(await kuboReady() ? 204 : 503).end();
      return;
    }
    if (req.method !== 'POST' || !ROUTES.includes(req.url || '')) { res.writeHead(404).end(); return; }
    const op = (req.url || '').slice(1);
    const started = performance.now();
    const fail = (status: number, code: string) => { logFailure(op, status, code, started); res.writeHead(status).end(); };
    if (active) { fail(503, 'busy'); return; }
    active = true;
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); req.destroy(); res.destroy(); }, TIMEOUT);
    res.once('close', () => { if (!res.writableFinished) controller.abort(); });
    req.once('aborted', () => controller.abort());
    let response: Response | undefined;
    try {
      if (req.url === '/add') {
        if (Number(req.headers['content-length']) > LIMIT) { fail(413, 'too_large'); return; }
        const boundary = `vera-${randomUUID()}`;
        async function* multipart() {
          yield Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="encrypted.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`);
          let size = 0;
          for await (const chunk of req) {
            size += chunk.length;
            if (size > LIMIT) throw new ProxyFailure('too_large');
            yield chunk;
          }
          if (!size) throw new ProxyFailure('empty_ciphertext');
          yield Buffer.from(`\r\n--${boundary}--\r\n`);
        }
        response = await fetch(addUrl, {
          method: 'POST', body: Readable.toWeb(Readable.from(multipart())) as ReadableStream,
          duplex: 'half', headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
          redirect: 'error', signal: controller.signal,
        } as RequestInit & { duplex: 'half' });
      } else {
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of req) {
          size += chunk.length;
          if (size > 256) { fail(413, 'too_large'); return; }
          chunks.push(Buffer.from(chunk));
        }
        const cid = Buffer.concat(chunks).toString('ascii');
        if (!cidPattern.test(cid)) { fail(400, 'invalid_cid'); return; }
        if (req.url === '/rm') {
          const unpinned = await removeCiphertext(cid, controller.signal);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ cid, unpinned }));
          return;
        }
        response = await fetch(`${KUBO}/cat?arg=${cid}`, {
          method: 'POST', redirect: 'error', signal: controller.signal,
        });
      }
      if (!response.ok) { fail(502, await kuboFailureCode(op, response)); return; }
      if (!response.body) { fail(502, 'empty_response'); return; }
      if (req.url === '/cat') {
        let total = 0;
        res.setHeader('Content-Type', 'application/octet-stream');
        await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream<Uint8Array>), new Transform({
          transform(chunk: Buffer, _encoding, callback) {
            total += chunk.length;
            callback(total > LIMIT ? new ProxyFailure('oversized_response') : null, chunk);
          },
        }), res);
      } else {
        const result = JSON.parse(await readSmall(response.body));
        // A CIDv1 root means Kubo ignored the profile; refuse it rather than mint an unmigratable CID.
        if (!cidV0Pattern.test(result.Hash)) throw new ProxyFailure('invalid_cid_version');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ cid: result.Hash }));
      }
    } catch (error) {
      controller.abort();
      const code = failureCode(error, timedOut);
      if (res.headersSent || timedOut) { logFailure(op, 'none', code, started); res.destroy(); }
      else fail(502, code);
    } finally { clearTimeout(timer); active = false; }
  });
}
// The enclave keeps its fixed vsock-bridged loopback port. The API-task sidecar
// sets IPFS_PROXY_PORT, and IPFS_PROXY_BIND=0.0.0.0 only for ECS bridge mode,
// where the task publishes no port and the API reaches it over the task link.
export function listenAddress(env: NodeJS.ProcessEnv = process.env): { port: number; host: string } {
  const port = Number(env.IPFS_PROXY_PORT || 5002);
  const host = env.IPFS_PROXY_BIND || (env.ENCLAVE_LOCAL_IPFS_TEST === '1' ? '0.0.0.0' : '127.0.0.1');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid IPFS_PROXY_PORT');
  if (!['127.0.0.1', '0.0.0.0'].includes(host)) throw new Error('Invalid IPFS_PROXY_BIND');
  return { port, host };
}
if (process.argv[1]?.endsWith('/ipfs-proxy.js')) {
  const { port, host } = listenAddress();
  if (process.argv[2] === 'healthcheck') {
    // Container health probe: the proxy answers and Kubo behind it is up.
    fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(2000) })
      .then(r => { process.exitCode = r.status === 204 ? 0 : 1; }, () => { process.exitCode = 1; });
  } else {
    installFatalHandlers('IPFS proxy');
    const server = createIpfsProxy();
    server.requestTimeout = TIMEOUT;
    server.headersTimeout = 10_000;
    server.listen(port, host);
  }
}
