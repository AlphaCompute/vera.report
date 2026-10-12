import { fetchRelay, RelayHttpError, RelayNetworkError } from '../../../lib/confidential/client';

const originalFetch = globalThis.fetch;
const encoder = new TextEncoder();
const nonce = 'a'.repeat(64);
afterEach(() => { globalThis.fetch = originalFetch; jest.useRealTimers(); });

test('rejects oversized session evidence while streaming, without waiting for the body to finish', async () => {
  const cancel = jest.fn();
  globalThis.fetch = jest.fn(async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(encoder.encode(' '.repeat(33 * 1024))); }, cancel,
  }))) as typeof fetch;
  const result = fetchRelay().open(nonce).catch(error => error);
  // The stream deliberately stays open: enforcing a limit only after json()
  // buffers its entire body never reaches the attestation length checks.
  const outcome = await Promise.race([result, new Promise(resolve => setTimeout(() => resolve('still reading'), 100))]);
  expect(outcome).toBeInstanceOf(RelayHttpError);
  expect(cancel).toHaveBeenCalledTimes(1);
});

test.each(['stage', 'stageChunk'] as const)('bounds the small %s acknowledgment independently of encrypted replies', async method => {
  globalThis.fetch = jest.fn(async () => new Response(JSON.stringify({ digest: nonce, padding: 'x'.repeat(2048) }))) as typeof fetch;
  const relay = fetchRelay();
  await expect(method === 'stage' ? relay.stage('ciphertext') : relay.stageChunk(new Uint8Array([1])))
    .rejects.toBeInstanceOf(RelayHttpError);
});

test('permits a full-sized encrypted evidence reply and enforces the response byte ceiling', async () => {
  const ciphertext = 'x'.repeat(1536 * 1024);
  globalThis.fetch = jest.fn(async () => Response.json({ ciphertext })) as typeof fetch;
  expect(await fetchRelay().call(nonce, 'request') === ciphertext).toBe(true);
  globalThis.fetch = jest.fn(async () => Response.json({ ciphertext: 'x'.repeat(2 * 1024 * 1024) })) as typeof fetch;
  const outcome = await fetchRelay().call(nonce, 'request').then(() => 'accepted oversized reply', error => error);
  expect(outcome).toBeInstanceOf(RelayHttpError);
});

test('an HTTP failure cancels its unread response body', async () => {
  const cancel = jest.fn();
  globalThis.fetch = jest.fn(async () => new Response(new ReadableStream({ cancel }), { status: 503 })) as typeof fetch;
  await expect(fetchRelay().call(nonce, 'request')).rejects.toBeInstanceOf(RelayHttpError);
  expect(cancel).toHaveBeenCalledTimes(1);
});

test('rejects an oversized declared body before reading it and cancels the stream', async () => {
  const cancel = jest.fn();
  globalThis.fetch = jest.fn(async () => new Response(new ReadableStream({ cancel }),
    { headers: { 'Content-Length': String(3 * 1024 * 1024) } })) as typeof fetch;
  await expect(fetchRelay().call(nonce, 'request')).rejects.toBeInstanceOf(RelayHttpError);
  expect(cancel).toHaveBeenCalledTimes(1);
});

test('does not silently replace invalid UTF-8 in an otherwise valid JSON reply', async () => {
  const before = encoder.encode('{"ciphertext":"'), after = encoder.encode('"}');
  globalThis.fetch = jest.fn(async () => new Response(new Uint8Array([...before, 0xff, ...after]))) as typeof fetch;
  await expect(fetchRelay().call(nonce, 'request')).rejects.toThrow();
});

test.each(['headers', 'body'])('a stalled %s phase reaches the same bounded deadline and aborts transport', async phase => {
  jest.useFakeTimers();
  let signal: AbortSignal | undefined;
  const cancel = jest.fn();
  globalThis.fetch = jest.fn(async (_url, init) => {
    signal = init?.signal ?? undefined;
    if (phase === 'headers') return new Promise<Response>(() => undefined);
    return new Response(new ReadableStream({ cancel }));
  }) as typeof fetch;
  let outcome: unknown = 'still reading';
  const pending = fetchRelay().call(nonce, 'request').then(value => { outcome = value; }, error => { outcome = error; });
  await jest.advanceTimersByTimeAsync(60_001);
  expect(outcome).toBeInstanceOf(RelayNetworkError);
  expect(signal?.aborted).toBe(true);
  if (phase === 'body') expect(cancel).toHaveBeenCalledTimes(1);
  await pending;
});
