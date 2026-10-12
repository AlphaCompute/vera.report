/**
 * RPC routing.
 *
 * handleRequest is the single entry point every framed message reaches, so it
 * is where a bad method name or a throwing handler either turns into a clean
 * error response or takes the connection down.
 */

import { handleRequest, keyStore } from '../src/server.js';

const FAST = 1000;

afterEach(() => {
  for (const [id, key] of keyStore.entries()) {
    key.fill(0);
    keyStore.delete(id);
  }
});

describe('handleRequest', () => {
  it('routes hash and echoes the request id', async () => {
    const res = await handleRequest({ id: 'req-1', method: 'hash', params: { data: 'abc' } });

    expect(res.id).toBe('req-1');
    expect(res.error).toBeUndefined();
    expect(res.result).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('preserves a numeric id', async () => {
    const res = await handleRequest({ id: 42, method: 'generateRandom', params: { length: 4 } });

    expect(res.id).toBe(42);
  });

  it('returns -32601 for an unknown method', async () => {
    const res = await handleRequest({ id: 1, method: 'exfiltrateKeys', params: {} });

    expect(res.error).toEqual({ code: -32601, message: 'Unknown method' });
    expect(res.result).toBeUndefined();
  });

  it('does not treat a prototype property as a method', async () => {
    // `switch` on an attacker-controlled string is safe here, but assert it so a
    // refactor to a lookup object cannot silently expose Object.prototype.
    for (const method of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      const res = await handleRequest({ id: 1, method, params: {} });
      expect(res.error?.code).toBe(-32601);
    }
  });

  it('converts a throwing handler into -32000 rather than rejecting', async () => {
    // decrypt with garbage input throws inside node:crypto. The server must
    // answer, because an unanswered request hangs the caller until timeout.
    const res = await handleRequest({
      id: 'bad',
      method: 'decrypt',
      params: { ciphertext: 'not-base64!!', iv: 'zz', authTag: 'zz', salt: 'zz', keyDerivationSecret: 's', iterations: FAST },
    });

    expect(res.id).toBe('bad');
    expect(res.error?.code).toBe(-32000);
    expect(typeof res.error?.message).toBe('string');
  });

  it('does not expose missing key identifiers in errors', async () => {
    const res = await handleRequest({ id: 1, method: 'sign', params: { data: 'x', keyId: 'nonexistent' } });

    expect(res.error?.code).toBe(-32000);
    expect(res.error?.message).toBe('Enclave operation unavailable');
  });

  it('signs with a key held in the enclave and is stable for the same input', async () => {
    const derived = await handleRequest({ id: 1, method: 'deriveKey', params: { secret: 's', iterations: FAST } });
    const keyId = (derived.result as Record<string, string>).keyId;

    const first = await handleRequest({ id: 2, method: 'sign', params: { data: 'payload', keyId } });
    const second = await handleRequest({ id: 3, method: 'sign', params: { data: 'payload', keyId } });

    expect(first.result).toBe(second.result);
    expect(first.result).toMatch(/^[0-9a-f]{64}$/);
  });

  it('produces a different signature for different data', async () => {
    const derived = await handleRequest({ id: 1, method: 'deriveKey', params: { secret: 's', iterations: FAST } });
    const keyId = (derived.result as Record<string, string>).keyId;

    const a = await handleRequest({ id: 2, method: 'sign', params: { data: 'a', keyId } });
    const b = await handleRequest({ id: 3, method: 'sign', params: { data: 'b', keyId } });

    expect(a.result).not.toBe(b.result);
  });

  it('never leaks key material in a response', async () => {
    const secret = 'super-secret-derivation-input';
    const derived = await handleRequest({ id: 1, method: 'deriveKey', params: { secret, iterations: FAST } });

    expect(JSON.stringify(derived)).not.toContain(secret);
  });

  it('never leaks key material in an error message', async () => {
    const secret = 'super-secret-derivation-input';
    const res = await handleRequest({
      id: 1,
      method: 'decrypt',
      params: { ciphertext: '!!', iv: '!!', authTag: '!!', salt: '!!', keyDerivationSecret: secret, iterations: FAST },
    });

    expect(res.error).toBeDefined();
    expect(JSON.stringify(res)).not.toContain(secret);
  });

  it('reports unavailable attestation without simulated PCRs', async () => {
    const res = await handleRequest({ id: 'h', method: 'health', params: {} });
    expect(res.result).toMatchObject({ status: 'unavailable', attested: false });
    for (const key of ['pcr0', 'pcr1', 'pcr2', 'document', 'keysInMemory']) {
      expect(res.result).not.toHaveProperty(key);
    }
  });
});


it('refuses legacy cryptography in production even with caller-supplied secrets', async () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    for (const method of ['encrypt', 'decrypt', 'deriveKey', 'sign']) {
      const response = await handleRequest({ id: 'opaque', method, params: { keyDerivationSecret: 'host-secret', secret: 'host-secret', plaintext: 'private', iterations: 1000 } });
      expect(response.result).toBeUndefined();
      expect(response.error?.message).toBe('Enclave operation unavailable');
    }
    expect(keyStore.size).toBe(0);
  } finally { process.env.NODE_ENV = previous; }
});
