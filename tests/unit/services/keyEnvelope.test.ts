/**
 * Unit tests for the key-envelope service using the local AES fallback
 * (no KMS_AT_REST_KEY_ID set, as in CI/dev). The KMS path is exercised in
 * production and is not reachable from here without live AWS.
 */

import { randomBytes } from 'node:crypto';
import { keyEnvelope } from '@services/keyEnvelope';

describe('keyEnvelope (local fallback)', () => {
  const key = () => randomBytes(32).toString('hex');

  it('round-trips a data key with matching context', async () => {
    const plaintext = key();
    const ctx = { trackingId: 'VRA-ABC', purpose: 'narrative' };

    const wrapped = await keyEnvelope.wrap(plaintext, ctx);
    expect(wrapped).toMatch(/^enc:local:v1:/);
    expect(wrapped).not.toContain(plaintext);

    const unwrapped = await keyEnvelope.unwrap(wrapped, ctx);
    expect(unwrapped).toBe(plaintext);
  });

  it('is idempotent — wrapping an already-wrapped value is a no-op', async () => {
    const wrapped = await keyEnvelope.wrap(key(), { purpose: 'evidence' });
    const again = await keyEnvelope.wrap(wrapped, { purpose: 'evidence' });
    expect(again).toBe(wrapped);
  });

  it('passes a legacy pre-envelope raw key through unchanged', async () => {
    const legacy = key();
    expect(await keyEnvelope.unwrap(legacy, { purpose: 'narrative' })).toBe(legacy);
  });

  it('fails to unwrap when the encryption context does not match', async () => {
    const wrapped = await keyEnvelope.wrap(key(), { trackingId: 'VRA-A', purpose: 'narrative' });
    await expect(
      keyEnvelope.unwrap(wrapped, { trackingId: 'VRA-B', purpose: 'narrative' }),
    ).rejects.toThrow();
  });

  it('fails closed in production with neither KMS nor AT_REST_LOCAL_KEY set', async () => {
    const prevNodeEnv = process.env.NODE_ENV;
    const prevLocalKey = process.env.AT_REST_LOCAL_KEY;
    process.env.NODE_ENV = 'production';
    delete process.env.AT_REST_LOCAL_KEY;
    try {
      await expect(keyEnvelope.wrap(key(), { purpose: 'narrative' })).rejects.toThrow(
        /must be set in production/,
      );
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
      if (prevLocalKey === undefined) delete process.env.AT_REST_LOCAL_KEY;
      else process.env.AT_REST_LOCAL_KEY = prevLocalKey;
    }
  });
});
