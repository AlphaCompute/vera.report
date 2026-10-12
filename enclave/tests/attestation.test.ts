/**
 * Attestation and secret handling.
 *
 * These are the properties that make the enclave worth having: that keys come
 * from KMS gated on a genuine attestation document, and that nothing about the
 * enclave's identity or its secrets can be produced outside one.
 *
 * An unavailable NSM implementation must fail explicitly. Local tests do not
 * establish real hardware attestation or recipient-key confinement.
 *
 * The legacy crypto smoke script does not verify the native identity endpoint
 * or the unfinished recipient flow. See ../README.md for the acceptance scope.
 *
 * Everything below runs off enclave hardware, where /dev/nsm is absent. That is
 * exactly the environment that triggers the fallback paths under test.
 */

import * as crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { clearSecrets, getSecret } from '../src/kms-proxy.js';
import { getSecretOrFallback } from '../src/server.js';

const onEnclaveHardware = existsSync('/dev/nsm');

describe('environment', () => {
  it('is running off enclave hardware, so fallback paths are the ones exercised', () => {
    // If this ever fails we are on a Nitro instance and these expectations
    // change meaning; the hardware path belongs in smoke-test.sh instead.
    expect(onEnclaveHardware).toBe(false);
  });
});

describe('getSecret', () => {
  it('refuses a secret with no KMS configuration rather than inventing one', async () => {
    await expect(getSecret('totally-unconfigured')).rejects.toThrow(
      /Secret configuration not found/
    );
  });

  it('refuses when the key id is present but the ciphertext is not', async () => {
    process.env.KMS_KEY_HALFCONFIGURED = 'arn:aws:kms:us-east-2:111122223333:key/abc';
    delete process.env.SECRET_HALFCONFIGURED;

    await expect(getSecret('halfconfigured')).rejects.toThrow(/Secret configuration not found/);

    delete process.env.KMS_KEY_HALFCONFIGURED;
  });
});

describe('clearSecrets', () => {
  it('is safe to call with an empty cache and is idempotent', () => {
    expect(() => {
      clearSecrets();
      clearSecrets();
    }).not.toThrow();
  });
});

describe('recipient bootstrap', () => {
  it('rejects configured secrets before contacting a plaintext proxy', async () => {
    process.env.KMS_KEY_CONFIGURED = 'test-key';
    process.env.SECRET_CONFIGURED = Buffer.from('ciphertext').toString('base64');
    try {
      await expect(getSecret('configured')).rejects.toThrow(/Nitro attestation unavailable/);
    } finally {
      delete process.env.KMS_KEY_CONFIGURED;
      delete process.env.SECRET_CONFIGURED;
    }
  });
});

describe('secret resolution fails closed', () => {
  it('ignores development fallback in production and unspecified environments', async () => {
    const previous = process.env.NODE_ENV;
    process.env.ENCLAVE_ALLOW_INSECURE_FALLBACK = 'true';
    try {
      for (const environment of ['production', '']) {
        process.env.NODE_ENV = environment;
        await expect(getSecretOrFallback('encryption')).rejects.toThrow(/Refusing to fall back/);
      }
    } finally { process.env.NODE_ENV = previous; }
  });
  const ENV_FLAG = 'ENCLAVE_ALLOW_INSECURE_FALLBACK';

  afterEach(() => {
    delete process.env[ENV_FLAG];
  });

  /**
   * This was the most serious of the three gaps, and it is now fixed.
   *
   * getSecretOrFallback() used to swallow any KMS failure and substitute
   * sha256(`enclave-fallback-${secretId}`), a constant anyone can compute from
   * the source. handleEncrypt and handleDecrypt call it whenever the caller
   * omits keyDerivationSecret, so an unreachable or misconfigured KMS meant the
   * enclave silently encrypted evidence under a publicly known key and reported
   * success, indistinguishable from real protection.
   *
   * These lock the fix in place.
   */
  it('throws rather than inventing a key when KMS cannot supply the secret', async () => {
    await expect(getSecretOrFallback('encryption')).rejects.toThrow(/Refusing to fall back/);
  });

  it('names the secret and the underlying reason in the error', async () => {
    await expect(getSecretOrFallback('encryption')).rejects.toThrow(/encryption/);
    await expect(getSecretOrFallback('encryption')).rejects.toThrow(
      /Secret configuration not found/
    );
  });

  it('does not leak the derivable value in the error message', async () => {
    const derivable = crypto
      .createHash('sha256')
      .update('enclave-fallback-encryption')
      .digest('hex');

    await expect(getSecretOrFallback('encryption')).rejects.not.toThrow(derivable);
  });

  it('still fails closed when the flag is set to anything but the exact string "true"', async () => {
    for (const value of ['1', 'yes', 'TRUE', 'True', '']) {
      process.env[ENV_FLAG] = value;
      await expect(getSecretOrFallback('encryption')).rejects.toThrow(/Refusing to fall back/);
    }
  });

  it('allows the derivable fallback only behind the explicit development opt-in', async () => {
    // The escape hatch exists so the server can run on a laptop with no KMS.
    // Asserting the exact value documents that it is public knowledge, which is
    // precisely why it must never be reachable by default.
    process.env[ENV_FLAG] = 'true';

    await expect(getSecretOrFallback('encryption')).resolves.toBe(
      crypto.createHash('sha256').update('enclave-fallback-encryption').digest('hex')
    );
  });

  it('scopes the fallback per secret id', async () => {
    process.env[ENV_FLAG] = 'true';

    await expect(getSecretOrFallback('signing')).resolves.toBe(
      crypto.createHash('sha256').update('enclave-fallback-signing').digest('hex')
    );
  });

  /**
   * The opt-in is ignored on real hardware: inside an enclave there is no
   * legitimate reason to want a derivable key, and an env var is attacker- or
   * operator-settable in a way the device check is not.
   *
   * Off hardware this asserts only the opt-in guard. Hardware acceptance is
   * separate and is not established by this test.
   */
  it('treats absence of the NSM device as the only case where opt-in applies', async () => {
    expect(onEnclaveHardware).toBe(false);

    process.env[ENV_FLAG] = 'true';
    await expect(getSecretOrFallback('encryption')).resolves.toEqual(expect.any(String));

    delete process.env[ENV_FLAG];
    await expect(getSecretOrFallback('encryption')).rejects.toThrow();
  });
});
