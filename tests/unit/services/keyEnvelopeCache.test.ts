/**
 * The KMS unwrap cache must be keyed on ciphertext AND encryption context. A
 * cache hit skips the KMS Decrypt that enforces EncryptionContext, so a blob
 * decrypted under one record's context must never be served for another's.
 * Uses a mocked KMS client (no live AWS).
 */

const send = jest.fn();

jest.mock('@aws-sdk/client-kms', () => ({
  KMSClient: jest.fn().mockImplementation(() => ({ send })),
  EncryptCommand: jest.fn().mockImplementation((input) => ({ input })),
  DecryptCommand: jest.fn().mockImplementation((input) => ({ input })),
}));

describe('keyEnvelope KMS unwrap cache', () => {
  const OLD_ENV = process.env.KMS_AT_REST_KEY_ID;
  let keyEnvelope: typeof import('@services/keyEnvelope').keyEnvelope;

  beforeAll(() => {
    process.env.KMS_AT_REST_KEY_ID = 'arn:aws:kms:us-east-1:000000000000:key/test';
    keyEnvelope = require('@services/keyEnvelope').keyEnvelope;
  });

  afterAll(() => {
    process.env.KMS_AT_REST_KEY_ID = OLD_ENV;
  });

  beforeEach(() => {
    send.mockReset();
    send.mockResolvedValue({ Plaintext: Buffer.from('a'.repeat(64), 'utf8') });
  });

  it('serves a repeat unwrap of the same blob+context from cache (one KMS call)', async () => {
    const blob = `enc:kms:v1:${Buffer.from('same-context-blob').toString('base64')}`;
    const ctx = { trackingId: 'VRA-A', purpose: 'reward' };
    await keyEnvelope.unwrap(blob, ctx);
    await keyEnvelope.unwrap(blob, ctx);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('does NOT serve a cached blob for a different context (re-hits KMS)', async () => {
    const blob = `enc:kms:v1:${Buffer.from('cross-context-blob').toString('base64')}`;
    await keyEnvelope.unwrap(blob, { trackingId: 'VRA-A', purpose: 'reward' });
    await keyEnvelope.unwrap(blob, { trackingId: 'VRA-B', purpose: 'reward' });
    expect(send).toHaveBeenCalledTimes(2);
  });
});

it('writes hashed KMS v2 context and reads v1 with its original context', async () => {
  process.env.KMS_AT_REST_KEY_ID = 'test-kms-key';
  const { keyEnvelope } = require('../../../src/services/keyEnvelope');
  const context = { trackingId: 'VRA-1111111111111111', purpose: 'narrative' };
  send.mockReset(); send.mockResolvedValueOnce({ CiphertextBlob: Buffer.from('v2-ciphertext') });
  const wrapped = await keyEnvelope.wrap('a'.repeat(64), context);
  expect(wrapped).toMatch(/^enc:kms:v2:/);
  const used = send.mock.calls[0][0].input.EncryptionContext;
  expect(used.purpose).toBe('narrative');
  expect(used.trackingId).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(used)).not.toContain(context.trackingId);
  send.mockResolvedValue({ Plaintext: Buffer.from('a'.repeat(64)) });
  await keyEnvelope.unwrap(wrapped, context);
  expect(send.mock.calls[1][0].input.EncryptionContext).toEqual(used);
  await keyEnvelope.unwrap('enc:kms:v1:' + Buffer.from('legacy-context-test').toString('base64'), context);
  expect(send.mock.calls[2][0].input.EncryptionContext).toEqual(context);
  delete process.env.KMS_AT_REST_KEY_ID;
});
