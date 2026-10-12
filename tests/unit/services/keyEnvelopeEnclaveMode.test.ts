import { KMSClient } from '@aws-sdk/client-kms';
import { keyEnvelope } from '../../../src/services/keyEnvelope';
const saved = { ...process.env };
afterEach(() => { process.env = { ...saved }; jest.restoreAllMocks(); });
it('refuses local, legacy and already-wrapped keys when enclave mode is requested', async () => {
  delete process.env.ENCLAVE_ENABLED;
  delete process.env.KMS_AT_REST_KEY_ID;
  const raw = '17'.repeat(32);
  const local = await keyEnvelope.wrap(raw, { purpose: 'narrative', record: 'synthetic-mode-check' });
  process.env.ENCLAVE_ENABLED = 'true';
  const send = jest.spyOn(KMSClient.prototype, 'send');
  await expect(keyEnvelope.wrap(raw)).rejects.toThrow('disabled in enclave mode');
  await expect(keyEnvelope.wrap(local)).rejects.toThrow('disabled in enclave mode');
  await expect(keyEnvelope.unwrap(raw)).rejects.toThrow('disabled in enclave mode');
  await expect(keyEnvelope.unwrap(local)).rejects.toThrow('disabled in enclave mode');
  await expect(keyEnvelope.unwrapEnvelope(local)).rejects.toThrow('disabled in enclave mode');
  expect(send).not.toHaveBeenCalled();
});
it('does not return a cached KMS plaintext key or contact KMS after enclave mode is enabled', async () => {
  delete process.env.ENCLAVE_ENABLED;
  const wrapped = 'enc:kms:v2:' + Buffer.from('synthetic-enclave-mode-cache').toString('base64');
  const context = { purpose: 'narrative', record: 'synthetic-mode-cache' };
  const raw = '23'.repeat(32);
  const send = jest.spyOn(KMSClient.prototype, 'send').mockResolvedValue({ Plaintext: Buffer.from(raw) } as never);
  expect(await keyEnvelope.unwrap(wrapped, context)).toBe(raw);
  expect(await keyEnvelope.unwrap(wrapped, context)).toBe(raw);
  expect(send).toHaveBeenCalledTimes(1);
  process.env.ENCLAVE_ENABLED = 'true';
  await expect(keyEnvelope.unwrap(wrapped, context)).rejects.toThrow('disabled in enclave mode');
  expect(send).toHaveBeenCalledTimes(1);
  // Returning to host mode must perform a fresh authorization, not reuse the
  // plaintext cache cleared when enclave mode was requested.
  process.env.ENCLAVE_ENABLED = 'false';
  expect(await keyEnvelope.unwrap(wrapped, context)).toBe(raw);
  expect(send).toHaveBeenCalledTimes(2);
});
