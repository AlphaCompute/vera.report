import { ENCLAVE_MAX_FRAME, MAX_CIPHERTEXT } from '../../../src/api/confidentialChannel';
import { MAX_FRAME } from '../../../enclave/src/confidential-server';

// The relay used to accept exactly 1 MiB of ciphertext, which the enclave then
// rejected once the JSON call envelope was added.
test('the largest ciphertext the relay accepts still fits the enclave frame', () => {
  expect(ENCLAVE_MAX_FRAME).toBe(MAX_FRAME);
  const envelope = Buffer.from(JSON.stringify({ op: 'call', nonce: 'f'.repeat(64), ciphertext: 'A'.repeat(MAX_CIPHERTEXT) }));
  expect(envelope.length).toBeLessThanOrEqual(MAX_FRAME);
  expect(MAX_CIPHERTEXT).toBeGreaterThan(MAX_FRAME - 2048);
});
