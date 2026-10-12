import { encodeRecipientEnvelope, decodeRecipientEnvelope, decodeHistoricalEnvelope } from '../src/recipient-envelope';
import { keyEnvelope } from '../../src/services/keyEnvelope';
it('persists and restores the full binary key wrapper with an explicit format version', () => {
  const bytes = Buffer.from(Array.from({ length: 6144 }, (_, i) => i % 256));
  const stored = encodeRecipientEnvelope(bytes);
  const restored = JSON.parse(JSON.stringify({ key: stored }));
  expect(decodeRecipientEnvelope(restored.key)).toEqual(bytes);
  bytes.fill(0);
  expect(decodeRecipientEnvelope(restored.key)).not.toEqual(bytes);
});
it.each([undefined, '', 'enc:kms:v1:YQ==', 'enc:kms:v2:YQ==', 'enc:local:v1:YQ==', 'enc:kms:recipient:v2:YQ==',
  'enc:kms:recipient:v1:', 'enc:kms:recipient:v1:YQ', 'enc:kms:recipient:v1:YR==', 'enc:kms:recipient:v1:YQ==\n',
  'enc:kms:recipient:v1:' + Buffer.alloc(6145).toString('base64')])('rejects ambiguous, legacy and malformed stored keys', value => {
  expect(() => decodeRecipientEnvelope(value)).toThrow('Invalid recipient key envelope');
});
it('keeps recipient keys out of the host plaintext-key reader', async () => {
  await expect(keyEnvelope.unwrap(encodeRecipientEnvelope(Buffer.from('synthetic')))).rejects.toThrow('Unsupported key envelope');
});
it('refuses empty or oversized wrappers at write time', () => {
  expect(() => encodeRecipientEnvelope(Buffer.alloc(0))).toThrow();
  expect(() => encodeRecipientEnvelope(Buffer.alloc(6145))).toThrow();
});

it('keeps the explicit historical wrapper reader separate from generated binary envelopes', () => {
  expect(decodeHistoricalEnvelope('enc:kms:v2:d3JhcHBlZA==')).toEqual(Buffer.from('wrapped'));
  for (const invalid of ['enc:kms:v1:d3JhcHBlZA==', 'enc:kms:v2:YR==', 'enc:kms:v2:', encodeRecipientEnvelope(Buffer.from('wrapped'))]) {
    expect(() => decodeHistoricalEnvelope(invalid)).toThrow();
  }
});
