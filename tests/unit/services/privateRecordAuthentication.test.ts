import { keyEnvelope } from '../../../src/services/keyEnvelope';
import { openPrivateValue, sealPrivateValue } from '../../../src/services/privateRecord';
import { encryptContactValue, decryptContactValue } from '../../../src/services/reportFieldCrypto';
import { encryptRewardContact, decryptRewardContact, decryptLegacyRewardContact } from '../../../src/services/rewardContact';
import { sealCapability, openCapability } from '../../../src/services/dissemination/recipientCapability';
import { encryptionService } from '../../../src/services/encryption';
import { LocalCryptoClient } from '../../../src/services/cryptoClient';
import { encryptSubmitterDisclosure, packetSubmitterFor } from '../../../src/services/submitterDisclosure';

it.each([4, 8, 12, 13, 14, 15])('rejects a shortened %i-byte private-record tag', async (length) => {
  const sealed = await sealPrivateValue({ private: 'synthetic' }, 'record', 'body');
  const envelope = JSON.parse(sealed.slice('private:v1:'.length));
  envelope.tag = Buffer.from(envelope.tag, 'base64').subarray(0, length).toString('base64');
  await expect(openPrivateValue('private:v1:' + JSON.stringify(envelope), 'record', 'body')).rejects.toThrow();
  expect(await openPrivateValue(sealed, 'record', 'body')).toEqual({ private: 'synthetic' });
});

it.each([4, 8, 12, 13, 14, 15])('rejects a shortened %i-byte local wrapped-key tag', async (length) => {
  const context = { purpose: 'narrative', record: 'synthetic' };
  const sealed = await keyEnvelope.wrap('12'.repeat(32), context);
  const parts = sealed.split(':');
  parts[4] = parts[4].slice(0, length * 2);
  await expect(keyEnvelope.unwrap(parts.join(':'), context)).rejects.toThrow();
  expect(await keyEnvelope.unwrap(sealed, context)).toBe('12'.repeat(32));
});


function shortenedHexTag(value: string): string {
  const parts = value.split(':'); parts[1] = parts[1].slice(0, 8); return parts.join(':');
}
it('rejects short tags in current and legacy reward contact readers', async () => {
  const legacy = encryptContactValue('synthetic');
  expect(() => decryptContactValue(shortenedHexTag(legacy))).toThrow();
  expect(() => decryptLegacyRewardContact(shortenedHexTag(legacy))).toThrow();
  expect(decryptContactValue(legacy)).toBe('synthetic');
  expect(decryptLegacyRewardContact(legacy)).toBe('synthetic');
  const current = await encryptRewardContact('synthetic', 'record');
  await expect(decryptRewardContact({ ...current, ciphertext: shortenedHexTag(current.ciphertext) }, 'record')).rejects.toThrow();
  expect(await decryptRewardContact(current, 'record')).toBe('synthetic');
});
it('rejects shortened recipient bearer capability tags', () => {
  const original = process.env.RECIPIENT_CAPABILITY_SECRET;
  try {
    process.env.RECIPIENT_CAPABILITY_SECRET = 'synthetic-independent-recipient-test-secret';
    const sealed = sealCapability('packet', { synthetic: true });
    const parts = sealed.split('.');
    parts[3] = Buffer.from(parts[3], 'base64url').subarray(0, 4).toString('base64url');
    expect(() => openCapability('packet', parts.join('.'))).toThrow();
    expect(openCapability('packet', sealed)).toEqual({ synthetic: true });
  } finally {
    if (original === undefined) delete process.env.RECIPIENT_CAPABILITY_SECRET;
    else process.env.RECIPIENT_CAPABILITY_SECRET = original;
  }
});
it('rejects shortened tags in generic and local-client encryption', async () => {
  const encrypted = encryptionService.encrypt('synthetic', 'test-secret');
  expect(() => encryptionService.decrypt(encrypted.encrypted, 'test-secret', encrypted.iv, encrypted.authTag.slice(0, 8), encrypted.salt)).toThrow();
  expect(encryptionService.decrypt(encrypted.encrypted, 'test-secret', encrypted.iv, encrypted.authTag, encrypted.salt)).toBe('synthetic');
  const client = new LocalCryptoClient();
  const result = await client.encrypt(Buffer.from('synthetic'), 'test-secret');
  await expect(client.decrypt({ ...result, authTag: result.authTag.slice(0, 8) }, 'test-secret')).rejects.toThrow();
  expect((await client.decrypt(result, 'test-secret')).toString()).toBe('synthetic');
});
it('rejects shortened tags before revealing consented submitter details', async () => {
  const submitter = await encryptSubmitterDisclosure({ mode: 'identified', details: { name: 'Synthetic', contactMethod: 'email', contactValue: 'synthetic@example.invalid' } }, 'record');
  if (submitter.mode !== 'identified') throw new Error('Expected identified fixture');
  const report = { trackingId: 'record', submitter } as any;
  expect((await packetSubmitterFor(report)).mode).toBe('identified');
  await expect(packetSubmitterFor({ ...report, submitter: { ...submitter, ciphertext: shortenedHexTag(submitter.ciphertext) } })).rejects.toThrow();
});

it('rejects shortened storage-layer IPFS data tags', async () => {
  const { encryptForStorage, decryptStoredCiphertext } = await import('../../../src/services/evidenceStorageCipher');
  const sealed = await encryptForStorage(Buffer.from('synthetic'), 'test-secret');
  const shortTag = Buffer.from(sealed.authTag, 'base64').subarray(0, 4).toString('base64');
  await expect(decryptStoredCiphertext(sealed.encrypted, 'test-secret', sealed.iv, shortTag, sealed.salt)).rejects.toThrow();
  expect((await decryptStoredCiphertext(sealed.encrypted, 'test-secret', sealed.iv, sealed.authTag, sealed.salt)).toString()).toBe('synthetic');
});
