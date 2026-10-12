import { createMessage, encrypt, generateKey } from '../../../enclave/src/confidential/pgp';
import { requireEncryptedPayload } from '../../../enclave/src/confidential/encryptedPayload';

test('relay requires the expected public-key encrypted container and bounded wire', async () => {
  const keys = await Promise.all(['one', 'two'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).publicKey));
  const message = await createMessage({ text: 'private synthetic payload' });
  const one = await encrypt({ message, encryptionKeys: [keys[0]], format: 'armored' });
  const two = await encrypt({ message, encryptionKeys: keys, format: 'armored' });
  const password = await encrypt({ message, passwords: ['synthetic-password'], format: 'armored' });
  const direct = await encrypt({ message, sessionKey: { algorithm: 'aes256', data: new Uint8Array(32).fill(1) }, format: 'armored' });
  await expect(requireEncryptedPayload(one, 1, 16384)).resolves.toBe(one);
  await expect(requireEncryptedPayload(two, 2, 16384)).resolves.toBe(two);
  await expect(requireEncryptedPayload(direct, 0, 16384)).resolves.toBe(direct);
  for (const [wire, count, limit] of [[one, 2, 16384], [two, 1, 16384], [one, 1, one.length - 1],
    [password, 1, 16384], [message.armor(), 1, 16384], [one, 0, 16384], [direct, 1, 16384]] as const) {
    await expect(requireEncryptedPayload(wire, count, limit)).rejects.toThrow('Invalid encrypted payload');
  }
});
