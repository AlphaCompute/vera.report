import { createMessage, decrypt, encrypt, generateKey, readMessage, readSignature, sign, verify } from '../../../enclave/src/confidential/pgp';
import { recordAttestedTime, setAttestedTimeClocksForTests } from '../../../lib/confidential/attestedTime';

const time = 1_800_000_000_000;
afterEach(() => setAttestedTimeClocksForTests());

test('key and signature packets use the attested signing time; explicit dates are preserved', async () => {
  setAttestedTimeClocksForTests({ device: () => time + 5_000, monotonic: () => 0 });
  recordAttestedTime(time);
  const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic owner' }], format: 'object' });
  expect(privateKey.getCreationTime().getTime()).toBe(time);
  const message = await createMessage({ binary: new Uint8Array([1, 2, 3]) });
  for (const date of [undefined, new Date(time + 2_000)]) {
    const wire = await sign({ message, signingKeys: privateKey, detached: true, format: 'armored', date });
    expect((await readSignature({ armoredSignature: wire })).packets[0].created?.getTime()).toBe(date?.getTime() ?? time);
  }
});

test('reply and signature verification use the upper time bound, including round trip', async () => {
  setAttestedTimeClocksForTests({ device: () => time - 5_000, monotonic: () => 5_000 });
  recordAttestedTime(time, 0); // Lower bound T, upper bound T + 5 seconds.
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic participant' }], format: 'object' });
  const message = await createMessage({ binary: new Uint8Array([1, 2, 3]) });
  const ciphertext = await encrypt({ message, signingKeys: privateKey, encryptionKeys: publicKey,
    date: new Date(time + 4_000), format: 'armored' });
  const opened = await decrypt({ message: await readMessage({ armoredMessage: ciphertext }),
    decryptionKeys: privateKey, verificationKeys: publicKey, expectSigned: true, format: 'binary' });
  await expect(opened.signatures[0].verified).resolves.toBe(true);
  const future = await sign({ message, signingKeys: privateKey, detached: true, format: 'armored',
    date: new Date(time + 6_000) });
  const checked = await verify({ message, signature: await readSignature({ armoredSignature: future }),
    verificationKeys: publicKey, format: 'binary' });
  await expect(checked.signatures[0].verified).rejects.toThrow();
});
