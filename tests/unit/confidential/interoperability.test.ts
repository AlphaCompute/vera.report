import { webcrypto } from 'node:crypto';
// Deliberately use the independently installed root runtime. Only serialized
// bytes cross into the enclave protocol runtime, never its live key objects.
import { createMessage, decrypt, generateKey, readMessage, sign } from 'openpgp';
import { readPrivateKey } from '../../../enclave/src/confidential/pgp';
import { verifyOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { sealCaseObject } from '../../../enclave/src/confidential/caseObject';

test('independent crypto runtimes exchange standard signed/encrypted bytes', async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  const external = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Synthetic independent owner' }], format: 'object' });
  const owner = await readPrivateKey({ armoredKey: external.privateKey.armor() });
  const caseId = '1'.repeat(64), fingerprint = owner.getFingerprint();
  const statement = { kind: 'listing', caseId, revision: 1, summary: 'Approved public preview' };
  const payload = { protocol: 'vera-owner-authorization/v1', ownerFingerprint: fingerprint, statement };
  const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(payload)) }),
    signingKeys: external.privateKey, detached: true, format: 'armored' });
  const verified = await verifyOwnerStatement(JSON.stringify({ ...payload, signature }),
    { caseId, ownerFingerprint: fingerprint, ownerPublicKey: owner.toPublic() });
  expect(verified.statement).toEqual(statement);

  const context = { caseId, objectId: '2'.repeat(64), scope: 'evidence' as const, keyEpoch: 1, objectRevision: 1 };
  const bytes = new TextEncoder().encode('SYNTHETIC-INTEROPERABILITY-EVIDENCE');
  const encrypted = await sealCaseObject(context, bytes, owner);
  const envelope = await decrypt({ message: await readMessage({ armoredMessage: encrypted.ownerEnvelope }),
    decryptionKeys: external.privateKey, verificationKeys: external.publicKey, expectSigned: true, format: 'binary' });
  const envelopeVerification = await Promise.all(envelope.signatures.map(result => result.verified));
  expect(envelopeVerification).toEqual([true]);
  const envelopeData = JSON.parse(new TextDecoder().decode(envelope.data));
  expect(envelopeData.context).toEqual(context);
  const sessionKey = new Uint8Array(Buffer.from(envelopeData.sessionKey, 'base64'));
  const content = await decrypt({ message: await readMessage({ armoredMessage: encrypted.ciphertext }),
    sessionKeys: { algorithm: 'aes256', data: sessionKey }, verificationKeys: external.publicKey,
    expectSigned: true, format: 'binary' });
  expect(await Promise.all(content.signatures.map(result => result.verified))).toEqual([true]);
  const data: Uint8Array = content.data;
  const headerLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0);
  const header = JSON.parse(new TextDecoder().decode(data.subarray(4, 4 + headerLength)));
  expect(header).toEqual({ format: 'vera-case-object/v1-padded', context, length: bytes.length });
  expect(data.slice(4 + headerLength, 4 + headerLength + header.length)).toEqual(bytes);
  // Zero padding up to the 4 KiB bucket, inside the signed and encrypted literal.
  expect(data.length).toBe(4096);
  expect(data.subarray(4 + headerLength + header.length).every(byte => byte === 0)).toBe(true);
  sessionKey.fill(0); envelope.data.fill(0); content.data.fill(0);
});
