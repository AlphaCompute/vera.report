import { webcrypto } from 'node:crypto';
import { createCaseOwner, createOwnerRecovery } from '../../../enclave/src/confidential/recovery';
import { signOwnerStatement } from '../../../enclave/src/confidential/authorization';
import { exportFirmIdentity, generateFirmIdentity, generateFirmRecoveryCode } from '../../../lib/confidential/firmKey';
import { verifyFirmBackup, verifyOwnerBackup } from '../../../lib/confidential/backupVerification';

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});

test('owner backup must include a decryptable package for this exact receipt', async () => {
  const owner = await createCaseOwner();
  const checkpoint = await signOwnerStatement({ kind: 'checkpoint', caseId: owner.trust.caseId, revision: 1,
    keyEpoch: 1, previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [],
    issuedAt: Date.now() }, owner.privateKey);
  const receipt = await createOwnerRecovery(owner, checkpoint);
  const file = new Blob([`Recovery code:\r\n${receipt.recoveryCode}\r\nEncrypted backup:\r\n${receipt.encryptedPackage}\r\n`]);
  await expect(verifyOwnerBackup(file, receipt.recoveryCode, receipt.encryptedPackage)).resolves.toBeUndefined();
  await expect(verifyOwnerBackup(new Blob([receipt.recoveryCode]), receipt.recoveryCode, receipt.encryptedPackage)).rejects.toThrow();
  // A different report's receipt (its own code and package) must not accept this file.
  const otherOwner = await createCaseOwner();
  const other = await createOwnerRecovery(otherOwner, await signOwnerStatement({ kind: 'checkpoint', caseId: otherOwner.trust.caseId,
    revision: 1, keyEpoch: 1, previousDigest: null, listingDigest: null, manifestDigest: null, grantDigests: [], releaseDigests: [],
    issuedAt: Date.now() }, otherOwner.privateKey));
  await expect(verifyOwnerBackup(file, other.recoveryCode, other.encryptedPackage)).rejects.toThrow();
  const tampered = JSON.parse(receipt.encryptedPackage);
  tampered.ciphertext = (tampered.ciphertext[0] === 'A' ? 'B' : 'A') + tampered.ciphertext.slice(1);
  await expect(verifyOwnerBackup(new Blob([receipt.recoveryCode + '\n' + JSON.stringify(tampered)]),
    receipt.recoveryCode, receipt.encryptedPackage)).rejects.toThrow();
});

test('firm backup requires the separately saved secret and the correct organization key', async () => {
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const secret = generateFirmRecoveryCode();
  const file = new Blob([await exportFirmIdentity(firm, secret)]);
  await expect(verifyFirmBackup(file, secret, firm)).resolves.toBeUndefined();
  await expect(verifyFirmBackup(file, generateFirmRecoveryCode(), firm)).rejects.toThrow();
  await expect(verifyFirmBackup(file, secret, { ...firm, recipientKeyId: 'b'.repeat(64) })).rejects.toThrow();
  await expect(verifyFirmBackup(file, secret, { ...firm, organizationId: 'b'.repeat(64) })).rejects.toThrow();
});

test('oversized backups are rejected before reading into memory', async () => {
  const text = jest.fn();
  const file = { size: 512 * 1024 + 1, text } as unknown as Blob;
  await expect(verifyOwnerBackup(file, 'unused', 'unused')).rejects.toThrow();
  await expect(verifyFirmBackup(file, 'unused', { organizationId: '', recipientKeyId: '', domain: '' })).rejects.toThrow();
  expect(text).not.toHaveBeenCalled();
});

test('file selection rejects malformed and unrelated backups without a recovery code', async () => {
  const { checkFirmBackupFile } = await import('../../../lib/confidential/backupVerification');
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const code = generateFirmRecoveryCode();
  const file = new Blob([await exportFirmIdentity(firm, code)]);
  for (const content of ['', 'ordinary text', '{broken json}', '%PDF-1.7']) {
    await expect(checkFirmBackupFile(new Blob([content]), firm)).rejects.toThrow('empty, unsupported or damaged');
  }
  for (const changed of [{ organizationId: 'b'.repeat(64) }, { recipientKeyId: 'b'.repeat(64) }, { domain: 'other.example' }]) {
    await expect(checkFirmBackupFile(file, { ...firm, ...changed })).rejects.toThrow('different organization key');
  }
  const text = jest.fn();
  await expect(checkFirmBackupFile({ size: 512 * 1024 + 1, text } as unknown as Blob, firm)).rejects.toThrow();
  expect(text).not.toHaveBeenCalled();
  await expect(checkFirmBackupFile(file, firm)).resolves.toBeUndefined();
  // Envelope acceptance never replaces full decryption, and a failed attempt permits retry.
  await expect(verifyFirmBackup(file, generateFirmRecoveryCode(), firm)).rejects.toThrow();
  await expect(verifyFirmBackup(file, code, firm)).resolves.toBeUndefined();
});
