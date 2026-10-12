import { exportFirmIdentity, firmBindingDocument, generateFirmIdentity, generateFirmRecoveryCode, importFirmIdentity } from '../../../lib/confidential/firmKey';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import { verifyFirmBackup } from '../../../lib/confidential/backupVerification';

// The encrypted export is the only organization key file format. A file must
// never open, or pass backup verification, without its separately held secret.
let firm: FirmIdentity;
beforeAll(async () => { firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' }); });

test('a downloaded backup contains ciphertext, never the private key or its recovery secret', async () => {
  const secret = generateFirmRecoveryCode();
  const file = await exportFirmIdentity(firm, secret);
  const payload = JSON.parse(file.split('\n').find(line => line.startsWith('{'))!);
  expect(payload.format).toBe('vera-firm-key-export/v1');
  expect(payload).not.toHaveProperty('privateKey');
  expect(payload.ciphertext).toEqual(expect.any(String));
  expect(file).not.toContain('BEGIN PGP PRIVATE KEY BLOCK');
  expect(file).not.toContain(secret);
});

test('file theft alone cannot import or verify a backup; the correct separate secret restores the same key', async () => {
  const secret = generateFirmRecoveryCode();
  const file = await exportFirmIdentity(firm, secret);
  await expect(importFirmIdentity(file, '')).rejects.toThrow();
  await expect(importFirmIdentity(file, generateFirmRecoveryCode())).rejects.toThrow();
  await expect(verifyFirmBackup(new Blob([file]), '', firm)).rejects.toThrow();
  const restored = await importFirmIdentity(file, secret);
  expect(restored.recipientKeyId).toBe(firm.recipientKeyId);
  expect(restored.privateKey.armor()).toBe(firm.privateKey.armor());
  await expect(verifyFirmBackup(new Blob([file]), secret, firm)).resolves.toBeUndefined();
});

test('an export cannot fall back to plaintext when its recovery secret is missing', async () => {
  await expect(exportFirmIdentity(firm, '')).rejects.toThrow();
});

test('an unencrypted key file is rejected with or without a secret', async () => {
  const privateKey = firm.privateKey.armor();
  const unencrypted = JSON.stringify({ format: 'vera-firm-private-key/v1', organizationId: firm.organizationId, domain: firm.domain,
    recipientKeyId: firm.recipientKeyId, privateKey, bindingDocument: await firmBindingDocument(firm, Date.now()) });
  for (const file of [unencrypted, `VERA legal organization key\n\n${unencrypted}\n`, privateKey]) {
    for (const secret of ['', generateFirmRecoveryCode()]) {
      await expect(importFirmIdentity(file, secret)).rejects.toThrow();
      await expect(verifyFirmBackup(new Blob([file]), secret, firm)).rejects.toThrow();
    }
  }
});
