import { restoreOwnerRecovery } from '../../enclave/src/confidential/recovery';
import { formatRecoveryCode } from '../../enclave/src/confidential/recoveryCode';
import { importFirmIdentity, inspectFirmBackup } from './firmKey';
import type { FirmIdentity } from './firmKey';
import { parseRecoveryFile } from './recoveryFile';

/** Read back a participant-selected file, locally. A download click cannot tell
 * us whether the browser actually saved anything. Never upload these bytes. */
async function boundedText(file: Blob): Promise<string> {
  if (file.size === 0 || file.size > 512 * 1024) throw new Error('Invalid backup file');
  return file.text();
}

export async function verifyOwnerBackup(file: Blob, recoveryCode: string, recoveryPackage: string): Promise<void> {
  const parsed = await parseRecoveryFile(await boundedText(file));
  if (!parsed || parsed.code !== formatRecoveryCode(recoveryCode)) throw new Error('This is not the recovery file for this report');
  if (!parsed.recoveryPackage) throw new Error('The encrypted backup is missing');
  const expected = await restoreOwnerRecovery(recoveryCode, recoveryPackage);
  const restored = await restoreOwnerRecovery(parsed.code, parsed.recoveryPackage, expected.pin);
  if (restored.pin.digest !== expected.pin.digest) throw new Error('The backup does not match this receipt');
  // This confirms recoverability of the receipt, not freshness of server state.
}

export async function verifyFirmBackup(file: Blob, secret: string,
  expected: Pick<FirmIdentity, 'organizationId' | 'domain' | 'recipientKeyId'>): Promise<void> {
  const restored = await importFirmIdentity(await boundedText(file), secret);
  if (restored.organizationId !== expected.organizationId || restored.domain !== expected.domain ||
      restored.recipientKeyId !== expected.recipientKeyId) throw new Error('This backup belongs to a different organization key');
}

/** Reject unrelated or malformed files before asking the user to decrypt them. */
export async function checkFirmBackupFile(file: Blob,
  expected: Pick<FirmIdentity, 'organizationId' | 'domain' | 'recipientKeyId'>): Promise<void> {
  let meta;
  try { meta = inspectFirmBackup(await boundedText(file)); }
  catch { throw new Error('Choose the encrypted VERA legal key file you saved in step 1. This file is empty, unsupported or damaged.'); }
  if (meta.organizationId !== expected.organizationId || meta.domain !== expected.domain || meta.recipientKeyId !== expected.recipientKeyId)
    throw new Error('This file belongs to a different organization key. Choose the file saved for this application.');
}
