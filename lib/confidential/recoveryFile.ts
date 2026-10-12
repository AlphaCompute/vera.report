import { formatRecoveryCode, parseRecoveryCode, recoveryCodeShape } from '../../enclave/src/confidential/recoveryCode';
import { RECOVERY_PACKAGE_FORMATS } from '../../enclave/src/confidential/recoveryFormats';

export const RECOVERY_FILE_NAME = 'vera-private-recovery.txt';
const MAX_FILE = 512 * 1024;
const PACKAGE_LINE = /^\{"format":"vera-owner-recovery\/v\d+"/;

export type RecoveryFile = { code: string; recoveryPackage: string | null };

/** Text of the offline recovery file: plain instructions, the code, and the
 * encrypted package (so the report still opens if the online copy is lost).
 * `statusUrl` is the page address only; never put the code in a URL. */
export function recoveryFileText(input: { recoveryCode: string; recoveryPackage: string; statusUrl?: string }): string {
  return [
    'VERA confidential report: PRIVATE RECOVERY FILE',
    '',
    'Anyone with this file can open your encrypted report and act for you.',
    'VERA cannot reset or recover it. Keep it offline. Do not email, upload or share it.',
    '',
    'How to open your report:',
    `1. Go to the VERA status page${input.statusUrl ? ` (${input.statusUrl})` : ''}.`,
    '2. Choose "Open recovery file" and select this file, or type the recovery code below.',
    '3. The code and this file are read on your device only. They are never sent to VERA.',
    '',
    'Recovery code:',
    formatRecoveryCode(input.recoveryCode),
    '',
    'Encrypted backup (opens your report even if the online copy is lost; do not edit):',
    input.recoveryPackage,
    '',
  ].join('\n');
}

/** Reads a recovery file the participant selected or dropped. Nothing is uploaded. */
export async function readRecoveryFile(file: Blob): Promise<RecoveryFile | null> {
  if (!file || file.size === 0 || file.size > MAX_FILE) return null;
  let text: string;
  try { text = await file.text(); } catch { return null; }
  return parseRecoveryFile(text);
}

/** Finds a valid recovery code (any supported version, checksum verified) and the
 * encrypted package line. Works for files written by every earlier version. */
export async function parseRecoveryFile(text: string): Promise<RecoveryFile | null> {
  if (typeof text !== 'string' || !text || text.length > MAX_FILE) return null;
  const lines = text.replace(/^﻿/, '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  let code: string | null = null;
  for (const line of lines) {
    if (recoveryCodeShape(line) === null) continue;
    try {
      const parsed = await parseRecoveryCode(line);
      parsed.secret.fill(0);
      code = parsed.code;
      break;
    } catch { /* not a code line */ }
  }
  if (!code) return null;
  const recoveryPackage = lines.find(line => {
    if (!PACKAGE_LINE.test(line)) return false;
    try {
      const value = JSON.parse(line) as { format?: unknown };
      return typeof value?.format === 'string' && RECOVERY_PACKAGE_FORMATS.includes(value.format);
    } catch { return false; }
  }) ?? null;
  return { code, recoveryPackage };
}
