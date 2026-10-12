import { webcrypto } from 'node:crypto';
import { parseRecoveryFile, readRecoveryFile, recoveryFileText } from '../../../lib/confidential/recoveryFile';
import { encodeRecoveryCodeV2 } from '../../../enclave/src/confidential/recoveryCode';

beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});
const PACKAGE_V2 = '{"format":"vera-owner-recovery/v2","nonce":"x","ciphertext":"y"}';
const PACKAGE_V1 = '{"format":"vera-owner-recovery/v1","nonce":"x","ciphertext":"y"}';

describe('recovery file', () => {
  test('the current file carries plain instructions, the grouped code and the package', async () => {
    const code = await encodeRecoveryCodeV2(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const text = recoveryFileText({ recoveryCode: code.toLowerCase(), recoveryPackage: PACKAGE_V2, statusUrl: 'https://vera.example/status' });
    expect(text).toContain('How to open your report:');
    expect(text).toContain('https://vera.example/status');
    expect(text).toContain(`\n${code}\n`);
    expect(text).not.toMatch(/status\?|#.*[0-9A-Z]{4}-/); // never a code in a URL
    expect(await parseRecoveryFile(text)).toEqual({ code, recoveryPackage: PACKAGE_V2 });
    // Windows line endings, a byte-order mark and no package line (code only) also work.
    expect(await parseRecoveryFile(`﻿${text.replace(/\n/g, '\r\n')}`)).toEqual({ code, recoveryPackage: PACKAGE_V2 });
    expect(await parseRecoveryFile(`My note\n${code.replace(/-/g, ' ')}\n`)).toEqual({ code, recoveryPackage: null });
  });

  test('files written by the earlier (v1) client still open', async () => {
    const code = `VERA-OWNER-1.${'a'.repeat(64)}.${'b'.repeat(40)}.${'A'.repeat(43)}`;
    const text = ['VERA confidential report — PRIVATE RECOVERY FILE', '', 'Recovery code:', code, '',
      'Encrypted backup (needed if the online copy becomes unavailable):', PACKAGE_V1, ''].join('\r\n');
    expect(await parseRecoveryFile(text)).toEqual({ code, recoveryPackage: PACKAGE_V1 });
  });

  test('instruction lines and mistyped codes are not mistaken for a code', async () => {
    const code = await encodeRecoveryCodeV2(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const broken = code.slice(0, -1) + (code.endsWith('A') ? 'B' : 'A');
    expect(await parseRecoveryFile(`Anyone with this file can open your encrypted report and act for you\n${broken}\n${PACKAGE_V2}`)).toBeNull();
    expect(await parseRecoveryFile('no code here')).toBeNull();
    expect(await parseRecoveryFile('')).toBeNull();
    // Unknown package formats are ignored rather than passed on.
    const parsed = await parseRecoveryFile(`${code}\n{"format":"vera-owner-recovery/v9","nonce":"x","ciphertext":"y"}`);
    expect(parsed).toEqual({ code, recoveryPackage: null });
  });

  test('refuses empty and oversized files before reading them', async () => {
    const text = jest.fn();
    expect(await readRecoveryFile({ size: 512 * 1024 + 1, text } as unknown as Blob)).toBeNull();
    expect(await readRecoveryFile({ size: 0, text } as unknown as Blob)).toBeNull();
    expect(text).not.toHaveBeenCalled();
    const unreadable = { size: 10, text: async () => { throw new Error('denied'); } } as unknown as Blob;
    expect(await readRecoveryFile(unreadable)).toBeNull();
  });
});
