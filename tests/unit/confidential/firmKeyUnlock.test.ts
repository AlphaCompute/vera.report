/** Regression: a key-file unlock that fails after the key file decrypts (release
 * manifest verification, attestation, relay) must not tell the lawyer that their
 * key file and recovery code do not match. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  CONNECTION_FALLBACK, KEY_MISMATCH_MESSAGE, REPORT_FILE_MESSAGE, REPORT_CODE_MESSAGE, SESSION_START_FALLBACK, unlockFirmKey,
} from '../../../components/vera/confidential/firmKeyUnlock';
import type { FirmIdentity } from '../../../lib/confidential/firmKey';
import type { FirmSession } from '../../../lib/confidential/firmCase';

const firm = { firmId: 'f' } as unknown as FirmIdentity;
const session = { firm } as unknown as FirmSession;
const describe_ = (error: unknown, fallback: string) =>
  error instanceof Error && error.message.startsWith('The secure connection') ? error.message : fallback;

describe('unlockFirmKey', () => {
  it('directs a reporter recovery file to Status without starting a firm session', async () => {
    const start = jest.fn();
    const result = await unlockFirmKey('PRIVATE RECOVERY FILE\n{"format":"vera-owner-recovery/v2","ciphertext":"test"}', 'test', {
      importIdentity: async () => { throw new Error('wrong format'); }, start, describeStartFailure: describe_,
    });
    expect(result).toEqual({ ok: false, message: REPORT_FILE_MESSAGE });
    expect(start).not.toHaveBeenCalled();
  });

  it('explains a report-code mix-up, while allowing custom firm passphrases with the same shape', async () => {
    const code = Array(14).fill('ABCD').join('-');
    const start = jest.fn(async () => session);
    const deps = { importIdentity: async () => { throw new Error('decrypt failed'); }, start, describeStartFailure: describe_ };
    expect(await unlockFirmKey('firm backup', code, deps)).toEqual({ ok: false, message: REPORT_CODE_MESSAGE });
    expect(start).not.toHaveBeenCalled();
    expect(await unlockFirmKey('firm backup', code, { ...deps, importIdentity: async () => firm })).toEqual({ ok: true, session });
  });

  it('reports a mismatch only when the key file fails to decrypt', async () => {
    const start = jest.fn();
    const result = await unlockFirmKey('file', 'wrong', {
      importIdentity: async () => { throw new Error('decrypt failed'); }, start, describeStartFailure: describe_,
    });
    expect(result).toEqual({ ok: false, message: KEY_MISMATCH_MESSAGE });
    expect(start).not.toHaveBeenCalled();
  });

  it('reports a session start failure as a connection problem, not a mismatch', async () => {
    const result = await unlockFirmKey('file', 'right', {
      importIdentity: async () => firm,
      start: async () => { throw new Error('release manifest signature did not verify'); },
      describeStartFailure: describe_,
    });
    expect(result).toEqual({ ok: false, message: SESSION_START_FALLBACK });
    expect(SESSION_START_FALLBACK).not.toBe(KEY_MISMATCH_MESSAGE);
    expect(SESSION_START_FALLBACK).toMatch(/secure connection could not be opened/);
  });

  it('keeps a specific connection message from the session start', async () => {
    const result = await unlockFirmKey('file', 'right', {
      importIdentity: async () => firm,
      start: async () => { throw new Error('The secure connection is paused.'); },
      describeStartFailure: describe_,
    });
    expect(result).toEqual({ ok: false, message: 'The secure connection is paused.' });
  });

  it('returns the session when both steps succeed', async () => {
    const start = jest.fn(async () => session);
    const result = await unlockFirmKey('file', 'right', {
      importIdentity: async () => firm, start, describeStartFailure: describe_,
    });
    expect(result).toEqual({ ok: true, session });
    expect(start).toHaveBeenCalledWith(firm);
  });

  it('is what FirmKeyUnlock uses, with failureMessage for start failures and no blanket mismatch catch', () => {
    const source = readFileSync(path.resolve(__dirname, '../../../components/vera/confidential/LegalPortal.tsx'), 'utf8');
    const body = source.slice(source.indexOf('export function FirmKeyUnlock'), source.indexOf('export function FirmWorkspaceUnlock'));
    expect(body).toContain('unlockFirmKey(');
    expect(body).toContain('describeStartFailure: failureMessage');
    expect(body).toContain('failureMessage(caught, CONNECTION_FALLBACK)');
    expect(body).not.toContain('do not match');
    expect(CONNECTION_FALLBACK).not.toMatch(/match/);
  });
});
