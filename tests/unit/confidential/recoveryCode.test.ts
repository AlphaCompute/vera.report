import { webcrypto } from 'node:crypto';
import {
  encodeRecoveryCodeV2, formatRecoveryCode, parseRecoveryCode, recoveryCodeGroups, recoveryCodeProblem,
  recoveryCodeProblemText, recoveryCodeShape, RECOVERY_CODE_LENGTH,
} from '../../../enclave/src/confidential/recoveryCode';
import { isConfidentialOwnerCode } from '../../../src/utils/confidentialIdentifiers';
import { TRACKING_ID_PATTERN } from '../../../lib/reportStatus';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
beforeAll(() => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
});
const secret = (fill?: number) => fill === undefined ? globalThis.crypto.getRandomValues(new Uint8Array(32)) : new Uint8Array(32).fill(fill);
const swap = (code: string, index: number) => {
  const chars = code.split('');
  chars[index] = ALPHABET[(ALPHABET.indexOf(chars[index]) + 7) % 32];
  return chars.join('');
};

describe('v2 recovery code encoding', () => {
  test('is 56 Crockford base32 characters in 14 groups and round-trips the secret', async () => {
    for (let i = 0; i < 25; i += 1) {
      const value = secret();
      const code = await encodeRecoveryCodeV2(value);
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){13}$/);
      expect(code.replace(/-/g, '')).toHaveLength(RECOVERY_CODE_LENGTH);
      const parsed = await parseRecoveryCode(code);
      expect(parsed.version).toBe('v2');
      expect(parsed.code).toBe(code);
      expect(Array.from(parsed.secret)).toEqual(Array.from(value));
    }
  });

  test('covers edge values (all zero, all one bits)', async () => {
    for (const fill of [0, 255]) {
      const code = await encodeRecoveryCodeV2(secret(fill));
      expect(Array.from((await parseRecoveryCode(code)).secret)).toEqual(Array.from(secret(fill)));
    }
  });

  test('accepts the ways people type it: lower case, spaces, no separators, O/0 and I/L/1 confusion', async () => {
    const value = secret();
    const code = await encodeRecoveryCodeV2(value);
    const forms = [code.toLowerCase(), code.replace(/-/g, ' '), code.replace(/-/g, ''), `  ${code}\n`,
      code.replace(/0/g, 'O').replace(/1/g, 'I'), code.replace(/1/g, 'l').replace(/-/g, ' – ')];
    for (const form of forms) {
      const parsed = await parseRecoveryCode(form);
      expect(Array.from(parsed.secret)).toEqual(Array.from(value));
      expect(parsed.code).toBe(code);
      expect(formatRecoveryCode(form)).toBe(code);
    }
    expect(recoveryCodeGroups(code.toLowerCase())).toEqual(code.split('-'));
  });

  test('rejects wrong secret sizes on encode', async () => {
    await expect(encodeRecoveryCodeV2(new Uint8Array(31))).rejects.toThrow();
    await expect(encodeRecoveryCodeV2(new Uint8Array(33))).rejects.toThrow();
  });

  test('the checksum catches every single-character substitution and adjacent swap', async () => {
    // Fixed synthetic input: a truncated checksum cannot promise no collisions
    // for arbitrary randomly generated mutations.
    const code = (await encodeRecoveryCodeV2(secret(0))).replace(/-/g, '');
    for (let index = 0; index < code.length; index += 1) {
      await expect(parseRecoveryCode(swap(code, index))).rejects.toThrow('Invalid recovery code');
    }
    for (let index = 0; index + 1 < code.length; index += 1) {
      if (code[index] === code[index + 1]) continue;
      const swapped = code.slice(0, index) + code[index + 1] + code[index] + code.slice(index + 2);
      await expect(parseRecoveryCode(swapped)).rejects.toThrow('Invalid recovery code');
    }
  });

  test.each([undefined, 42, '', 'x'.repeat(300), 'U'.repeat(56), '0'.repeat(55), '0'.repeat(57)])(
    'rejects malformed input %#', async value => {
      await expect(parseRecoveryCode(value)).rejects.toThrow('Invalid recovery code');
    });
});

describe('v1 (legacy) codes stay parseable', () => {
  const caseId = 'ab'.repeat(32), fingerprint = 'cd'.repeat(20);
  test('parses locator, fingerprint and secret', async () => {
    const raw = secret(9);
    const code = `VERA-OWNER-1.${caseId}.${fingerprint}.${Buffer.from(raw).toString('base64url')}`;
    const parsed = await parseRecoveryCode(` ${code} `);
    expect(parsed.version).toBe('v1');
    if (parsed.version !== 'v1') throw new Error('unreachable');
    expect(parsed.caseId).toBe(caseId);
    expect(parsed.ownerFingerprint).toBe(fingerprint);
    expect(Array.from(parsed.secret)).toEqual(Array.from(raw));
    expect(formatRecoveryCode(` ${code} `)).toBe(code);
    expect(await recoveryCodeProblem(code)).toBeNull();
  });
  test.each([
    `VERA-OWNER-1.${'ab'.repeat(32)}.${'cd'.repeat(20)}.${'A'.repeat(42)}`,
    `VERA-OWNER-1.${'AB'.repeat(32)}.${'cd'.repeat(20)}.${'A'.repeat(43)}`,
    `VERA-OWNER-1.${'ab'.repeat(32)}.${'cd'.repeat(21)}.${'A'.repeat(43)}`,
    `VERA-OWNER-1.${'ab'.repeat(32)}.${'cd'.repeat(20)}.${'A'.repeat(42)}B`, // non-canonical padding bits
    `VERA-OWNER-2.${'ab'.repeat(32)}.${'cd'.repeat(20)}.${'A'.repeat(43)}`,
  ])('rejects malformed v1 input %#', async code => {
    await expect(parseRecoveryCode(code)).rejects.toThrow();
    expect(await recoveryCodeProblem(code)).toEqual({ reason: 'format' });
  });
});

describe('shape recognition keeps codes on the device', () => {
  test('typed and mistyped codes are kept local; report IDs and short prose are not', async () => {
    const code = await encodeRecoveryCodeV2(secret());
    for (const form of [code, code.toLowerCase(), code.replace(/-/g, ''), code.slice(0, -5), `${code}-ABCD`, swap(code, 3)]) {
      expect(recoveryCodeShape(form)).toBe('v2');
      // Server-side legacy isolation uses the same rule.
      expect(isConfidentialOwnerCode(form)).toBe(true);
      expect(TRACKING_ID_PATTERN.test(form.toUpperCase())).toBe(false);
    }
    expect(recoveryCodeShape('VERA-OWNER-1.abc')).toBe('v1');
    // Long prose can conservatively match a secret; never use digit count to route it outward.
    expect(recoveryCodeShape('financial fraud involving public procurement officials in the region')).toBe('v2');
    for (const other of ['VRA-0123456789ABCDEF', `VRC-${'A'.repeat(64)}`, 'fraud', '', 'x'.repeat(300),
      42]) {
      expect(recoveryCodeShape(other)).toBeNull();
      expect(isConfidentialOwnerCode(other)).toBe(false);
    }
  });

  test('a valid letter-heavy code is recognised and recoverable from its file', async () => {
    const code = await encodeRecoveryCodeV2(new Uint8Array(32).fill(255));
    expect((code.match(/[0-9]/g) ?? []).length).toBeLessThan(4);
    for (const form of [code, code.toLowerCase(), code.replace(/-/g, '')]) {
      expect(recoveryCodeShape(form)).toBe('v2');
      expect(isConfidentialOwnerCode(form)).toBe(true);
      const { parseRecoveryFile } = await import('../../../lib/confidential/recoveryFile');
      expect(await parseRecoveryFile(form)).toMatchObject({ code });
    }
  });

  test('generated codes are recognised', async () => {
    for (let i = 0; i < 200; i += 1) expect(recoveryCodeShape(await encodeRecoveryCodeV2(secret()))).toBe('v2');
  });
});

test('valid codes with fewer than four digits remain local in every accepted spelling', async () => {
  // All-one bits yield fifty-one Zs followed by checksum bits: no entropy heuristic is safe.
  const code = await encodeRecoveryCodeV2(secret(255));
  expect((code.match(/[0-9]/g) ?? []).length).toBeLessThan(4);
  for (const spelling of [code, code.toLowerCase(), code.replace(/-/g, ''), code.replace(/-/g, ' ')]) {
    expect((await parseRecoveryCode(spelling)).version).toBe('v2');
    expect(recoveryCodeShape(spelling)).toBe('v2');
    expect(isConfidentialOwnerCode(spelling)).toBe(true);
  }
});

describe('local feedback for mistyped codes', () => {
  test('valid codes have no problem', async () => {
    expect(await recoveryCodeProblem(await encodeRecoveryCodeV2(secret()))).toBeNull();
  });

  test('names the group with a single wrong character', async () => {
    const code = await encodeRecoveryCodeV2(secret(0));
    const compact = code.replace(/-/g, '');
    for (const index of [0, 13, 29, 55]) {
      const problem = await recoveryCodeProblem(swap(compact, index));
      expect(problem).toEqual({ reason: 'typo', group: Math.floor(index / 4) + 1 });
      expect(recoveryCodeProblemText(problem!)).toContain(`group ${Math.floor(index / 4) + 1}`);
    }
  });

  test('does not name a group when two single-character corrections are valid', async () => {
    // Synthetic 24-bit checksum collision; neither candidate belongs to a case.
    const ambiguous = '8Q89AWZNHCBGJ1RQ1MC7HVYJ6AMAKFM1XD4MT3E76C7PKCSNMEQXF9YC';
    const candidates = [
      '8Q89AWZNHCBGJ1RQ1MC7HVYJ6A2AKFM1XD4MT3E76C7PKCSNMEQXF9YC',
      '8Q89AWZNHCBGJ1RQ1MC7HVYJ6AMAKFM1XD4MT3E76C7PKCANMEQXF9YC',
    ];
    for (const candidate of candidates) {
      expect([...candidate].filter((char, at) => char !== ambiguous[at])).toHaveLength(1);
      (await parseRecoveryCode(candidate)).secret.fill(0);
    }
    await expect(parseRecoveryCode(ambiguous)).rejects.toThrow('Invalid recovery code');
    const problem = await recoveryCodeProblem(ambiguous);
    expect(problem).toEqual({ reason: 'typo', group: null });
    expect(recoveryCodeProblemText(problem!)).not.toContain('group');
  });

  test('explains length, characters, emptiness and unknown formats without echoing the input', async () => {
    const code = await encodeRecoveryCodeV2(secret(0));
    const short = await recoveryCodeProblem(code.slice(0, -5));
    expect(short).toEqual({ reason: 'length', length: 52 });
    expect(recoveryCodeProblemText(short!)).toMatch(/56 characters in 14 groups of 4\. You entered 52/);
    const bad = await recoveryCodeProblem(code.replace(/^./, 'U'));
    expect(bad).toEqual({ reason: 'characters', characters: ['U'] });
    expect(await recoveryCodeProblem('   ')).toEqual({ reason: 'empty' });
    expect(await recoveryCodeProblem('hello')).toEqual({ reason: 'length', length: 5 });
    // Two separate mistakes cannot be pinned to one group.
    const twice = await recoveryCodeProblem(swap(swap(code.replace(/-/g, ''), 2), 40));
    expect(twice).toEqual({ reason: 'typo', group: null });
    for (const problem of [short!, bad!, twice!]) {
      for (const group of code.split('-')) expect(recoveryCodeProblemText(problem)).not.toContain(group);
    }
  });
});
