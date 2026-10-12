import { readFileSync } from 'node:fs';
import path from 'node:path';
import { webcrypto } from 'node:crypto';
import { parseFirmKeyWitness, witnessStatus } from '../../../lib/confidential/firmKeyWitness';
import { reportCheckCode } from '../../../lib/confidential/reportCheckCode';
const hex = (n: number) => n.toString(16).padStart(64, '0');
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });

describe('firm key witness', () => {
  const entry = { domain: 'counsel.example', organizationId: hex(1), recipientKeyId: hex(2), recordedAt: '2026-09-01T00:00:00.000Z' };

  test('the bundled witness file is valid', () => {
    const bundled = JSON.parse(readFileSync(path.resolve(__dirname, '../../../lib/confidential/firmKeyWitness.json'), 'utf8'));
    expect(() => parseFirmKeyWitness(bundled)).not.toThrow();
  });

  test('strict parsing', () => {
    expect(parseFirmKeyWitness({ format: 'vera-firm-key-witness/v1', firms: [entry] })).toEqual([entry]);
    for (const firms of [[{ ...entry, extra: 1 }], [{ ...entry, domain: 'Not A Domain' }], [entry, { ...entry }], [{ ...entry, recordedAt: 'x' }]]) {
      expect(() => parseFirmKeyWitness({ format: 'vera-firm-key-witness/v1', firms })).toThrow('Invalid firm key witness');
    }
    expect(() => parseFirmKeyWitness({ format: 'other', firms: [] })).toThrow();
  });

  test('recorded, unrecorded and mismatch', () => {
    expect(witnessStatus({ organizationId: hex(1), domain: 'counsel.example', recipientKeyId: hex(2) }, [entry])).toBe('recorded');
    expect(witnessStatus({ organizationId: hex(9), domain: 'other.example', recipientKeyId: hex(2) }, [entry])).toBe('unrecorded');
    expect(witnessStatus({ organizationId: hex(1), domain: 'counsel.example', recipientKeyId: hex(3) }, [entry])).toBe('mismatch');
    expect(witnessStatus({ organizationId: hex(1), domain: 'moved.example', recipientKeyId: hex(2) }, [entry])).toBe('mismatch');
  });


});

describe('report check code', () => {
  test('stable, readable and bound to both the report and the owner key', async () => {
    const a = await reportCheckCode(hex(1), 'ab'.repeat(20));
    expect(a).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
    expect(await reportCheckCode(hex(1), 'ab'.repeat(20))).toBe(a);
    expect(await reportCheckCode(hex(1), 'ac'.repeat(20))).not.toBe(a);
    expect(await reportCheckCode(hex(2), 'ab'.repeat(20))).not.toBe(a);
    await expect(reportCheckCode('nothex', 'ab'.repeat(20))).rejects.toThrow();
  });
});
