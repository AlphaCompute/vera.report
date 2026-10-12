import { decodeAttestationCbor as decode } from '../../../enclave/src/confidential/attestationCbor';
import type { AttestationCbor } from '../../../enclave/src/confidential/attestationCbor';

const hex = (value: string) => Uint8Array.from(Buffer.from(value.replace(/\s/g, ''), 'hex'));

describe('bounded Nitro CBOR decoding', () => {
  test('preserves signed byte strings, safe integers and map key types', () => {
    const original = hex('8344bf6161001b0000018bcfe56800a20138226131f6');
    const decoded = decode(original) as unknown[];
    expect(decoded[0]).toEqual(hex('bf616100'));
    expect(decoded[1]).toBe(1700000000000);
    expect(decoded[2]).toEqual(new Map<number | string, AttestationCbor>([[1, -35], ['1', null]]));
    original.fill(0);
    expect(decoded[0]).toEqual(hex('bf616100'));
  });
  test('accepts definite and indefinite equivalent containers without normalizing payload bytes', () => {
    expect(decode(hex('bf61619f0102ff61625f4201024103ffff'))).toEqual(
      new Map<string, AttestationCbor>([['a', [1, 2]], ['b', hex('010203')]])
    );
    expect(decode(hex('7f626865636c6c6fff'))).toBe('hello');
    expect(decode(hex('9fff'))).toEqual([]);
    expect(decode(hex('bfff'))).toEqual(new Map());
    expect(decode(hex('5fff'))).toEqual(new Uint8Array());
  });
  test('accepts only explicitly allowed outer COSE tag', () => {
    expect(decode(hex('d28440a04040'), true)).toEqual([hex(''), new Map(), hex(''), hex('')]);
    expect(() => decode(hex('d28440a04040'))).toThrow();
    expect(() => decode(hex('d2d280'), true)).toThrow();
    expect(() => decode(hex('81d280'), true)).toThrow();
    expect(() => decode(hex('d380'), true)).toThrow();
    expect(() => decode(hex('d200'), true)).toThrow();
  });
  test('preserves UTF-8 BOM as text instead of silently changing a map key', () => {
    expect(decode(hex('63efbbbf'))).toBe('\ufeff');
  });
  test.each([
    '', 'ff', '00ff', '18', '1c', '1f', '3f', '1b0020000000000000', '3b001fffffffffffff',
    'f4', 'f5', 'f7', 'f800', 'f90000', 'fa00000000', 'fb0000000000000000',
    'a20100180101', // Duplicate integer keys with different wire encodings.
    'bf6161007f6161ff01ff', // Duplicate text key with indefinite encoding.
    'a14000', 'a18000', // Unsupported binary/array keys.
    'bf01ff', '9f00', 'bf0100', '5f4100', '5f5fff', '5f6100ff',
    '7f4100ff', '7f61c261a2ff', '61ff', '62c080', '63eda080', // Invalid UTF-8/chunks.
    '590100', '9b00000000ffffffff', 'bb00000000ffffffff',
  ])('rejects malformed or ambiguous bytes %s', value => {
    expect(() => decode(hex(value), true)).toThrow('Invalid attestation CBOR');
  });
  test('bounds size, depth and item count before allocation', () => {
    expect(() => decode(new Uint8Array(16385))).toThrow();
    expect(() => decode(hex('81'.repeat(17) + '00'))).toThrow();
    expect(() => decode(hex('990800' + '00'.repeat(2048)))).toThrow();
    expect(() => decode(null as unknown as Uint8Array)).toThrow();
  });
});
