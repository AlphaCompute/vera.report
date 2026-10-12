import { parseMetadataSelection } from '../../../src/utils/metadataSelection';

test('accepts missing and legacy boolean-map selections', () => {
  expect(parseMetadataSelection(undefined)).toEqual({}); expect(parseMetadataSelection('')).toEqual({});
  expect(parseMetadataSelection('{"gps_location":true,"artist":false}')).toEqual({ gps_location: true, artist: false });
});

test.each(['null', '[]', 'true', '1', '"identity-canary"', '{"gps_location":null}', '{"gps_location":{"nested":true}}', 'identity-canary-invalid-json', ['{}'], 0])('rejects invalid shapes without reflecting raw values (%s)', raw => {
  expect(() => parseMetadataSelection(raw)).toThrow('stripSelection must be a JSON object of boolean values.');
  try { parseMetadataSelection(raw); } catch (error) { expect(String(error)).not.toContain('identity-canary'); }
});

test('bounds field count, key length and total input', () => {
  expect(() => parseMetadataSelection(JSON.stringify(Object.fromEntries(Array.from({ length: 129 }, (_, i) => [String(i), true]))))).toThrow();
  expect(() => parseMetadataSelection(JSON.stringify({ ['x'.repeat(257)]: true }))).toThrow();
  expect(() => parseMetadataSelection(' '.repeat(16_385))).toThrow();
});
