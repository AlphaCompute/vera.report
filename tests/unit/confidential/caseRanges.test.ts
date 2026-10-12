import { createHash } from 'node:crypto';
import { collectGrantedCaseRanges } from '../../../enclave/src/confidential/caseRanges';
import type { CaseRangeDescriptor, CaseCiphertextRange } from '../../../enclave/src/confidential/caseRanges';

const ciphertext = Buffer.from('synthetic ciphertext '.repeat(16000));
const expected: CaseRangeDescriptor = { caseId: '1'.repeat(64), objectId: '2'.repeat(64), scope: 'evidence',
  keyEpoch: 1, objectRevision: 1, totalBytes: ciphertext.length,
  ciphertextDigest: createHash('sha256').update(ciphertext).digest('hex') };
function range(offset: number, length: number): CaseCiphertextRange {
  return { ...expected, offset, chunk: ciphertext.subarray(offset, offset + length).toString('base64'), recipientEnvelope: 'synthetic encrypted envelope' };
}
test('collects bounded sequential ranges and returns only the complete digest-matching ciphertext', async () => {
  const calls: number[][] = [];
  const result = await collectGrantedCaseRanges(expected, async (offset, length) => {
    calls.push([offset, length]); return range(offset, length);
  });
  expect(calls).toEqual([[0, 131072], [131072, 131072], [262144, ciphertext.length - 262144]]);
  expect(result).toEqual({ ciphertext: ciphertext.toString(), recipientEnvelope: 'synthetic encrypted envelope' });
});
test.each(['caseId', 'objectId', 'scope', 'keyEpoch', 'objectRevision', 'totalBytes', 'ciphertextDigest', 'offset'] as const)(
  'rejects substituted %s', async field => {
    await expect(collectGrantedCaseRanges(expected, async (offset, length) => {
      const row = range(offset, length);
      return { ...row, [field]: typeof row[field] === 'number' ? (row[field] as number) + 1 : 'changed' } as CaseCiphertextRange;
    })).rejects.toThrow();
  });
test('rejects mixed recipient envelopes and corrupt same-length ciphertext', async () => {
  await expect(collectGrantedCaseRanges(expected, async (offset, length) => ({ ...range(offset, length),
    recipientEnvelope: offset ? 'different envelope' : 'original envelope' }))).rejects.toThrow();
  await expect(collectGrantedCaseRanges(expected, async (offset, length) => {
    const row = range(offset, length), corrupted = Buffer.from(row.chunk, 'base64'); corrupted[0] ^= 1;
    return { ...row, chunk: corrupted.toString('base64') };
  })).rejects.toThrow();
});
test('rejects short, noncanonical and extra-field responses', async () => {
  for (const alter of [
    (row: CaseCiphertextRange) => ({ ...row, chunk: row.chunk.slice(4) }),
    (row: CaseCiphertextRange) => ({ ...row, chunk: '\n' + row.chunk.slice(1) }),
    (row: CaseCiphertextRange) => ({ ...row, privateField: 'not allowed' }),
  ]) await expect(collectGrantedCaseRanges(expected, async (offset, length) => alter(range(offset, length)))).rejects.toThrow();
});
test('stops on cancellation or transport failure without returning partial bytes', async () => {
  const controller = new AbortController(); let calls = 0;
  await expect(collectGrantedCaseRanges(expected, async (offset, length) => {
    calls++; controller.abort(); return range(offset, length);
  }, controller.signal)).rejects.toThrow();
  expect(calls).toBe(1);
  await expect(collectGrantedCaseRanges(expected, async () => { throw new Error('private backend diagnostic'); }))
    .rejects.toThrow('Unable to assemble confidential case object');
});
test('bounds allocation and snapshots expected metadata', async () => {
  const fetch = jest.fn(async (offset: number, length: number) => range(offset, length));
  await expect(collectGrantedCaseRanges({ ...expected, totalBytes: 16 * 1024 * 1024 + 1 }, fetch)).rejects.toThrow();
  expect(fetch).not.toHaveBeenCalled();
  const mutable = { ...expected };
  const result = await collectGrantedCaseRanges(mutable, async (offset, length) => {
    mutable.ciphertextDigest = '0'.repeat(64); mutable.keyEpoch = 2;
    return range(offset, length);
  });
  expect(result.ciphertext).toBe(ciphertext.toString());
});
