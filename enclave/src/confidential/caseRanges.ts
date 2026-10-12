import type { GrantedCaseObject, ObjectContext } from './caseObject.ts';
import { decodeCanonicalBase64 } from './base64.ts';

export type CaseRangeDescriptor = ObjectContext & { ciphertextDigest: string; totalBytes: number };
export type CaseCiphertextRange = CaseRangeDescriptor & {
  offset: number; chunk: string; recipientEnvelope: string;
};
const CHUNK_SIZE = 128 * 1024, MAX_OBJECT = 16 * 1024 * 1024;
function invalid(): never { throw new Error('Unable to assemble confidential case object'); }
function descriptor(input: CaseRangeDescriptor): CaseRangeDescriptor {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).sort().join(',') !== 'caseId,ciphertextDigest,keyEpoch,objectId,objectRevision,scope,totalBytes' ||
      [input.caseId, input.objectId, input.ciphertextDigest].some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) ||
      !['narrative', 'evidence', 'messages', 'identity', 'contact', 'rewards'].includes(input.scope) ||
      !Number.isSafeInteger(input.keyEpoch) || input.keyEpoch < 1 ||
      !Number.isSafeInteger(input.objectRevision) || input.objectRevision < 1 ||
      !Number.isSafeInteger(input.totalBytes) || input.totalBytes < 1 || input.totalBytes > MAX_OBJECT) invalid();
  return { caseId: input.caseId, objectId: input.objectId, scope: input.scope, keyEpoch: input.keyEpoch,
    objectRevision: input.objectRevision, ciphertextDigest: input.ciphertextDigest, totalBytes: input.totalBytes };
}

/** Browser-only collection of encrypted bytes. The descriptor must come from
 * authenticated current object metadata, and fetchRange must use a freshly
 * attested, owner-approved, authenticated read session for every range.
 * Returns ciphertext only. Call openGrantedCaseObject with current authorization
 * before rendering anything; a matching transport hash is not owner authenticity. */
export async function collectGrantedCaseRanges(input: CaseRangeDescriptor,
  fetchRange: (offset: number, length: number) => Promise<CaseCiphertextRange>, signal?: AbortSignal,
): Promise<GrantedCaseObject> {
  let collected: Uint8Array<ArrayBuffer> | undefined;
  try {
    const expected = descriptor(input);
    if (signal?.aborted || typeof fetchRange !== 'function') invalid();
    collected = new Uint8Array(expected.totalBytes);
    let envelope: string | undefined;
    for (let offset = 0; offset < expected.totalBytes; offset += CHUNK_SIZE) {
      if (signal?.aborted) invalid();
      const length = Math.min(CHUNK_SIZE, expected.totalBytes - offset);
      const response = await fetchRange(offset, length);
      if (signal?.aborted || !response || typeof response !== 'object' || Array.isArray(response) ||
          Object.keys(response).sort().join(',') !== 'caseId,chunk,ciphertextDigest,keyEpoch,objectId,objectRevision,offset,recipientEnvelope,scope,totalBytes') invalid();
      const row = { ...response };
      if (Object.entries(expected).some(([key, value]) => row[key as keyof CaseCiphertextRange] !== value) ||
          row.offset !== offset || typeof row.chunk !== 'string' || row.chunk.length !== 4 * Math.ceil(length / 3) ||
          typeof row.recipientEnvelope !== 'string' || !row.recipientEnvelope.length || row.recipientEnvelope.length > 16384 ||
          (envelope !== undefined && envelope !== row.recipientEnvelope)) invalid();
      envelope = row.recipientEnvelope;
      const bytes = decodeCanonicalBase64(row.chunk, length) ?? invalid();
      try {
        if (bytes.length !== length) invalid();
        collected.set(bytes, offset);
      } finally { bytes.fill(0); }
    }
    const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', collected));
    if (signal?.aborted || Array.from(hash, value => value.toString(16).padStart(2, '0')).join('') !== expected.ciphertextDigest) invalid();
    return { ciphertext: new TextDecoder('utf-8', { fatal: true }).decode(collected), recipientEnvelope: envelope! };
  } catch { return invalid(); } finally { collected?.fill(0); }
}
