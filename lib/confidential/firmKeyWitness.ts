import witness from './firmKeyWitness.json';

/** Optional source-history pins for approved organization keys. A recorded key
 * must agree with the onboarding-authority registration verified by the enclave.
 * No firm website is contacted and a new approved organization needs no bundled
 * entry. Existing pins still block silent key replacement until reviewed.
 */
export type FirmKeyWitnessEntry = { domain: string; organizationId: string; recipientKeyId: string; recordedAt: string };
export type WitnessStatus = 'recorded' | 'unrecorded' | 'mismatch';

const HEX64 = /^[a-f0-9]{64}$/;

export function parseFirmKeyWitness(value: unknown): FirmKeyWitnessEntry[] {
  const document = value as { format?: unknown; firms?: unknown };
  if (!document || document.format !== 'vera-firm-key-witness/v1' || !Array.isArray(document.firms) || document.firms.length > 1000) {
    throw new Error('Invalid firm key witness');
  }
  const seen = new Set<string>();
  return document.firms.map(item => {
    const entry = item as FirmKeyWitnessEntry;
    if (!entry || Object.keys(entry).sort().join(',') !== 'domain,organizationId,recipientKeyId,recordedAt' ||
        typeof entry.domain !== 'string' || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(entry.domain) ||
        !HEX64.test(entry.organizationId) || !HEX64.test(entry.recipientKeyId) || typeof entry.recordedAt !== 'string' ||
        Number.isNaN(Date.parse(entry.recordedAt)) || seen.has(entry.organizationId)) throw new Error('Invalid firm key witness');
    seen.add(entry.organizationId);
    return { ...entry };
  });
}

let bundled: FirmKeyWitnessEntry[] | null = null;
function entries(): FirmKeyWitnessEntry[] {
  // A malformed bundled list trusts nothing extra: every firm reads as unrecorded.
  if (!bundled) { try { bundled = parseFirmKeyWitness(witness); } catch { bundled = []; } }
  return bundled;
}

/** Status of a registration-confirmed firm key against the witnessed record. */
export function witnessStatus(firm: { organizationId: string; domain: string; recipientKeyId: string },
  list: readonly FirmKeyWitnessEntry[] = entries()): WitnessStatus {
  const entry = list.find(item => item.organizationId === firm.organizationId);
  if (!entry) return 'unrecorded';
  return entry.domain === firm.domain && entry.recipientKeyId === firm.recipientKeyId ? 'recorded' : 'mismatch';
}
