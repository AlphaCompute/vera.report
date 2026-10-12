/** In-memory record of the last successful secure-service verification in this
 * tab, for the "Security details" disclosure. Holds only the public release ID
 * the attestation was checked against and the time; never case, organization or
 * session identifiers. Nothing is persisted or sent anywhere. */
export type VerificationRecord = { releaseDigest: string; sourceCommit: string; sourceRepository: string; verifiedAt: number };

let latest: VerificationRecord | null = null;
const listeners = new Set<() => void>();

export function recordVerification(record: VerificationRecord): void {
  if (!/^[a-f0-9]{64}$/.test(record.releaseDigest) || !Number.isSafeInteger(record.verifiedAt)) return;
  latest = { ...record };
  for (const listener of listeners) listener();
}

export function lastVerification(): VerificationRecord | null { return latest; }

export function subscribeVerification(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Tests only. */
export function resetVerificationRecord(): void { latest = null; for (const listener of listeners) listener(); }
