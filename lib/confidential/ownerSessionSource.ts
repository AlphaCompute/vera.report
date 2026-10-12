import type { CheckpointPin } from '@/enclave/src/confidential/recovery';

/** What an owner session was restored from. A newer recovery file (or a newer
 * checkpoint pin) for the same recovery code is a different source: reusing the
 * session restored from the older one would silently ignore the newer file and
 * its newer pin, which is exactly what the rollback/refused recovery copy tells
 * the reporter to open. */
export type OwnerSessionSource = {
  recoveryCode: string;
  recoveryPackage: string | null;
  savedPin: CheckpointPin | undefined;
};

type Ref<T> = { current: T };

const samePin = (a: CheckpointPin | undefined, b: CheckpointPin | undefined) =>
  a === b || (!!a && !!b && a.caseId === b.caseId && a.ownerFingerprint === b.ownerFingerprint &&
    a.revision === b.revision && a.keyEpoch === b.keyEpoch && a.digest === b.digest);

export function sameOwnerSessionSource(a: OwnerSessionSource | null, b: OwnerSessionSource): boolean {
  return !!a && a.recoveryCode === b.recoveryCode && a.recoveryPackage === b.recoveryPackage && samePin(a.savedPin, b.savedPin);
}

/** Returns the held session when it was restored from exactly `source`.
 * Otherwise releases the held session (its channel sessions and progress
 * callback) and restores a fresh one from `source`. `restore` returns null when
 * the load was superseded; nothing is stored then. */
export async function ownerSessionFor<S>(
  held: { session: Ref<S | null>; source: Ref<OwnerSessionSource | null> },
  source: OwnerSessionSource,
  restore: (source: OwnerSessionSource) => Promise<S | null>,
  release: (session: S) => void,
): Promise<S | null> {
  const current = held.session.current;
  if (current && sameOwnerSessionSource(held.source.current, source)) return current;
  if (current) {
    held.session.current = null;
    held.source.current = null;
    release(current);
  }
  const restored = await restore(source);
  if (!restored) return null;
  held.session.current = restored;
  held.source.current = source;
  return restored;
}
