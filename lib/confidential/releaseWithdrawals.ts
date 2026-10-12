import {
  ConfidentialReleaseWithdrawnError, createWithdrawalMonitor, readWithdrawalPublicKey,
} from '../../enclave/src/confidential/releaseWithdrawals';
import type { ReleaseWithdrawal, ReleaseWithdrawalList, WithdrawalFloorStore } from '../../enclave/src/confidential/releaseWithdrawals';
export { ConfidentialReleaseWithdrawnError } from '../../enclave/src/confidential/releaseWithdrawals';

/** Participant-device side of release withdrawal (owner status, report submit,
 * legal portal, onboarding). The withdrawal public key is pinned in the build
 * (NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY, base64 of the armored key); the
 * signed list comes from the untrusted host. When a key is pinned:
 *  - a withdrawn release is refused before any session opens (nothing is sent);
 *  - with no current verified list the release is treated as paused;
 *  - nothing here approves or selects another release: that stays an explicit
 *    owner decision through Approve update.
 * With no key pinned the check is reported as not configured.
 *
 * Replay: the highest verified sequence and that list are kept in localStorage
 * per pinned key (WITHDRAWAL_FLOOR_PREFIX + key fingerprint) and never lowered,
 * so after a reload or in another tab the host cannot serve an older, still
 * unexpired list that omits a later withdrawal. It holds only the public signed
 * list: no case, organization or account data. "Forget this device" removes it,
 * which returns this browser to the state of a fresh device. */
export const WITHDRAWAL_FLOOR_PREFIX = 'vera-confidential-withdrawals/v1:';
const MAX_STORED_WIRE = 256 * 1024;
const REUSE_MS = 60_000;
type Source = () => Promise<string | null>;
type State = { configured: false } | {
  configured: true; checkedAt: number | null; list: ReleaseWithdrawalList | null;
  paused: ReleaseWithdrawal | 'unconfirmed' | null;
};

let override: string | null | undefined;
let monitor: { armored: string; monitor: ReturnType<typeof createWithdrawalMonitor> } | null = null;
let last: { at: number; digest: string } | null = null;
let state: State = { configured: false };

function decodeKey(value: string | undefined): string | null {
  if (!value || !value.trim()) return null;
  try {
    const text = typeof atob === 'function' ? atob(value.trim()) : Buffer.from(value.trim(), 'base64').toString('utf8');
    return text.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') ? text : null;
  } catch { return null; }
}

/** Build-pinned key (literal reference so Next inlines it), or the test override. */
export function withdrawalPublicKey(): string | null {
  if (override !== undefined) return override;
  return decodeKey(process.env.NEXT_PUBLIC_CONFIDENTIAL_WITHDRAWAL_KEY);
}

/** Tests and tools: pin a key (armored) or disable checks (null); undefined restores the build value. */
export function configureReleaseWithdrawals(armored: string | null | undefined): void {
  override = armored; monitor = null; last = null;
  state = withdrawalPublicKey() ? { configured: true, checkedAt: null, list: null, paused: null } : { configured: false };
}

export function releaseWithdrawalState(): State {
  if (!state.configured && withdrawalPublicKey()) state = { configured: true, checkedAt: null, list: null, paused: null };
  return state;
}

function localStore(): Storage | null {
  try { return typeof window === 'undefined' ? null : window.localStorage; } catch { return null; }
}

/** localStorage floor for one pinned key. Reads tolerate a malformed entry (it
 * is ignored, and the in-memory floor still applies); writes only ever raise it. */
export function browserWithdrawalFloorStore(fingerprint: string): WithdrawalFloorStore {
  const slot = WITHDRAWAL_FLOOR_PREFIX + fingerprint;
  const load = () => {
    const raw = localStore()?.getItem(slot);
    if (!raw || raw.length > MAX_STORED_WIRE + 64) return null;
    const value = JSON.parse(raw) as unknown;
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const { sequence, wire } = value as Record<string, unknown>;
    if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) return null;
    return { sequence: sequence as number, wire: typeof wire === 'string' && wire.length <= MAX_STORED_WIRE ? wire : null };
  };
  return {
    load,
    save(sequence, wire) {
      const storage = localStore();
      if (!storage || wire.length > MAX_STORED_WIRE) return;
      let existing: number;
      try { existing = load()?.sequence ?? 0; } catch { existing = 0; }
      if (sequence <= existing) return;
      storage.setItem(slot, JSON.stringify({ sequence, wire }));
    },
  };
}

/** Default source: GET /api/confidential/release-withdrawals (404 = none published). */
export const fetchReleaseWithdrawals: Source = async () => {
  const response = await fetch('/api/confidential/release-withdrawals', { cache: 'no-store', credentials: 'omit' });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error();
  const text = await response.text();
  return text.length <= 256 * 1024 ? text : null;
};

/** Throws ConfidentialReleaseWithdrawnError when the release must be treated as paused.
 * Callers pass `trustedNow()` (attested enclave time), never the raw device clock. */
export async function assertReleaseNotWithdrawn(releaseDigest: string, now: number, source: Source = fetchReleaseWithdrawals): Promise<void> {
  const armored = withdrawalPublicKey();
  if (!armored) { state = { configured: false }; return; }
  if (!monitor || monitor.armored !== armored) {
    const key = await readWithdrawalPublicKey(armored);
    monitor = { armored, monitor: createWithdrawalMonitor(key, { store: browserWithdrawalFloorStore(key.getFingerprint()) }) };
  }
  const current = monitor.monitor.current();
  // `now` is attested enclave time (`trustedNow`). A cached result is reused
  // only forward in time: a check recorded on a clock that later moved back
  // (for example before the first session verified) is not reused.
  if (last && last.digest === releaseDigest && now >= last.at && now - last.at < REUSE_MS && current && now < current.expiresAt) return;
  let wire: string | null = null;
  try { wire = await source(); } catch { wire = null; }
  try {
    const list = await monitor.monitor.check(wire, releaseDigest, now);
    last = { at: now, digest: releaseDigest };
    state = { configured: true, checkedAt: now, list, paused: null };
  } catch (error) {
    last = null;
    const withdrawal = error instanceof ConfidentialReleaseWithdrawnError ? error.withdrawal : null;
    state = { configured: true, checkedAt: now, list: monitor.monitor.current(), paused: withdrawal ?? 'unconfirmed' };
    throw error instanceof ConfidentialReleaseWithdrawnError ? error : new ConfidentialReleaseWithdrawnError(null);
  }
}

/** Keep the paused-release error distinct when wrapping other failures. */
export function isReleasePaused(error: unknown): error is ConfidentialReleaseWithdrawnError {
  return error instanceof ConfidentialReleaseWithdrawnError;
}
