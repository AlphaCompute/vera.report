import { createMessage, readKey, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';

/** Machine-readable withdrawal and expiry of confidential backend releases.
 *
 * A release team signs a short-lived list offline with a dedicated withdrawal
 * key. Its public key is pinned in the measured configuration (enclave) and in
 * the frontend build (participant devices). The host only delivers the bytes.
 *
 * - A withdrawn release is PAUSED: the enclave refuses every case operation and
 *   participant devices refuse to open sessions to it. Nothing moves a case to
 *   another release: each owner still has to approve a replacement explicitly.
 * - Every list expires (at most 72 hours after issue). If the host stops
 *   delivering a fresh list, pinned verifiers pause rather than keep trusting a
 *   stale one.
 * - A replayed older list is refused by sequence number against the verifier's
 *   floor: the highest sequence it has verified. Browsers persist that floor
 *   (and the newest list) across reloads through a WithdrawalFloorStore, so a
 *   host cannot serve them an older, still unexpired list that omits a later
 *   withdrawal. The enclave has no storage the host cannot roll back, so after
 *   a restart its floor starts again from the lists it is served: that residual
 *   replay window is bounded by the 72-hour maximum validity (see
 *   CONFIDENTIAL-CASE-ARCHITECTURE.md, "Release withdrawal replay").
 * - Availability is not a goal: an operator can always pause service. The list
 *   only prevents silently continuing on a release its publisher withdrew.
 */
export const RELEASE_WITHDRAWALS_FORMAT = 'vera-confidential-withdrawals/v1';
export const MAX_WITHDRAWAL_VALIDITY_MS = 72 * 60 * 60 * 1000;
export const WITHDRAWAL_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 1024;
const MAX_WIRE = 256 * 1024;
export const WITHDRAWAL_REASONS = ['security', 'defect', 'retired'] as const;
export type WithdrawalReason = typeof WITHDRAWAL_REASONS[number];

export type ReleaseWithdrawal = { releaseDigest: string; reason: WithdrawalReason; withdrawnAt: number };
export type ReleaseWithdrawalList = {
  format: typeof RELEASE_WITHDRAWALS_FORMAT;
  sequence: number;
  issuedAt: number;
  expiresAt: number;
  withdrawn: ReleaseWithdrawal[];
};

/** Distinct from "unavailable": the release this device would use was withdrawn
 * by its publisher, or no current withdrawal list could be verified. */
export class ConfidentialReleaseWithdrawnError extends Error {
  readonly code = 'release-withdrawn';
  constructor(readonly withdrawal: ReleaseWithdrawal | null = null) {
    super(withdrawal
      ? 'This version of the secure service has been withdrawn and is paused. Nothing was sent.'
      : 'The secure service could not confirm this version is still approved. It is paused and nothing was sent.');
    this.name = 'ConfidentialReleaseWithdrawnError';
  }
}

function invalid(): never { throw new Error('Invalid release withdrawal list'); }
function exact(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index])) invalid();
  return value as Record<string, unknown>;
}
function time(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > 8640000000000000) invalid();
  return value as number;
}

/** Strict parser; field order is fixed so the signed bytes are canonical. */
export function parseReleaseWithdrawalList(value: unknown): ReleaseWithdrawalList {
  const list = exact(value, ['format', 'sequence', 'issuedAt', 'expiresAt', 'withdrawn']);
  if (list.format !== RELEASE_WITHDRAWALS_FORMAT || !Number.isSafeInteger(list.sequence) || (list.sequence as number) < 1 ||
      !Array.isArray(list.withdrawn) || list.withdrawn.length > MAX_ENTRIES) invalid();
  const issuedAt = time(list.issuedAt), expiresAt = time(list.expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_WITHDRAWAL_VALIDITY_MS) invalid();
  let previous = '';
  const withdrawn = (list.withdrawn as unknown[]).map(item => {
    const entry = exact(item, ['releaseDigest', 'reason', 'withdrawnAt']);
    if (typeof entry.releaseDigest !== 'string' || !/^[a-f0-9]{64}$/.test(entry.releaseDigest) ||
        entry.releaseDigest <= previous || !(WITHDRAWAL_REASONS as readonly unknown[]).includes(entry.reason)) invalid();
    const withdrawnAt = time(entry.withdrawnAt);
    if (withdrawnAt > issuedAt) invalid();
    previous = entry.releaseDigest;
    return { releaseDigest: entry.releaseDigest, reason: entry.reason as WithdrawalReason, withdrawnAt };
  });
  return { format: RELEASE_WITHDRAWALS_FORMAT, sequence: list.sequence as number, issuedAt, expiresAt, withdrawn };
}

export function canonicalReleaseWithdrawalList(list: ReleaseWithdrawalList): string {
  return JSON.stringify(parseReleaseWithdrawalList(list));
}

/** Offline release-team operation. Entries are sorted by digest here. */
export async function signReleaseWithdrawalList(list: ReleaseWithdrawalList, key: PrivateKey): Promise<string> {
  const sorted = { ...list, withdrawn: [...list.withdrawn].sort((a, b) => a.releaseDigest < b.releaseDigest ? -1 : 1) };
  const canonical = canonicalReleaseWithdrawalList(sorted);
  const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(canonical) }),
    signingKeys: key, detached: true, format: 'armored' });
  return JSON.stringify({ list: JSON.parse(canonical), signature });
}

export async function readWithdrawalPublicKey(armored: string): Promise<PublicKey> {
  try {
    if (typeof armored !== 'string' || armored.length > 16384 || !armored.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) invalid();
    const key = await readKey({ armoredKey: armored });
    if (key.isPrivate()) invalid();
    await key.getSigningKey();
    return key;
  } catch { return invalid(); }
}

/** Verifies signature, canonical form, freshness and monotonic sequence. */
export async function verifyReleaseWithdrawalList(wire: string, publicKey: PublicKey,
  options: { now: number; minimumSequence?: number }): Promise<ReleaseWithdrawalList> {
  try {
    if (typeof wire !== 'string' || !wire.length || wire.length > MAX_WIRE) invalid();
    const value = JSON.parse(wire);
    const envelope = exact(value, ['list', 'signature']);
    if (typeof envelope.signature !== 'string' || envelope.signature.length > 16384) invalid();
    const list = parseReleaseWithdrawalList(envelope.list);
    const canonical = JSON.stringify(list);
    if (JSON.stringify(envelope.list) !== canonical) invalid();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(canonical) }),
      signature: await readSignature({ armoredSignature: envelope.signature }), verificationKeys: publicKey,
      expectSigned: true, format: 'binary' });
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
    if (list.issuedAt > options.now + WITHDRAWAL_CLOCK_SKEW_MS || options.now >= list.expiresAt) invalid();
    if (options.minimumSequence !== undefined && list.sequence < options.minimumSequence) invalid();
    return list;
  } catch { return invalid(); }
}

export function releaseWithdrawal(list: ReleaseWithdrawalList, releaseDigest: string): ReleaseWithdrawal | null {
  return list.withdrawn.find(entry => entry.releaseDigest === releaseDigest) ?? null;
}

/** Durable floor for one verifier and one pinned key. `save` must never lower
 * a stored sequence (the monitor only ever offers higher ones, and the store
 * re-checks). Failures are swallowed by the monitor: without durable storage the
 * verifier falls back to its in-memory floor. */
export type WithdrawalFloorStore = {
  load(): { sequence: number; wire: string | null } | null;
  save(sequence: number, wire: string): void;
};

/** Tracks the newest verified list for one verifier (enclave process or browser).
 * A list with a lower sequence than the floor is refused: the floor is the
 * highest sequence seen in this process, raised to the store's persisted value. */
export function createWithdrawalMonitor(publicKey: PublicKey, options: { store?: WithdrawalFloorStore } = {}) {
  let highest = 0;
  let current: ReleaseWithdrawalList | null = null;
  const usable = (list: ReleaseWithdrawalList | null, now: number, floor: number): list is ReleaseWithdrawalList =>
    !!list && list.sequence >= floor && now < list.expiresAt && list.issuedAt <= now + WITHDRAWAL_CLOCK_SKEW_MS;
  const persisted = () => {
    try {
      const value = options.store?.load() ?? null;
      return value && Number.isSafeInteger(value.sequence) && value.sequence > 0 ? value : null;
    } catch { return null; }
  };
  return {
    /** Throws ConfidentialReleaseWithdrawnError when `releaseDigest` must be paused. */
    async check(wire: string | null, releaseDigest: string, now: number): Promise<ReleaseWithdrawalList> {
      const stored = persisted();
      const floor = Math.max(highest, stored?.sequence ?? 0);
      let list: ReleaseWithdrawalList | null = null, accepted: string | null = null;
      try {
        if (wire === null) invalid();
        list = await verifyReleaseWithdrawalList(wire, publicKey, { now, minimumSequence: floor });
        accepted = wire;
      } catch {
        // Keep the newest verified list (this process, else the persisted one)
        // until it expires; never fall below the floor; otherwise pause.
        if (usable(current, now, floor)) list = current;
        else if (stored?.wire) {
          try { list = await verifyReleaseWithdrawalList(stored.wire, publicKey, { now, minimumSequence: floor }); }
          catch { list = null; }
        }
        if (!list) throw new ConfidentialReleaseWithdrawnError(null);
      }
      // Signature verification yields. Another check (or another browser tab's
      // durable store) may have accepted a newer withdrawal in the meantime.
      // Reconcile against the live floor before publishing any result.
      const latestFloor = Math.max(highest, persisted()?.sequence ?? 0, floor);
      if (list.sequence < latestFloor) {
        if (!usable(current, now, latestFloor)) throw new ConfidentialReleaseWithdrawnError(null);
        list = current;
        accepted = null;
      }
      highest = Math.max(latestFloor, list.sequence);
      current = list;
      if (accepted !== null && list.sequence > (stored?.sequence ?? 0)) {
        try { options.store?.save(list.sequence, accepted); } catch { /* In-memory floor still applies. */ }
      }
      const withdrawn = releaseWithdrawal(list, releaseDigest);
      if (withdrawn) throw new ConfidentialReleaseWithdrawnError(withdrawn);
      return list;
    },
    current: () => current,
    highestSequence: () => highest,
  };
}
