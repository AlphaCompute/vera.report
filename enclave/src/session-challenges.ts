/** Single-use participant challenges held in enclave memory for ONE attested
 * application-channel session.
 *
 * A session may carry several sequential operations (see
 * application-channel-sessions.ts). Every authenticated operation still signs a
 * fresh challenge, and that challenge must have been issued inside the same
 * session and not yet used. Because the ledger lives in enclave memory, the
 * untrusted host store cannot re-insert a consumed challenge, and a challenge
 * cannot move to another session (the proof is also bound to the session nonce
 * and key). Challenges die with the session: expiry, failure, restart or close.
 */
export type SessionChallenges = {
  /** Record an enclave-generated challenge. Throws when the session already holds
   * the maximum number of unexpired, unused challenges. */
  add(challenge: string, expiresAt: number, now: number, protectFollowup?: boolean): void;
  /** Atomically remove the challenge; true only if it was present and unexpired. */
  consume(challenge: string, now: number): boolean;
  /** Unused, unexpired challenges (for admission checks and tests). */
  outstanding(now: number): number;
  /** A just-issued challenge whose immediate proof has not arrived yet.
   * Expiry is pruned with the case service's clock; session idle deadlines
   * independently bound this hold without consulting host wall time. */
  hasPendingFollowup(): boolean;
  clear(): void;
};

/** Upper bound on unused challenges per session. Clients request a small batch
 * (CASE_CHALLENGE_BATCH) and spend them on the next operations of that session. */
export const MAX_SESSION_CHALLENGES = 16;
/** Largest batch one challenge request may ask for. */
export const CASE_CHALLENGE_BATCH = 8;
const ID = /^[a-f0-9]{64}$/;

export function createSessionChallenges(): SessionChallenges {
  const issued = new Map<string, number>();
  const followups = new Set<string>();
  function prune(now: number) {
    for (const [challenge, expiresAt] of issued) if (expiresAt <= now) { issued.delete(challenge); followups.delete(challenge); }
  }
  return {
    add(challenge, expiresAt, now, protectFollowup = false) {
      if (typeof challenge !== 'string' || !ID.test(challenge) || !Number.isSafeInteger(expiresAt) ||
          !Number.isSafeInteger(now) || expiresAt <= now) throw new Error('Invalid session challenge');
      prune(now);
      if (issued.has(challenge) || issued.size >= MAX_SESSION_CHALLENGES) throw new Error('Session challenge limit reached');
      issued.set(challenge, expiresAt);
      if (protectFollowup) followups.add(challenge);
    },
    consume(challenge, now) {
      if (typeof challenge !== 'string' || !issued.has(challenge)) return false;
      const expiresAt = issued.get(challenge)!;
      issued.delete(challenge); // Single use even when the caller then fails.
      followups.delete(challenge);
      return Number.isSafeInteger(now) && expiresAt > now;
    },
    outstanding(now) { prune(now); return issued.size; },
    hasPendingFollowup() { return followups.size > 0; },
    clear() { issued.clear(); followups.clear(); },
  };
}
