import { CASE_CHALLENGE_BATCH, MAX_SESSION_CHALLENGES, createSessionChallenges } from '../../../enclave/src/session-challenges';

const id = (n: number) => n.toString(16).padStart(64, '0');

describe('per-session challenge ledger (enclave memory)', () => {
  test('only the immediate follow-up pins eviction; consumption, expiry and clear release it', () => {
    const ledger = createSessionChallenges();
    ledger.add(id(1), 100, 10, true);
    ledger.add(id(2), 100, 10);
    expect(ledger.hasPendingFollowup()).toBe(true);
    expect(ledger.consume(id(1), 20)).toBe(true);
    expect(ledger.hasPendingFollowup()).toBe(false);
    expect(ledger.outstanding(20)).toBe(1);
    ledger.add(id(3), 100, 20, true);
    expect(ledger.outstanding(100)).toBe(0);
    expect(ledger.hasPendingFollowup()).toBe(false);
    ledger.add(id(4), 200, 100, true);
    ledger.clear();
    expect(ledger.hasPendingFollowup()).toBe(false);
  });

  test('a challenge is single use, only while unexpired', () => {
    const ledger = createSessionChallenges();
    ledger.add(id(1), 100, 10);
    expect(ledger.consume(id(1), 20)).toBe(true);
    expect(ledger.consume(id(1), 20)).toBe(false);
    ledger.add(id(2), 100, 10);
    expect(ledger.consume(id(2), 100)).toBe(false); // Expired at its deadline.
    expect(ledger.consume(id(2), 20)).toBe(false); // And gone, not revived.
    expect(ledger.consume(id(3), 20)).toBe(false); // Never issued here.
  });

  test('outstanding challenges are bounded; expired ones free their slot', () => {
    const ledger = createSessionChallenges();
    for (let n = 0; n < MAX_SESSION_CHALLENGES; n++) ledger.add(id(n + 1), 100, 10);
    expect(() => ledger.add(id(99), 100, 10)).toThrow('limit');
    expect(ledger.outstanding(10)).toBe(MAX_SESSION_CHALLENGES);
    expect(ledger.outstanding(100)).toBe(0);
    ledger.add(id(99), 200, 100);
    expect(CASE_CHALLENGE_BATCH).toBeLessThanOrEqual(MAX_SESSION_CHALLENGES);
  });

  test('rejects malformed, duplicate and already-expired challenges; clear empties it', () => {
    const ledger = createSessionChallenges();
    expect(() => ledger.add('not-hex', 100, 10)).toThrow();
    expect(() => ledger.add(id(1), 10, 10)).toThrow();
    expect(() => ledger.add(id(1), 1.5, 1)).toThrow();
    ledger.add(id(1), 100, 10);
    expect(() => ledger.add(id(1), 100, 10)).toThrow();
    ledger.clear();
    expect(ledger.consume(id(1), 20)).toBe(false);
  });
});
