import { webcrypto } from 'node:crypto';

// Attestation is replaced by a synthetic verified result carrying the "enclave"
// (NSM) time; the subject is how the browser anchors and uses that time.
let enclaveTime: (() => number) | null = null;
jest.mock('../../../enclave/src/confidential/attestation', () => {
  const actual = jest.requireActual('../../../enclave/src/confidential/attestation');
  return {
    ...actual,
    verifyApplicationAttestation: (document: Uint8Array, key: Uint8Array, policy: unknown) => enclaveTime
      ? Promise.resolve({ publicKey: new Uint8Array(key), timestamp: enclaveTime(), verifiedAt: 0 })
      : actual.verifyApplicationAttestation(document, key, policy),
  };
});

import {
  attestedTimeMark, hasAttestedTime, recordAttestedTime, resetTrustedTime, setAttestedTimeClocksForTests, trustedNow, trustedTime,
} from '../../../lib/confidential/attestedTime';
import { grantActiveAt } from '../../../enclave/src/confidential/grantPolicy';
import { requestOutcome } from '../../../lib/confidential/firmSharedRequests';
import { membershipLease } from '../../../lib/confidential/firmOnboarding';
import { expiryState } from '../../../lib/confidential/accessChoices';
import { accessEnd } from '../../../lib/confidential/firmCaseView';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import {
  ConfidentialReleaseWithdrawnError, signReleaseWithdrawalList,
} from '../../../enclave/src/confidential/releaseWithdrawals';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { configureReleaseWithdrawals } from '../../../lib/confidential/releaseWithdrawals';
import { verifiedSession } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import type { SharedRequest } from '../../../enclave/src/confidential/firmSharedList';

const T = 1_800_000_000_000, MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR, YEAR = 365 * DAY;

/** A device whose wall clock and monotonic clock the test moves independently. */
function device(wall: number) {
  const state = { wall, monotonic: 1_000 };
  setAttestedTimeClocksForTests({ device: () => state.wall, monotonic: () => state.monotonic });
  return {
    /** Real time passes: both clocks advance. */
    pass(ms: number) { state.wall += ms; state.monotonic += ms; },
    /** The user or an attacker changes the wall clock only. */
    setWall(value: number) { state.wall = value; },
    /** The machine sleeps: the wall clock advances, a paused monotonic clock does not. */
    sleep(ms: number) { state.wall += ms; },
  };
}
const grant = (expiresAt: number | null, issuedAt = T - DAY) => ({ issuedAt, expiresAt });

afterEach(() => { setAttestedTimeClocksForTests(undefined); resetTrustedTime(); enclaveTime = null; configureReleaseWithdrawals(undefined); });

describe('attested time on participant devices', () => {
  test('without a verified session both readings are the device clock', () => {
    device(T);
    expect(hasAttestedTime()).toBe(false);
    expect(trustedNow()).toBe(T);
    expect(trustedTime(T + 5)).toBe(T + 5);
    expect(trustedNow(T + 5)).toBe(T + 5);
  });

  test.each([['a year behind', -YEAR], ['a year ahead', YEAR], ['a few minutes behind', -4 * MINUTE]])(
    'a device clock %s cannot make an expired grant, request or lease look valid', (_name, skew) => {
      const clock = device(T + skew);
      recordAttestedTime(T);
      clock.pass(10 * MINUTE);
      const now = trustedNow();
      expect(now).toBe(T + 10 * MINUTE);
      // Expired one minute ago in enclave time.
      expect(grantActiveAt(grant(T + 9 * MINUTE), now)).toBe(false);
      expect(expiryState(T + 9 * MINUTE, now).state).toBe('ended');
      expect(accessEnd(T + 9 * MINUTE, now)).toMatchObject({ daysLeft: 0 });
      const request = { caseId: 'c', requestId: 'r', ownerPublicKey: 'k', summary: 's', requestedAt: T - DAY,
        expiresAt: T + 9 * MINUTE, recipientKeyId: 'key', state: 'requested', updatedAt: T - DAY, grantExpiresAt: null } as SharedRequest;
      expect(requestOutcome(request, 'key', now)).toBe('expired');
      expect(requestOutcome({ ...request, state: 'granted', grantExpiresAt: T + 9 * MINUTE }, 'key', now)).toBe('expired');
      expect(membershipLease({ state: 'enrolled', leaseExpiresAt: T + 9 * MINUTE, members: 1, keyMatches: true }, now))
        .toEqual({ state: 'ended', endedAt: T + 9 * MINUTE });
      // ...and something still valid in enclave time stays valid, whatever the device says.
      expect(grantActiveAt(grant(T + 11 * MINUTE), now)).toBe(true);
      expect(requestOutcome({ ...request, expiresAt: T + 11 * MINUTE }, 'key', now)).toBe('waiting');
      expect(membershipLease({ state: 'enrolled', leaseExpiresAt: T + 30 * DAY, members: 1, keyMatches: true }, now).state).toBe('active');
      // A device-clock reading (the `now` a flow started with) maps onto the same clock.
      expect(trustedNow(T + skew + 10 * MINUTE)).toBe(now);
    });

  test('setting the device clock back after verification does not resurrect an expired grant', () => {
    const clock = device(T);
    recordAttestedTime(T);
    clock.pass(5 * MINUTE);
    clock.setWall(T - 2 * DAY);
    const now = trustedNow();
    expect(now).toBe(T + 5 * MINUTE);
    expect(grantActiveAt(grant(T + 4 * MINUTE), now)).toBe(false);
  });

  test('a paused monotonic clock (sleep) does not hold time back either', () => {
    const clock = device(T);
    recordAttestedTime(T);
    clock.sleep(8 * HOUR);
    expect(trustedNow()).toBe(T + 8 * HOUR);
    expect(grantActiveAt(grant(T + HOUR), trustedNow())).toBe(false);
  });

  test('a relay that delays its answer cannot make time lag: the round trip is credited to decisions', () => {
    const clock = device(T);
    const startedAt = attestedTimeMark();
    clock.pass(40_000);
    // The document was produced right after the nonce left, then held for 40 s.
    recordAttestedTime(T, startedAt);
    // True enclave time is now T + 40 s at most; decisions use that upper bound...
    expect(trustedNow()).toBe(T + 40_000);
    expect(grantActiveAt(grant(T + 30_000), trustedNow())).toBe(false);
    // ...so a valid grant looks expired at most one round trip early, never later.
    expect(grantActiveAt(grant(T + 41_000), trustedNow())).toBe(true);
    // Signing uses the lower bound, so statements are never "from the future".
    expect(trustedTime(T + 40_000)).toBe(T);
  });

  test('a device clock moved forward after verification fails closed (items look expired, never valid)', () => {
    const clock = device(T);
    recordAttestedTime(T);
    clock.setWall(T + DAY);
    expect(trustedNow()).toBe(T + DAY);
    expect(grantActiveAt(grant(T + HOUR), trustedNow())).toBe(false);
  });
});

describe('release withdrawal list on a wrong device clock', () => {
  const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
    sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
    eifSha256: '1'.repeat(64), imageSha256: '2'.repeat(64), provenanceSha256: '3'.repeat(64), configurationSha256: '4'.repeat(64),
    protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: '1'.repeat(96), pcr1: '2'.repeat(96), pcr2: '3'.repeat(96) } });
  beforeAll(() => { if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });

  test('an expired list accepted on a clock set back is refused as soon as the session verifies', async () => {
    const key = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'withdrawals' }], format: 'object' });
    configureReleaseWithdrawals(key.publicKey.armor());
    // Real (enclave) time is T; the list expired a day ago and omits any later withdrawal.
    const wire = await signReleaseWithdrawalList({ format: 'vera-confidential-withdrawals/v1', sequence: 5,
      issuedAt: T - 3 * DAY, expiresAt: T - DAY, withdrawn: [] }, key.privateKey);
    device(T - 2 * DAY);
    enclaveTime = () => T;
    const opened = jest.fn(async () => ({ document: new Uint8Array([1]), publicKey: new Uint8Array([1]) }));
    const relay = { stage: jest.fn(), call: jest.fn(), open: opened, withdrawals: async () => wire } as unknown as ChannelRelay;
    const error = await verifiedSession(relay, manifest, T - 2 * DAY).catch(caught => caught);
    // The device-clock pre-check passed (the relay was reached), the attested re-check did not.
    expect(opened).toHaveBeenCalledTimes(1);
    expect(error).toBeInstanceOf(ConfidentialReleaseWithdrawnError);
    expect(hasAttestedTime()).toBe(true);
    // Later sessions check on attested time before anything is sent.
    opened.mockClear();
    await expect(verifiedSession(relay, manifest)).rejects.toBeInstanceOf(ConfidentialReleaseWithdrawnError);
    expect(opened).not.toHaveBeenCalled();
  });
});
