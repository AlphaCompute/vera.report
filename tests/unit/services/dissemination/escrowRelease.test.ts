/**
 * Evidence-escrow token — the HMAC-signed, time-limited "verified link" an
 * agency uses to reach consent-gated evidence (VERA-PDR-001 §10 / FR-5).
 *
 * These are the security properties that make the link trustworthy: it round
 * trips, it cannot be forged or tampered, it expires, and it is bound to the
 * signing secret. If any of these break, an agency link becomes a bypass.
 */
import {
  makeEscrowToken,
  verifyEscrowToken,
  escrowUrl,
} from '../../../../src/services/dissemination/escrowRelease';

const ORIGINAL_ENV = process.env;
beforeEach(() => {
  process.env = { ...ORIGINAL_ENV, DISSEMINATION_WEBHOOK_SECRET: 'test-secret-abc' };
});
afterEach(() => {
  process.env = ORIGINAL_ENV;
});

describe('escrow token', () => {
  it('round-trips to the correct scope', () => {
    const token = makeEscrowToken('VRA-347931AB816E53F1', 'cisa', 'submission-binding');
    const scope = verifyEscrowToken(token);
    expect(scope).not.toBeNull();
    expect(scope!.kind).toBe('escrow');
    expect(scope!.trackingId).toBe('VRA-347931AB816E53F1');
    expect(scope!.entityId).toBe('cisa');
    expect(typeof scope!.exp).toBe('number');
    expect(scope!.exp).toBeGreaterThan(Date.now());
  });

  it('rejects a tampered payload', () => {
    const token = makeEscrowToken('VRA-1', 'cisa', 'submission-binding');
    const [payload, sig] = token.split('.');
    // Flip the last payload char — signature no longer matches.
    const flipped = payload.slice(0, -1) + (payload.slice(-1) === 'A' ? 'B' : 'A');
    expect(verifyEscrowToken(`${flipped}.${sig}`)).toBeNull();
  });

  it('rejects a forged signature', () => {
    const token = makeEscrowToken('VRA-1', 'cisa', 'submission-binding');
    const [payload] = token.split('.');
    expect(verifyEscrowToken(`${payload}.not-a-real-signature`)).toBeNull();
  });

  it('rejects an expired token', () => {
    const token = makeEscrowToken('VRA-1', 'cisa', 'submission-binding', -1); // exp one day in the past
    expect(verifyEscrowToken(token)).toBeNull();
  });

  it('rejects malformed tokens', () => {
    expect(verifyEscrowToken('')).toBeNull();
    expect(verifyEscrowToken('no-dot-here')).toBeNull();
    expect(verifyEscrowToken('.onlysig')).toBeNull();
    expect(verifyEscrowToken('garbage.garbage')).toBeNull();
  });

  it('rejects a token signed with a different secret', () => {
    const token = makeEscrowToken('VRA-1', 'cisa', 'submission-binding');
    process.env.RECIPIENT_CAPABILITY_SECRET = 'a-different-independent-secret-for-test';
    expect(verifyEscrowToken(token)).toBeNull();
  });

  it('builds an escrow URL that verifies', () => {
    process.env.APP_BASE_URL = 'https://vera.report';
    const { url, token } = escrowUrl('VRA-1', 'epa-oig', 'submission-binding');
    expect(url).toBe(`https://vera.report/api/dissemination/escrow/${token}`);
    expect(verifyEscrowToken(token)?.entityId).toBe('epa-oig');
  });

  it('cannot mint or verify without the signing secret', () => {
    delete process.env.RECIPIENT_CAPABILITY_SECRET;
    expect(() => makeEscrowToken('VRA-1', 'cisa', 'submission-binding')).toThrow(/RECIPIENT_CAPABILITY_SECRET/);
    // A previously valid token can't be verified either once the secret is gone.
    expect(verifyEscrowToken('anypayload.anysig')).toBeNull();
  });
});
