import { sealCapability } from '../../../../src/services/dissemination/recipientCapability';
/**
 * One-time secure-packet token — the single-use, HMAC-signed link emailed to an
 * external recipient (VERA-PDR-001, reporter-reward flow). These are the
 * security properties that make it trustworthy: it round-trips, it cannot be
 * forged or tampered, it expires, it is bound to the signing secret, its `kind`
 * is checked (no cross-use of escrow/counsel payloads), and every mint carries a
 * fresh `jti` so the consumed-store can enforce single use.
 */
import crypto from 'node:crypto';
import {
  makeSecureLinkToken,
  verifySecureLinkToken,
  secureLinkUrl,
  SECURE_LINK_ENTITY_ID,
} from '../../../../src/services/dissemination/secureLink';

const ORIGINAL_ENV = process.env;
beforeEach(() => {
  process.env = { ...ORIGINAL_ENV, DISSEMINATION_WEBHOOK_SECRET: 'test-secret-abc' };
});
afterEach(() => {
  process.env = ORIGINAL_ENV;
});

/** A correctly-signed token from an arbitrary scope (for negative-path tests). */
function signScope(scope: Record<string, unknown>, secret = 'test-secret-abc'): string {
  return sealCapability('securelink', scope);
}

describe('secure-link token', () => {
  it('round-trips to the correct scope with a jti', () => {
    const token = makeSecureLinkToken('VRA-347931AB816E53F1');
    const scope = verifySecureLinkToken(token);
    expect(scope).not.toBeNull();
    expect(scope!.kind).toBe('securelink');
    expect(scope!.trackingId).toBe('VRA-347931AB816E53F1');
    expect(scope!.entityId).toBe(SECURE_LINK_ENTITY_ID);
    expect(typeof scope!.jti).toBe('string');
    expect(scope!.jti).toHaveLength(32); // 16 random bytes, hex
    expect(scope!.exp).toBeGreaterThan(Date.now());
  });

  it('mints a fresh jti every time (the single-use key)', () => {
    const a = verifySecureLinkToken(makeSecureLinkToken('VRA-1'))!;
    const b = verifySecureLinkToken(makeSecureLinkToken('VRA-1'))!;
    expect(a.jti).not.toBe(b.jti);
  });

  it('rejects a tampered payload', () => {
    const token = makeSecureLinkToken('VRA-1');
    const [payload, sig] = token.split('.');
    const flipped = payload.slice(0, -1) + (payload.slice(-1) === 'A' ? 'B' : 'A');
    expect(verifySecureLinkToken(`${flipped}.${sig}`)).toBeNull();
  });

  it('rejects a forged signature', () => {
    const token = makeSecureLinkToken('VRA-1');
    const [payload] = token.split('.');
    expect(verifySecureLinkToken(`${payload}.not-a-real-signature`)).toBeNull();
  });

  it('rejects malformed tokens', () => {
    expect(verifySecureLinkToken('')).toBeNull();
    expect(verifySecureLinkToken('no-dot-here')).toBeNull();
    expect(verifySecureLinkToken('.onlysig')).toBeNull();
    expect(verifySecureLinkToken('garbage.garbage')).toBeNull();
  });

  it('rejects a token signed with a different secret', () => {
    const token = makeSecureLinkToken('VRA-1');
    process.env.RECIPIENT_CAPABILITY_SECRET = 'a-different-independent-secret-for-test';
    expect(verifySecureLinkToken(token)).toBeNull();
  });

  it('rejects a validly-signed token whose kind is not "securelink"', () => {
    // An escrow/counsel-shaped payload, correctly signed with the same secret,
    // must not verify as a secure link — the kind discriminator prevents it.
    const token = signScope({
      kind: 'escrow',
      trackingId: 'VRA-1',
      entityId: 'cisa',
      jti: 'a'.repeat(32),
      exp: Date.now() + 100_000,
    });
    expect(verifySecureLinkToken(token)).toBeNull();
  });

  it('rejects an expired token', () => {
    const token = signScope({
      kind: 'securelink',
      trackingId: 'VRA-1',
      entityId: SECURE_LINK_ENTITY_ID,
      jti: 'a'.repeat(32),
      exp: Date.now() - 1_000,
    });
    expect(verifySecureLinkToken(token)).toBeNull();
  });

  it('rejects a token missing its jti', () => {
    const token = signScope({
      kind: 'securelink',
      trackingId: 'VRA-1',
      entityId: SECURE_LINK_ENTITY_ID,
      exp: Date.now() + 100_000,
    });
    expect(verifySecureLinkToken(token)).toBeNull();
  });

  it('builds a secure-packet URL that verifies', () => {
    process.env.APP_BASE_URL = 'https://vera.report';
    const { url, token } = secureLinkUrl('VRA-1');
    expect(url).toBe(`https://vera.report/api/dissemination/secure-packet/${token}`);
    expect(verifySecureLinkToken(token)?.trackingId).toBe('VRA-1');
  });

  it('cannot mint or verify without the signing secret', () => {
    delete process.env.RECIPIENT_CAPABILITY_SECRET;
    expect(() => makeSecureLinkToken('VRA-1')).toThrow(/RECIPIENT_CAPABILITY_SECRET/);
    expect(verifySecureLinkToken('anypayload.anysig')).toBeNull();
  });
});
