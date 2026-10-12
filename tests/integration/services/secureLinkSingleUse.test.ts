/**
 * One-time secure-packet link — the single-use invariant, end to end.
 *
 * The reveal is the whole security surface of the reporter-reward link (#505/#524):
 * it must open exactly once and never again, and racing reveals must not both win.
 * The unit suite mocks the persistence layer, so the real guarantee — a MongoDB
 * unique index on the token's `jti` — is only actually exercised here, against a
 * real (in-memory) MongoDB and the real capability-token crypto.
 *
 * Lives under tests/integration/services (not tests/e2e) so it runs in the CI gate:
 * it needs only mongodb-memory-server, never a live Midnight proof server.
 */

import { MongoMemoryServer } from 'mongodb-memory-server';
import {
  makeSecureLinkToken,
  verifySecureLinkToken,
  SECURE_LINK_ENTITY_ID,
} from '../../../src/services/dissemination/secureLink';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { disseminationService } from '../../../src/services/dissemination/disseminationService';
import { recipientCapabilityActive } from '../../../src/services/dissemination/recipientCapability';
import { sendSecurePacket } from '../../../src/services/dissemination/securePacketSender';
import { emailNotificationService } from '../../../src/services/emailNotification';

let mongoServer: MongoMemoryServer;
const TOUCHED = ['MONGODB_URI', 'MONGODB_DB_NAME', 'DISSEMINATION_WEBHOOK_SECRET'] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeAll(async () => {
  for (const k of TOUCHED) savedEnv[k] = process.env[k];
  mongoServer = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongoServer.getUri();
  process.env.MONGODB_DB_NAME = 'integration_secure_link';
  process.env.DISSEMINATION_WEBHOOK_SECRET = 'integration-secure-link-secret';
});

afterAll(async () => {
  await disseminationPersistence.disconnect();
  if (mongoServer) await mongoServer.stop();
  // Don't leak this file's env into the next suite sharing the worker process.
  for (const k of TOUCHED) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

/** Mint a link and return its verified scope, failing loudly if setup itself is broken. */
function scopeOf(trackingId: string, origin?: 'auto') {
  const scope = verifySecureLinkToken(makeSecureLinkToken(trackingId, SECURE_LINK_ENTITY_ID, origin));
  if (!scope) throw new Error(`token failed to verify in setup for ${trackingId}`);
  return scope;
}
const reveal = (jti: string, trackingId: string) =>
  disseminationPersistence.consumeSecureLink({ jti, trackingId, entityId: SECURE_LINK_ENTITY_ID });

describe('secure-link token crypto (mint → verify)', () => {
  it('round-trips the scope through a real HMAC seal', () => {
    const scope = scopeOf('VRA-000000000000ABCD', 'auto');
    expect(scope.kind).toBe('securelink');
    expect(scope.trackingId).toBe('VRA-000000000000ABCD');
    expect(scope.entityId).toBe(SECURE_LINK_ENTITY_ID);
    expect(scope.origin).toBe('auto');
    expect(scope.jti).toMatch(/^[a-f0-9]{32}$/);
    expect(scope.exp).toBeGreaterThan(Date.now());
  });

  it('mints a fresh jti per link so two links never collide', () => {
    expect(scopeOf('VRA-1').jti).not.toBe(scopeOf('VRA-1').jti);
  });

  it('rejects a tampered or malformed token by returning null, never throwing', () => {
    const token = makeSecureLinkToken('VRA-1', SECURE_LINK_ENTITY_ID);
    const tampered = token.slice(0, 8) + (token[8] === 'A' ? 'B' : 'A') + token.slice(9);
    expect(verifySecureLinkToken(tampered)).toBeNull();
    expect(verifySecureLinkToken('not-a-token')).toBeNull();
    expect(verifySecureLinkToken('')).toBeNull();
  });
});

describe('single-use reveal against a real MongoDB unique index', () => {
  it('landing never consumes; the first reveal succeeds; a replay is rejected', async () => {
    const { jti, trackingId } = scopeOf('VRA-000000000000BEEF');

    // The landing GET checks state but must never burn the link.
    expect(await disseminationPersistence.isSecureLinkConsumed(jti)).toBe(false);
    expect(await disseminationPersistence.isSecureLinkConsumed(jti)).toBe(false);

    // The reveal POST consumes exactly once.
    expect(await reveal(jti, trackingId)).toBe(true);
    expect(await disseminationPersistence.isSecureLinkConsumed(jti)).toBe(true);

    // A second reveal (a replayed link) is refused — not a second dossier served.
    expect(await reveal(jti, trackingId)).toBe(false);
  });

  it('consumes independent links once each, with no cross-talk', async () => {
    const a = scopeOf('VRA-00000000000000A1');
    const b = scopeOf('VRA-00000000000000B2');
    expect(a.jti).not.toBe(b.jti);

    expect(await reveal(a.jti, a.trackingId)).toBe(true);
    expect(await disseminationPersistence.isSecureLinkConsumed(b.jti)).toBe(false); // A's reveal didn't touch B
    expect(await reveal(b.jti, b.trackingId)).toBe(true);
  });

  it('serves exactly one of two reveals that race for the same link', async () => {
    const { jti, trackingId } = scopeOf('VRA-00000000000000C3');
    const [r1, r2] = await Promise.all([reveal(jti, trackingId), reveal(jti, trackingId)]);
    expect([r1, r2].filter(Boolean)).toHaveLength(1);
  });
});


it('reissue creates independent capabilities without reviving a consumed link across reconnect', async () => {
  const old = scopeOf('VRA-0000000000006250');
  const replacement = scopeOf(old.trackingId);
  expect(replacement.jti).not.toBe(old.jti);
  // Existing policy: generating another link does not silently revoke any
  // independently issued recipient capability for the same report.
  expect(await reveal(old.jti, old.trackingId)).toBe(true);
  await disseminationPersistence.disconnect();
  expect(await reveal(old.jti, old.trackingId)).toBe(false);
  expect(await reveal(replacement.jti, replacement.trackingId)).toBe(true);
  expect(await reveal(replacement.jti, replacement.trackingId)).toBe(false);
});

describe('reissue through the real send path (#625)', () => {
  // docs/LOCAL-SHROUD-LEGAL-ACCEPTANCE.md: reissue creates an independent
  // capability and does NOT revoke earlier unconsumed ones, which may belong to
  // other intended recipients. Reissue is sendSecurePacket -> issueRecipientCapability,
  // and the reveal route gates on recipientCapabilityActive (recipientGrants.revoked)
  // before it ever consumes, so the policy is asserted against the durable grant,
  // not just the jti ledger.
  const trackingId = 'VRA-0000000000006251';
  const savedMode = process.env.DISSEMINATION_MODE;
  const savedInbox = process.env.DISSEMINATION_DRYRUN_INBOX;

  beforeEach(() => {
    delete process.env.DISSEMINATION_MODE; // dryrun: mail routes to the test inbox
    process.env.DISSEMINATION_DRYRUN_INBOX = 'dryrun@example.invalid';
    // Only the report loader and the mailer are stubbed; grant issuance, case
    // registration, audit and single-use consumption all hit the real MongoDB.
    jest.spyOn(disseminationService, 'buildView').mockResolvedValue({
      narrativeReadable: true,
      report: { trackingId, consent: { psst: { granted: false }, agency: false, legalReview: true, capturedAt: new Date(), textVersion: 'v4-legal-review' }, status: 'verified', processingStatus: 'completed', verification: { isLegitimate: true } },
      view: { narrative: 'scrubbed' },
    } as any);
    jest.spyOn(emailNotificationService, 'sendSecurePacketEmail').mockResolvedValue({ sent: true } as any);
  });
  afterEach(() => {
    jest.restoreAllMocks();
    if (savedMode === undefined) delete process.env.DISSEMINATION_MODE; else process.env.DISSEMINATION_MODE = savedMode;
    if (savedInbox === undefined) delete process.env.DISSEMINATION_DRYRUN_INBOX; else process.env.DISSEMINATION_DRYRUN_INBOX = savedInbox;
  });

  const send = async () => {
    const result = await sendSecurePacket({ trackingId, recipientEmail: 'agency@example.invalid', actor: 'integration-test', origin: 'auto' });
    expect(result).toMatchObject({ sent: true, mode: 'dryrun' });
    return decodeURIComponent(result.url!.split('/secure-packet/').pop()!);
  };
  const scopeFromToken = (token: string) => {
    const scope = verifySecureLinkToken(token);
    if (!scope) throw new Error('issued token failed to verify');
    return scope;
  };

  it('reissue leaves the earlier unconsumed grant active and its link redeemable exactly once', async () => {
    const earlierToken = await send();
    expect(await recipientCapabilityActive(earlierToken)).toBe(true);

    const replacementToken = await send();
    expect(replacementToken).not.toBe(earlierToken);

    // The reveal route's first gate: the earlier grant must survive reissue.
    expect(await recipientCapabilityActive(earlierToken)).toBe(true);
    expect(await recipientCapabilityActive(replacementToken)).toBe(true);

    const earlier = scopeFromToken(earlierToken);
    const replacement = scopeFromToken(replacementToken);
    expect(replacement.jti).not.toBe(earlier.jti);

    // Both links open once each, in either order, and neither can be replayed.
    expect(await reveal(replacement.jti, replacement.trackingId)).toBe(true);
    expect(await recipientCapabilityActive(earlierToken)).toBe(true);
    expect(await reveal(earlier.jti, earlier.trackingId)).toBe(true);
    expect(await reveal(earlier.jti, earlier.trackingId)).toBe(false);
    expect(await reveal(replacement.jti, replacement.trackingId)).toBe(false);
  });
});
