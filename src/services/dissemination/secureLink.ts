import { sealCapability, openCapability } from './recipientCapability';
/**
 * One-time secure disclosure-packet links (VERA-PDR-001, reporter-reward flow).
 *
 * A single-use, authenticated encrypted link emailed to an external recipient (e.g. a
 * whistleblower attorney) that serves the identity-free dossier packet. The
 * token scopes exactly one (trackingId, entityId, jti) triple with an expiry;
 * tampering with any field invalidates the signature.
 *
 * Unlike the escrow (`escrowRelease.ts`) and counsel-workspace
 * (`counselWorkspace.ts`) links — both stateless and reusable until their TTL —
 * this token is SINGLE-USE: the `jti` is burned in the consumed-store on first
 * reveal (`disseminationPersistence.consumeSecureLink`), so a held or forwarded
 * link cannot be replayed. Consumption happens on the reveal POST, never on the
 * landing GET, so email link-scanners / prefetch cannot burn it.
 *
 * The link carries no reporter identity and no decryption keys: it serves the
 * identity-free dossier packet (`packetGenerator`) — the same firewall as every
 * other dissemination surface. Reward follow-up rides the anonymous relay, not
 * this link.
 */

import crypto from 'node:crypto';

/**
 * Synthetic entity id for standalone secure-packet sends. It is NOT a routing
 * entity (it has no adapter and no taxonomy row); it only scopes the token and
 * labels the packet/audit. `packetGenerator` tolerates an unknown entityId
 * (`getEntity(id)?.name ?? id`).
 */
export const SECURE_LINK_ENTITY_ID = 'secure-link';

const DEFAULT_TTL_DAYS = 7;

export interface SecureLinkScope {
  kind: 'securelink';
  trackingId: string;
  entityId: string;
  /** Unique token id — the single-use key burned on first reveal. */
  jti: string;
  /** Expiry, epoch millis. */
  exp: number;
  /**
   * How the link was minted. `'auto'` marks a link sent automatically on report
   * submission — the reveal route serves the redaction-scrubbed dissemination
   * narrative for these. Absent = admin-minted (#505), served as-is.
   */
  origin?: 'auto';
  /** Frozen digest of evidence automatically included with the report. */
  evidenceDigest?: string;
}


function ttlDays(): number {
  const raw = Number(process.env.SECURE_LINK_TTL_DAYS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TTL_DAYS;
}

export function makeSecureLinkToken(
  trackingId: string,
  entityId: string = SECURE_LINK_ENTITY_ID,
  origin?: 'auto',
  evidenceDigest?: string,
): string {
  const scope: SecureLinkScope = {
    kind: 'securelink',
    trackingId,
    entityId,
    jti: crypto.randomBytes(16).toString('hex'),
    exp: Date.now() + ttlDays() * 24 * 3600 * 1000,
    ...(origin ? { origin } : {}),
    ...(evidenceDigest ? { evidenceDigest } : {}),
  };
  return sealCapability('securelink', scope);
}

export function verifySecureLinkToken(token: string): SecureLinkScope | null {
  try {
    const scope = openCapability('securelink', token) as SecureLinkScope;
    if (
      (scope.evidenceDigest !== undefined && (typeof scope.evidenceDigest !== 'string' || !/^[a-f0-9]{64}$/.test(scope.evidenceDigest) || scope.origin === 'auto')) ||
      scope.kind !== 'securelink' ||
      typeof scope.trackingId !== 'string' ||
      typeof scope.entityId !== 'string' ||
      typeof scope.jti !== 'string' || !scope.jti ||
      typeof scope.exp !== 'number' ||
      !Number.isFinite(scope.exp) || scope.exp <= Date.now()
    ) {
      return null;
    }
    return scope;
  } catch {
    return null;
  }
}

/** Absolute one-time secure-packet URL (and the raw token, for audit digesting). */
export function secureLinkUrl(
  trackingId: string,
  entityId: string = SECURE_LINK_ENTITY_ID,
  origin?: 'auto',
  evidenceDigest?: string,
): { url: string; token: string } {
  const base =
    process.env.DISSEMINATION_PUBLIC_BASE_URL ||
    process.env.APP_BASE_URL ||
    'http://localhost:3001';
  const token = makeSecureLinkToken(trackingId, entityId, origin, evidenceDigest);
  return {
    url: `${base.replace(/\/$/, '')}/api/dissemination/secure-packet/${token}`,
    token,
  };
}
