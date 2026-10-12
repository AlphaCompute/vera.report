import { issuedNotAfter } from './clockSkew.ts';
import type { AccessGrant, ManifestEntry } from './authorization.ts';

/** Grant time and coverage rules, kept free of cryptography so pages can use
 * them without loading openpgp. authorization.ts re-exports all of these. */

/** Longest optional expiry an owner may choose; "until revoked" is `null`. */
export const MAX_GRANT_LIFETIME_MS = 400 * 86_400_000;

/** A grant is usable from its issue time (allowing the tolerated clock skew
 * between the signer's and the checker's clocks) until its expiry; `null`
 * never lapses. */
export function grantActiveAt(grant: Pick<AccessGrant, 'issuedAt' | 'expiresAt'>, now: number): boolean {
  return issuedNotAfter(grant.issuedAt, now) && (grant.expiresAt === null || grant.expiresAt > now);
}
/** Whether a grant covers one manifest object: granted scope, within the
 * revision limit and not individually excluded. Expiry is checked separately. */
export function grantCoversObject(grant: Pick<AccessGrant, 'scopes' | 'objectRevisionLimit' | 'excludedObjectIds'>,
  entry: Pick<ManifestEntry, 'objectId' | 'scope' | 'objectRevision'>): boolean {
  return grant.scopes.includes(entry.scope) &&
    (grant.objectRevisionLimit === null || entry.objectRevision <= grant.objectRevisionLimit) &&
    !(grant.excludedObjectIds ?? []).includes(entry.objectId);
}
