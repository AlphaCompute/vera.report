import { createHash } from 'node:crypto';
import { createMessage, readKey, readSignature, verify } from 'openpgp';
import { CONFIDENTIAL_ADMIN_VISIBLE_FIELDS } from '../utils/intakeConsent';

/** Public listings contain the approved summary, opaque reference and optional signed submission facts. */
export type ConfidentialListingRow = {
  caseId: string; ownerPublicKey: string; ownerFingerprint: string;
  listingDigest: string; listingWire: string | null; hidden?: boolean;
};
export type ConfidentialListingSource = {
  moderateListing?(caseId: string, hidden: boolean, actor: string, now: number): Promise<boolean>;
  listListingWires(limit: number, after: string | null): Promise<ConfidentialListingRow[]>;
};
/** Submission facts are present only when the owner signed them. */
export type ConfidentialAdminListing = {
  caseId: string; summary: string; publishedAt?: number; hasAttachments?: boolean; hidden?: boolean;
};
export type ConfidentialAdminListingPage = { listings: ConfidentialAdminListing[]; next: string | null };

const PROTOCOL = 'vera-owner-authorization/v1';
const MAX_WIRE_LENGTH = 65_536;
const MAX_KEY_LENGTH = 16_384;
export const CONFIDENTIAL_LISTING_PAGE_MAX = 100;
export const CONFIDENTIAL_LISTING_PAGE_DEFAULT = 25;
const HEX64 = /^[a-f0-9]{64}$/;
const FINGERPRINT = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;

function exactKeys(value: unknown, fields: string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every(key => fields.includes(key));
}

/** Returns the verified listing, or null for anything that is not a valid
 * owner-signed listing for this case. Never throws and never echoes input. */
export async function verifyConfidentialListing(row: ConfidentialListingRow): Promise<ConfidentialAdminListing | null> {
  try {
    const { caseId, ownerFingerprint, listingDigest, listingWire, ownerPublicKey } = row;
    if (typeof caseId !== 'string' || !HEX64.test(caseId) || typeof listingDigest !== 'string' || !HEX64.test(listingDigest) ||
        typeof ownerFingerprint !== 'string' || !FINGERPRINT.test(ownerFingerprint) ||
        typeof listingWire !== 'string' || listingWire.length > MAX_WIRE_LENGTH ||
        typeof ownerPublicKey !== 'string' || ownerPublicKey.length > MAX_KEY_LENGTH) return null;
    const wire: unknown = JSON.parse(listingWire);
    if (!exactKeys(wire, ['protocol', 'ownerFingerprint', 'statement', 'signature']) || wire.protocol !== PROTOCOL ||
        wire.ownerFingerprint !== ownerFingerprint || typeof wire.signature !== 'string' || wire.signature.length > 16_384) return null;
    const statement = wire.statement;
    const optional = statement && typeof statement === 'object' ? ['publishedAt', 'hasAttachments'].filter(key => Object.prototype.hasOwnProperty.call(statement, key)) : [];
    if (!exactKeys(statement, ['kind', 'caseId', 'revision', 'summary', ...optional]) || statement.kind !== 'listing' ||
        statement.caseId !== caseId || typeof statement.revision !== 'number' ||
        !Number.isSafeInteger(statement.revision) || statement.revision <= 0) return null;
    const summary = statement.summary;
    const { publishedAt, hasAttachments } = statement;
    if (optional.includes('publishedAt') && (typeof publishedAt !== 'number' || !Number.isSafeInteger(publishedAt) ||
        publishedAt < 0 || publishedAt > 8_640_000_000_000_000)) return null;
    if (optional.includes('hasAttachments') && typeof hasAttachments !== 'boolean') return null;
    const metadata = { ...(typeof publishedAt === 'number' ? { publishedAt } : {}),
      ...(typeof hasAttachments === 'boolean' ? { hasAttachments } : {}) };
    if (typeof summary !== 'string' || !summary.trim() || summary.length > 600 ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(summary)) return null;
    // Canonical field order matches the enclave's parseStatement reconstruction.
    const payload = JSON.stringify({ protocol: PROTOCOL, ownerFingerprint,
      statement: { kind: 'listing', caseId, revision: statement.revision, summary, ...metadata } });
    if (createHash('sha256').update(payload, 'utf8').digest('hex') !== listingDigest) return null;
    const key = await readKey({ armoredKey: ownerPublicKey });
    if (key.isPrivate() || key.getFingerprint() !== ownerFingerprint) return null;
    const signature = await readSignature({ armoredSignature: wire.signature });
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(payload) }),
      signature, verificationKeys: key, expectSigned: true, format: 'binary' });
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') return null;
    return { caseId, summary, ...metadata };
  } catch {
    return null;
  }
}

/** One page of verified listings. Rows that fail verification are omitted,
 * never repaired or partially serialized. The cursor advances over the raw rows
 * so a page of unverifiable rows cannot stall pagination. */
export async function listConfidentialAdminListings(source: ConfidentialListingSource,
  options: { limit?: number; after?: string | null } = {}): Promise<ConfidentialAdminListingPage> {
  const limit = options.limit ?? CONFIDENTIAL_LISTING_PAGE_DEFAULT;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > CONFIDENTIAL_LISTING_PAGE_MAX) throw new RangeError('Invalid page size');
  const after = options.after ?? null;
  if (after !== null && !HEX64.test(after)) throw new RangeError('Invalid cursor');
  const rows = await source.listListingWires(limit, after);
  const listings: ConfidentialAdminListing[] = [];
  for (const row of rows.slice(0, limit)) {
    const listing = await verifyConfidentialListing(row);
    // Explicit projection: nothing beyond the reviewed admin-visible fields, and
    // a separate unsigned administrative visibility flag.
    if (listing) listings.push({ ...Object.fromEntries(CONFIDENTIAL_ADMIN_VISIBLE_FIELDS
      .filter(field => listing[field] !== undefined).map(field => [field, listing[field]])),
      ...(row.hidden === true ? { hidden: true } : {}) } as ConfidentialAdminListing);
  }
  const last = rows.length >= limit ? rows[limit - 1]?.caseId : undefined;
  return { listings, next: typeof last === 'string' && HEX64.test(last) ? last : null };
}
