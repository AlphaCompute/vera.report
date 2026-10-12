import { readKey } from '../confidential/pgp.js';
import { FIRM_ONBOARDING_TERMS_VERSION, FIRM_SETUP_REQUIREMENTS, FIRM_SETUP_STATEMENT_KINDS, FIRM_SETUP_STATEMENT_MAX, verifyFirmSetupStatement } from '../confidential/firmSetup.js';
import type { FirmCustodyStatement, FirmSetupRequirement, FirmTermsStatement } from '../confidential/firmSetup.js';
import type { OrganizationContext } from './service.js';
import type { LegalFirmStore } from './legalFirm.js';

/** Enforced organization setup (architecture: "Firm key custody and onboarding
 * terms"). An organization may not request access to a report, or read state
 * keys, unlock, open or message on a case, until:
 *
 * - terms: the organization key signed an acknowledgement of the current
 *   onboarding terms version and digest.
 * Optional second-custodian attestations and verified key-holder counts remain
 * visible in setup status, but never gate report operations.
 *
 * Statements come from untrusted host rows and are verified against the
 * registered key on every read; a missing, stale or invalid one reads as missing.
 * Only a complete result is cached, per organization key, for one minute. This is
 * an onboarding precondition, not an access authority: grants, releases and
 * checkpoints are still checked by the case service for every read.
 */
export type FirmSetupStatus = {
  complete: boolean; missing: FirmSetupRequirement[];
  /** Optional backup custody evidence (null: not recorded). */
  custody: 'attested' | 'members' | null;
  /** Enrolled key holders counted for display, up to 2. */
  holders: number;
  custodyAttestedAt: number | null;
  terms: { version: number; acknowledgedAt: number } | null;
  termsVersion: number;
};
/** Counts distinct enrolled people verified to hold the organization key, stopping at `enough`. */
export type KeyHolderCounter = (enough: number) => Promise<number>;
type Stored = { custody: FirmCustodyStatement | null; terms: FirmTermsStatement | null };

const COMPLETE_TTL_MS = 60_000, CACHE_LIMIT = 512, DISPLAY_HOLDERS = 2;
function denied(): never { throw new Error('Legal organization operation unavailable'); }

export function isFirmSetupStatementKind(value: unknown): value is FirmSetupRequirement {
  return typeof value === 'string' && (FIRM_SETUP_STATEMENT_KINDS as readonly string[]).includes(value);
}

export function createFirmSetup(deps: { store: Pick<LegalFirmStore, 'getOrganizationSetup' | 'putOrganizationSetup'>; now(): number }) {
  const complete = new Map<string, number>();
  const cacheKey = (context: OrganizationContext) => `${context.organizationId}:${context.recipientKeyId}`;

  async function stored(context: OrganizationContext): Promise<Stored> {
    const row = await deps.store.getOrganizationSetup(context.organizationId);
    if (row === null || row === undefined) return { custody: null, terms: null };
    if (typeof row !== 'object' || Array.isArray(row)) denied();
    const publicKey = await readKey({ armoredKey: context.publicKey });
    const expected = { organizationId: context.organizationId, recipientKeyId: context.recipientKeyId, publicKey };
    const now = deps.now();
    const read = async <K extends FirmSetupRequirement>(kind: K, value: unknown) => {
      if (value === null || value === undefined) return null;
      try {
        return kind === 'custody' ? await verifyFirmSetupStatement(value, { ...expected, kind: 'custody' }, now)
          : await verifyFirmSetupStatement(value, { ...expected, kind: 'terms' }, now);
      } catch { return null; }
    };
    return { custody: await read('custody', row.custody) as FirmCustodyStatement | null,
      terms: await read('terms', row.terms) as FirmTermsStatement | null };
  }

  async function evaluate(context: OrganizationContext, holders: KeyHolderCounter, countAlways: boolean): Promise<FirmSetupStatus> {
    const { custody, terms } = await stored(context);
    const counted = countAlways ? Math.min(await holders(DISPLAY_HOLDERS), DISPLAY_HOLDERS) : 0;
    if (!Number.isSafeInteger(counted) || counted < 0) denied();
    const how = counted >= DISPLAY_HOLDERS ? 'members' as const : custody ? 'attested' as const : null;
    const missing = FIRM_SETUP_REQUIREMENTS.filter(item => item === 'custody' ? how === null : terms === null);
    const status: FirmSetupStatus = { complete: missing.length === 0, missing, custody: how, holders: counted,
      custodyAttestedAt: custody?.attestedAt ?? null,
      terms: terms ? { version: terms.termsVersion, acknowledgedAt: terms.acknowledgedAt } : null,
      termsVersion: FIRM_ONBOARDING_TERMS_VERSION };
    if (status.complete) {
      if (complete.size >= CACHE_LIMIT) complete.delete(complete.keys().next().value as string);
      complete.set(cacheKey(context), deps.now() + COMPLETE_TTL_MS);
    } else complete.delete(cacheKey(context));
    return status;
  }

  return {
    /** Full status for the portal checklist. */
    status(context: OrganizationContext, holders: KeyHolderCounter): Promise<FirmSetupStatus> {
      return evaluate(context, holders, true);
    },
    /** Null when the organization may proceed; otherwise what is missing. */
    async missing(context: OrganizationContext, holders: KeyHolderCounter): Promise<FirmSetupRequirement[] | null> {
      const until = complete.get(cacheKey(context));
      if (until !== undefined && until > deps.now()) return null;
      const status = await evaluate(context, holders, false);
      return status.complete ? null : status.missing;
    },
    /** Verifies a statement signed by the registered organization key and stores it
     * with the organization row. Throws on an invalid statement. */
    async record(context: OrganizationContext, kind: FirmSetupRequirement, statement: unknown): Promise<boolean> {
      if (!isFirmSetupStatementKind(kind) || typeof statement !== 'string' || statement.length > FIRM_SETUP_STATEMENT_MAX) denied();
      const publicKey = await readKey({ armoredKey: context.publicKey });
      const expected = { organizationId: context.organizationId, recipientKeyId: context.recipientKeyId, publicKey };
      try {
        if (kind === 'custody') await verifyFirmSetupStatement(statement, { ...expected, kind: 'custody' }, deps.now());
        else await verifyFirmSetupStatement(statement, { ...expected, kind: 'terms' }, deps.now());
      } catch { return denied(); }
      complete.delete(cacheKey(context));
      return deps.store.putOrganizationSetup(context.organizationId, kind, statement as string);
    },
  };
}
