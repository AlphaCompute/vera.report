import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { FirmSharedListKeyChanged, FIRM_SHARED_REQUEST_LIMIT, openFirmSharedList, sealFirmSharedList } from '../../enclave/src/confidential/firmSharedList';
import type { FirmSharedList, SharedRequest } from '../../enclave/src/confidential/firmSharedList';
import { ConfidentialUnavailableError, base64, channelSessionsFor, unavailable } from './client';
import type { FirmSession } from './firmCase';
export { FirmSharedListKeyChanged };
export type { FirmSharedList, SharedRequest };

/** The organization's shared request list (see `firmSharedList.ts`). Reads and
 * writes go through the attested channel as an enrolled member; the list is
 * encrypted to the organization key and padded to a size bucket, so VERA sees only
 * that bucket and the version (no write time).
 * Each write is the next version of the newest list (compare-and-set); on a
 * concurrent write the change is re-applied to the newer list. `minimumVersion`
 * is this device's pin: an older list from the host is refused. */
export type SharedListState = { version: number; list: FirmSharedList;
  /** Last written with the previous organization key: a rotation is not registered with VERA yet. */
  previousKeySigned: boolean };
export class SharedListRollbackError extends Error {
  constructor() { super('The shared request list is older than one this device already saw. Try again later, and tell VERA if this continues.'); }
}
export class SharedListFullError extends Error {
  constructor() { super(`Your organization's request list is full (${FIRM_SHARED_REQUEST_LIMIT} reports). Withdraw or clear old requests first.`); }
}
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
export const EMPTY_SHARED_LIST: FirmSharedList = { keyEpoch: 1, requests: [] };

/** One attested exchange. Keeps the failure reason: a relay outage, throttle or
 * lost connection must not read as a failed verification (which tells lawyers the
 * connection may be intercepted), and a real attestation or decryption failure
 * stays `verification`. A paused release is passed through unchanged. */
async function call(session: FirmSession, operation: 'legal.firm-list-read' | 'legal.firm-list-write', body: unknown,
  now: number): Promise<Record<string, unknown>> {
  const accessToken = await session.accessToken();
  try {
    // This signed compare-and-set write has no challenge/proof preflight. An
    // idle cached channel may have been reclaimed for another workspace at the
    // same address, and retrying a write after a lost reply is unsafe. Open a
    // fresh channel for writes: the enclave protects it until its first call.
    const reply = await channelSessionsFor(session, session.relay, session.releaseManifest).run(send =>
      send({ operation, accessToken, body: base64(encode(body)) }, { retry: operation === 'legal.firm-list-read' }),
    { fresh: operation === 'legal.firm-list-write' });
    if (!reply || typeof reply !== 'object' || Array.isArray(reply)) throw new Error();
    return reply as Record<string, unknown>;
  } catch (error) { throw unavailable(error); }
}

export async function readSharedList(session: FirmSession, minimumVersion: number, now: number): Promise<SharedListState> {
  const reply = await call(session, 'legal.firm-list-read', { organizationId: session.firm.organizationId }, now);
  if (reply.record === null) {
    if (reply.version !== 0) throw new ConfidentialUnavailableError();
    if (minimumVersion > 0) throw new SharedListRollbackError();
    return { version: 0, list: { keyEpoch: EMPTY_SHARED_LIST.keyEpoch, requests: [] }, previousKeySigned: false };
  }
  try {
    const opened = await openFirmSharedList(reply.record, { organizationId: session.firm.organizationId, minimumVersion: 0 },
      session.firm.privateKey);
    if (opened.version < minimumVersion) throw new SharedListRollbackError();
    return { version: opened.version, list: opened.list, previousKeySigned: opened.header.recipientKeyId !== session.firm.recipientKeyId };
  } catch (error) {
    if (error instanceof SharedListRollbackError || error instanceof FirmSharedListKeyChanged) throw error;
    throw new ConfidentialUnavailableError();
  }
}

/** Applies `change` to the newest list and writes it as the next version. */
export async function updateSharedList(session: FirmSession, minimumVersion: number,
  change: (list: FirmSharedList) => FirmSharedList, now: number): Promise<SharedListState> {
  let pin = minimumVersion;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readSharedList(session, pin, now);
    pin = current.version;
    const next = change({ keyEpoch: current.list.keyEpoch, requests: current.list.requests.map(item => ({ ...item })) });
    if (next.requests.length > FIRM_SHARED_REQUEST_LIMIT) throw new SharedListFullError();
    if (JSON.stringify(next) === JSON.stringify(current.list)) return current;
    let record: string;
    try { record = await sealFirmSharedList(next, { organizationId: session.firm.organizationId, version: current.version + 1 },
      session.firm.privateKey); }
    catch (error) { if (error instanceof RangeError) throw new SharedListFullError(); throw new ConfidentialUnavailableError(); }
    const reply = await call(session, 'legal.firm-list-write', { organizationId: session.firm.organizationId, record }, now);
    if (reply.version === current.version + 1) return { version: current.version + 1, list: next, previousKeySigned: false };
    if (reply.error !== 'conflict') throw new ConfidentialUnavailableError();
  }
  // Other members kept writing first: contention, not a verification failure.
  throw new ConfidentialUnavailableError('busy');
}

/** Rotation: the steward (still authenticated with the registered old key) writes
 * the list encrypted to the NEW key only, with the old public key and continuity
 * attached, and the next key epoch. Devices on the old key can no longer read it. */
export async function moveSharedListToKey(session: FirmSession, minimumVersion: number, input: {
  next: PrivateKey; continuity: string; keyEpoch: number;
}, now: number): Promise<SharedListState> {
  let pin = minimumVersion;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readSharedList(session, pin, now);
    pin = current.version;
    const next = { keyEpoch: input.keyEpoch, requests: current.list.requests };
    let record: string;
    try { record = await sealFirmSharedList(next, { organizationId: session.firm.organizationId, version: current.version + 1 },
      session.firm.privateKey, input.next.toPublic(), { publicKey: session.firm.privateKey.toPublic().armor(), continuity: input.continuity }); }
    catch { throw new ConfidentialUnavailableError(); }
    const reply = await call(session, 'legal.firm-list-write', { organizationId: session.firm.organizationId, record }, now);
    if (reply.version === current.version + 1) return { version: current.version + 1, list: next, previousKeySigned: true };
    if (reply.error !== 'conflict') throw new ConfidentialUnavailableError();
  }
  // Other members kept writing first: contention, not a verification failure.
  throw new ConfidentialUnavailableError('busy');
}

/** What a member sees for one request. */
export type RequestOutcome = 'waiting' | 'allowed' | 'withdrawn' | 'expired' | 'renew';
export function requestOutcome(item: SharedRequest, currentRecipientKeyId: string, now: number): RequestOutcome {
  if (item.recipientKeyId !== currentRecipientKeyId && item.state !== 'withdrawn') return 'renew';
  if (item.state === 'withdrawn') return 'withdrawn';
  if (item.state === 'granted') return item.grantExpiresAt !== null && item.grantExpiresAt <= now ? 'expired' : 'allowed';
  return item.expiresAt <= now ? 'expired' : 'waiting';
}
