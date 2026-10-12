import { readKey } from '../../enclave/src/confidential/pgp';
import { forgetChannelSessions } from './client';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import type { SharedRequest } from '../../enclave/src/confidential/firmSharedList';
import type { FirmSession } from './firmCase';
import type { OwnerTrust } from '../../enclave/src/confidential/authorization';
import type { FirmIdentity } from './firmKey';
import type { UnlockedVault } from './deviceVault';
import { assertFirmWorkspaceCapacity, firmWorkspace, validFirmProfile, validRequest } from './firmWorkspace';
import type { FirmProfile, RememberedRequest } from './firmWorkspace';
export type { FirmProfile } from './firmWorkspace';
import type { SharedListState } from './firmSharedRequests';
export type { RememberedRequest } from './firmWorkspace';

/** In-memory legal workspace for this tab.
 *
 * The organization's requests live in the shared, organization-key-encrypted
 * list (`firmSharedRequests.ts`) so every member sees them and their outcomes.
 * This device keeps a mirror of that list in its encrypted workspace, plus its
 * own freshness pins, message floors, member device key and the newest shared
 * list version it has seen. The old per-browser plaintext index is read once to
 * move its entries into the shared list and is removed after an encrypted save.
 * Request IDs are participant-held routing secrets: never send these records to
 * host storage or telemetry.
 */
export type FirmDevice = { memberId: string; privateKey: PrivateKey; keyEpoch: number };
let current: FirmSession | null = null;
let vault: UnlockedVault | null = null;
let requests: RememberedRequest[] = [];
let profile: FirmProfile | null = null;
let device: FirmDevice | null = null;
let shared: SharedListState | null = null;
let sharedPin = 0;
let writes: Promise<void> = Promise.resolve();
const DAY = 86_400_000;
export function currentFirmSession(): FirmSession | null { return current; }
export function currentFirmVault(): UnlockedVault | null { return vault; }
export function currentFirmDevice(): FirmDevice | null { return device; }
export function currentSharedList(): SharedListState | null { return shared; }
const storageKey = (organizationId: string) => `vera-legal-requests:${organizationId}`;
function legacyRequests(organizationId: string): RememberedRequest[] {
  try {
    const raw = window.localStorage.getItem(storageKey(organizationId));
    if (!raw || raw.length > 1024 * 1024) return [];
    const value = JSON.parse(raw);
    return Array.isArray(value) && value.length <= 200 ? value.filter(validRequest) : [];
  } catch { return []; }
}
export function setFirmSession(session: FirmSession | null): void {
  if (session === current) return;
  vault?.lock(); vault = null;
  if (current) forgetChannelSessions(current); // The replaced workspace's attested session ends with it.
  device = null; shared = null; sharedPin = 0;
  current = session; requests = session ? legacyRequests(session.firm.organizationId) : []; profile = null;
}
export function setFirmVault(next: UnlockedVault, restoredRequests?: RememberedRequest[], restoredProfile?: FirmProfile | null): void {
  if (!current || next.role !== 'legal') throw new Error('No organization workspace is open');
  if (vault && vault !== next) vault.lock();
  vault = next;
  if (restoredRequests) requests = mergeRequests(restoredRequests, requests);
  if (restoredProfile) profile = validFirmProfile(restoredProfile);
  // Successful create/unlock already persisted this encrypted index.
  // An older vault must not silently erase newer legacy request records.
  const legacy = legacyRequests(current.firm.organizationId);
  if (legacy.every(item => requests.some(saved => JSON.stringify(saved) === JSON.stringify(item)))) {
    try { window.localStorage.removeItem(storageKey(current.firm.organizationId)); } catch { /* Reported by forget if needed. */ }
  }
}
function mergeRequests(primary: RememberedRequest[], extra: RememberedRequest[]): RememberedRequest[] {
  const merged = primary.map(item => ({ ...item }));
  for (const item of extra) if (!merged.some(saved => saved.caseId === item.caseId)) merged.push({ ...item });
  return merged;
}
export function restoreFirmRequests(restored: RememberedRequest[], restoredProfile?: FirmProfile | null): void {
  if (!current || !restored.every(validRequest) || restored.length > 200) throw new Error('Invalid restored requests');
  requests = mergeRequests(restored, requests);
  if (restoredProfile) profile = validFirmProfile(restoredProfile);
}
/** Device key and shared-list pin restored from this device's encrypted workspace. */
export function restoreFirmDevice(restored: { device: FirmDevice | null; sharedListVersion: number }): void {
  if (!current) throw new Error('Unlock the organization key first');
  device = restored.device ? { ...restored.device } : null;
  sharedPin = Math.max(sharedPin, restored.sharedListVersion);
}
export function setFirmDevice(next: FirmDevice | null): void {
  if (!current) throw new Error('Unlock the organization key first');
  device = next ? { ...next } : null;
}
function extras() {
  return { device: device ? { memberId: device.memberId, privateKey: device.privateKey.armor(), keyEpoch: device.keyEpoch } : null,
    sharedListVersion: sharedPin, profile };
}
export function currentFirmPayload() {
  if (!current) throw new Error('Unlock the organization key first');
  return firmWorkspace(current, requests, extras());
}
/** The organization profile sent with requests from this workspace. */
export function currentFirmProfile(): FirmProfile | null {
  return profile ? { ...profile, practiceAreas: [...profile.practiceAreas] } : null;
}
export async function saveFirmProfile(organizationId: string, next: FirmProfile): Promise<void> {
  if (current?.firm.organizationId !== organizationId) throw new Error('Unlock the organization workspace first');
  profile = validFirmProfile(next);
  await persistFirmWorkspace();
}
export function persistFirmWorkspace(): Promise<void> {
  const expectedSession = current, expectedVault = vault;
  if (!expectedSession || !expectedVault) return Promise.resolve();
  const write = writes.catch(() => {}).then(async () => {
    if (current !== expectedSession || vault !== expectedVault) return;
    await expectedVault.save(firmWorkspace(expectedSession, requests, extras()));
  });
  writes = write;
  return write;
}
/** After a rotation: save this device's workspace with the new organization key
 * (and key epoch). Returns false when the workspace is not saved on this device. */
export async function replaceFirmKeyInWorkspace(next: FirmIdentity, keyEpoch: number): Promise<boolean> {
  const session = current, saved = vault;
  if (!session || !saved) return false;
  if (device) device = { ...device, keyEpoch: Math.max(device.keyEpoch, keyEpoch) };
  await saved.save(firmWorkspace({ ...session, firm: next }, requests, extras()));
  return true;
}
export function rememberedRequests(organizationId: string): RememberedRequest[] {
  return current?.firm.organizationId === organizationId ? requests.map(item => ({ ...item })) : [];
}

function mirror(state: SharedListState): void {
  shared = { version: state.version, list: { keyEpoch: state.list.keyEpoch, requests: state.list.requests.map(item => ({ ...item })) },
    previousKeySigned: state.previousKeySigned };
  sharedPin = Math.max(sharedPin, state.version);
  const local = state.list.requests.filter(item => item.state !== 'withdrawn').map(item => ({ caseId: item.caseId,
    requestId: item.requestId, ownerPublicKey: item.ownerPublicKey, summary: item.summary, requestedAt: item.requestedAt }));
  requests = local;
}
function sharedEntry(item: RememberedRequest, session: FirmSession, now: number): SharedRequest {
  return { caseId: item.caseId, requestId: item.requestId, ownerPublicKey: item.ownerPublicKey, summary: item.summary,
    requestedAt: item.requestedAt, expiresAt: item.requestedAt + 30 * DAY, recipientKeyId: session.firm.recipientKeyId,
    state: 'requested', updatedAt: now, grantExpiresAt: null };
}
async function changeShared(change: (list: SharedRequest[]) => SharedRequest[]): Promise<SharedListState> {
  const session = current;
  if (!session) throw new Error('Unlock the organization workspace first');
  const { updateSharedList } = await import('./firmSharedRequests');
  const next = await updateSharedList(session, sharedPin, list => ({ keyEpoch: list.keyEpoch, requests: change(list.requests) }), Date.now());
  if (current !== session) throw new Error('The organization workspace changed');
  mirror(next);
  await persistFirmWorkspace().catch(() => {});
  return next;
}

/** Loads the organization's shared list and moves any requests this device knew
 * about (older per-browser or per-device lists) into it once. */
export async function loadSharedRequests(session: FirmSession): Promise<SharedListState> {
  if (current !== session) throw new Error('Unlock the organization workspace first');
  const { readSharedList } = await import('./firmSharedRequests');
  const state = await readSharedList(session, sharedPin, Date.now());
  if (current !== session) throw new Error('The organization workspace changed');
  const missing = requests.filter(item => !state.list.requests.some(entry => entry.caseId === item.caseId));
  if (missing.length && !state.previousKeySigned) {
    const now = Date.now();
    return changeShared(list => [...list, ...missing.filter(item => !list.some(entry => entry.caseId === item.caseId))
      .map(item => sharedEntry(item, session, now))]);
  }
  mirror(state);
  await persistFirmWorkspace().catch(() => {});
  return state;
}

/** A new request the organization sent (replaces any older entry for the case). */
export async function rememberRequest(organizationId: string, request: RememberedRequest & { expiresAt: number }): Promise<SharedListState> {
  const session = current;
  const { expiresAt, ...base } = request;
  if (!session || session.firm.organizationId !== organizationId || !validRequest(base) ||
      !Number.isSafeInteger(expiresAt) || expiresAt <= base.requestedAt) throw new Error('Invalid organization request');
  assertFirmWorkspaceCapacity(session, mergeRequests(requests, [base]));
  const now = Date.now();
  return changeShared(list => [...list.filter(item => item.caseId !== base.caseId),
    { ...sharedEntry(base, session, now), expiresAt }]);
}
/** Withdrawn requests stay in the list so every member sees the outcome. */
export async function forgetRequest(organizationId: string, caseId: string): Promise<SharedListState> {
  if (current?.firm.organizationId !== organizationId) throw new Error('Unlock the organization workspace first');
  const now = Date.now();
  return changeShared(list => list.map(item => item.caseId === caseId ? { ...item, state: 'withdrawn', updatedAt: now } : item));
}
/** Removes a finished entry (withdrawn, expired or superseded) from everyone's list. */
export async function clearRequest(organizationId: string, caseId: string): Promise<SharedListState> {
  if (current?.firm.organizationId !== organizationId) throw new Error('Unlock the organization workspace first');
  return changeShared(list => list.filter(item => item.caseId !== caseId));
}
/** A member opened the case: record that the reporter allowed access. */
export async function recordRequestGranted(caseId: string, grantExpiresAt: number | null): Promise<void> {
  const session = current;
  if (!session || !shared) return;
  const entry = shared.list.requests.find(item => item.caseId === caseId);
  if (!entry || entry.recipientKeyId !== session.firm.recipientKeyId ||
      (entry.state === 'granted' && entry.grantExpiresAt === grantExpiresAt)) return;
  const now = Date.now();
  await changeShared(list => list.map(item => item.caseId === caseId && item.recipientKeyId === session.firm.recipientKeyId
    ? { ...item, state: 'granted', grantExpiresAt, updatedAt: now } : item));
}
export async function pinOwnerFromRequest(session: FirmSession, caseId: string): Promise<boolean> {
  if (session.owners.has(caseId)) return true;
  const found = rememberedRequests(session.firm.organizationId).find(item => item.caseId === caseId) ??
    shared?.list.requests.find(item => item.caseId === caseId);
  return !!found && !!await ownerFromRequest(session, found);
}
/** The organization's request for a case and whether its reporter key is pinned,
 * loading the shared list when this device does not know the request yet: after
 * unlocking with the key file, or for a request another lawyer made. Callers must
 * use the returned request rather than one read before this call, which may be
 * stale once the shared list has loaded. */
export async function resolveCaseRequest(session: FirmSession, caseId: string):
  Promise<{ pinned: boolean; request: RememberedRequest | null }> {
  const find = () => rememberedRequests(session.firm.organizationId).find(item => item.caseId === caseId) ?? null;
  let pinned = await pinOwnerFromRequest(session, caseId);
  // Reload even when a list is cached: it may predate a request a colleague sent since.
  if (!pinned || !find()) {
    await loadSharedRequests(session).catch(() => null);
    if (!pinned) pinned = await pinOwnerFromRequest(session, caseId);
  }
  return { pinned, request: find() };
}
/** The reporter key a request row names, pinned for this session. Used when the
 * session has not pinned the owner yet: after unlocking with the key file, or
 * for a request another lawyer made. A key that differs from one this session
 * or a saved checkpoint already pinned is refused, never replaced. */
export async function ownerFromRequest(session: FirmSession,
  item: { caseId: string; ownerPublicKey: string }): Promise<OwnerTrust | null> {
  try {
    const key = await readKey({ armoredKey: item.ownerPublicKey });
    if (key.isPrivate()) return null;
    const ownerFingerprint = key.getFingerprint();
    const pinned = session.owners.get(item.caseId);
    if (pinned) return pinned.ownerFingerprint === ownerFingerprint ? pinned : null;
    const checkpoint = session.pins.get(item.caseId);
    if (checkpoint && checkpoint.ownerFingerprint !== ownerFingerprint) return null;
    const owner: OwnerTrust = { caseId: item.caseId, ownerFingerprint, ownerPublicKey: key };
    session.owners.set(item.caseId, owner);
    return owner;
  } catch { return null; }
}
