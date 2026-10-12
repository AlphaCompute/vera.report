import { connect as tcpConnect } from 'node:net';
import type { Duplex } from 'node:stream';
import type { CaseStore } from './service.js';
import type { LegalMembershipStore } from './legalChannel.js';
import type { LegalIdentityPolicy } from '../legal/identity.js';
import type { EnrollmentStore } from '../legal/enrollment.js';
import type { LegalFirmStore } from './legalFirm.js';

/** Enclave -> host storage RPC. The host store is untrusted ciphertext storage:
 * the service re-verifies every signature and the sealing decorator is applied on
 * the enclave side, so nothing readable crosses this boundary except the
 * documented public/routing fields. One request per connection, a fixed method
 * allowlist, bounded frames and a deadline. There is no generic eval or
 * decrypt method, and the host cannot call into the enclave over this socket.
 */
export const CASE_STORE_RPC_METHODS = [
  'putObjects', 'getStagedObject', 'getObjects', 'getEnvelopes',
  'readGrantedObjects', 'createCase', 'getCase', 'commitTransition', 'listListedCases', 'putAccessRequest',
  'insertAccessRequestAtCheckpoint', 'listAccessRequests', 'getAccessRequest', 'expireAccessRequests', 'countAccessRequests',
  'withdrawAccessRequest', 'declineAccessRequest', 'answerAccessRequest', 'appendMessage', 'listMessages', 'readInboxAtCheckpoint',
  'readMessagesAtCheckpoint', 'readMailboxPageAtCheckpoint', 'countMessages', 'getOwnerEnvelopes', 'listLegalOrganizations',
  // Chunked evidence: promote staged chunks named by a verified index; read one chunk.
  'promoteChunks', 'readObjectChunk',
  // Legal membership (untrusted rows, re-checked in the enclave against the verified token and firm key).
  'getMember', 'getOrganization', 'getInvitation', 'commitEnrollment', 'insertInvitation', 'upsertLegalOrganization', 'getApplicationApproval', 'registerFirstApplicationKey', 'queueFirstApplicationKeyReview',
  'getLegalOrganizationKeySetup', 'submitLegalOrganizationKeyCandidate', 'inviteLegalOrganizationMember', 'putFirmDeviceMembership',
  'countMembers',
  // Member devices and the organization's shared request list (ciphertext and public keys; re-checked in the enclave).
  'listFirmDevices', 'getFirmDevice', 'putFirmDevice', 'removeFirmDevice', 'getFirmSharedList', 'putFirmSharedList',
  // Organization setup: signed setup statements and the enrolled members for this key (re-verified in the enclave).
  'getOrganizationSetup', 'putOrganizationSetup', 'listMembers',
] as const;
export const CASE_STORE_RPC_MAX_FRAME = 48 * 1024 * 1024;
const FAILURE = 'Confidential storage unavailable';

function frame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  if (payload.length > CASE_STORE_RPC_MAX_FRAME) throw new Error(FAILURE);
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/** Reads exactly one length-prefixed JSON frame. The frame buffer is allocated
 * once, when the header arrives, and each chunk is copied into it: concatenating
 * on every chunk would copy a 12 MiB staged object hundreds of times and briefly
 * hold two copies of it. */
function readFrame(socket: Duplex, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let header = Buffer.alloc(0), body: Buffer | null = null, filled = 0;
    const timer = setTimeout(() => finish(new Error(FAILURE)), timeoutMs);
    function finish(error: Error | null, value?: unknown) {
      clearTimeout(timer);
      socket.removeAllListeners('data'); socket.removeAllListeners('error'); socket.removeAllListeners('end');
      socket.destroy();
      if (error) reject(error); else resolve(value);
    }
    socket.on('data', (chunk: Buffer) => {
      let offset = 0;
      if (!body) {
        const needed = 4 - header.length;
        header = Buffer.concat([header, chunk.subarray(0, needed)]);
        offset = Math.min(needed, chunk.length);
        if (header.length < 4) return;
        const length = header.readUInt32BE(0);
        if (length > CASE_STORE_RPC_MAX_FRAME) return finish(new Error(FAILURE));
        body = Buffer.allocUnsafe(length);
      }
      const rest = chunk.length - offset;
      if (filled + rest > body.length) return finish(new Error(FAILURE));
      chunk.copy(body, filled, offset);
      filled += rest;
      if (filled === body.length) {
        try { finish(null, JSON.parse(body.toString('utf8'))); } catch { finish(new Error(FAILURE)); }
      }
    });
    socket.on('error', () => finish(new Error(FAILURE)));
    socket.on('end', () => finish(new Error(FAILURE)));
  });
}

async function rpcCall(connect: () => Duplex, timeoutMs: number, method: string, args: unknown[]): Promise<unknown> {
  const socket = connect();
  const response = readFrame(socket, timeoutMs);
  socket.write(frame({ method, args }));
  const value = await response as { result?: unknown; error?: unknown } | null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || 'error' in value ||
      Object.keys(value).join(',') !== 'result') throw new Error(FAILURE);
  return value.result;
}
export type RpcOptions = { connect?: () => Duplex; port?: number; timeoutMs?: number };
function connector(options: RpcOptions): () => Duplex {
  return options.connect ?? (() => tcpConnect(options.port ?? 5005, '127.0.0.1'));
}

/** Enclave-side store backed by the host over a local socat vsock bridge. */
export function createRemoteCaseStore(options: RpcOptions = {}): CaseStore {
  const connect = connector(options), timeoutMs = options.timeoutMs ?? 30_000;
  return Object.fromEntries(CASE_STORE_RPC_METHODS.map(method =>
    [method, (...args: unknown[]) => rpcCall(connect, timeoutMs, method, args)])) as unknown as CaseStore;
}

/** Host-supplied release manifest. Untrusted: callers MUST pass it through
 * `verifySelfRelease` against this enclave's own NSM measurements. */
export async function fetchReleaseManifest(options: RpcOptions = {}): Promise<string> {
  const value = await rpcCall(connector(options), options.timeoutMs ?? 30_000, 'getReleaseManifest', []);
  if (typeof value !== 'string' || !value.length || value.length > 8192) throw new Error(FAILURE);
  return value;
}

/** Host-supplied signed release withdrawal list, or null when none is
 * published. Untrusted bytes: callers verify them with the measured key. */
export async function fetchReleaseWithdrawals(options: RpcOptions = {}): Promise<string | null> {
  const value = await rpcCall(connector(options), options.timeoutMs ?? 30_000, 'getReleaseWithdrawals', []);
  if (value === null) return null;
  if (typeof value !== 'string' || !value.length || value.length > 256 * 1024) throw new Error(FAILURE);
  return value;
}

/** Roughtime relay (optional external time, see roughtime.ts). The host sends
 * the request packet to `address` (an entry of the measured Roughtime policy that
 * the host also allowlists) and returns the answer, or null. Untrusted bytes:
 * the caller verifies them against the pinned server key and its own nonce. */
export async function roughtimeExchange(options: RpcOptions, address: string, packet: Uint8Array): Promise<Uint8Array | null> {
  if (packet.length < 1024 || packet.length > 2048) throw new Error(FAILURE);
  const value = await rpcCall(connector(options), options.timeoutMs ?? 10_000, 'roughtimeExchange',
    [address, Buffer.from(packet).toString('base64')]);
  if (value === null) return null;
  if (typeof value !== 'string' || !value.length || value.length > 8192 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error(FAILURE);
  return new Uint8Array(Buffer.from(value, 'base64'));
}

/** Membership rows over the same RPC; the legal dispatcher re-checks every field. */
export function createRemoteLegalMembershipStore(options: RpcOptions = {}): LegalMembershipStore {
  const connect = connector(options), timeoutMs = options.timeoutMs ?? 30_000;
  return {
    getMember: (...args) => rpcCall(connect, timeoutMs, 'getMember', args) as ReturnType<LegalMembershipStore['getMember']>,
    getOrganization: (...args) => rpcCall(connect, timeoutMs, 'getOrganization', args) as ReturnType<LegalMembershipStore['getOrganization']>,
    countMembers: async (...args) => {
      const value = await rpcCall(connect, timeoutMs, 'countMembers', args);
      if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(FAILURE);
      return value as number;
    },
    listMembers: async (...args) => {
      const value = await rpcCall(connect, timeoutMs, 'listMembers', args);
      if (!Array.isArray(value)) throw new Error(FAILURE);
      return value as Awaited<ReturnType<NonNullable<LegalMembershipStore['listMembers']>>>;
    },
  };
}

/** Member devices and shared request list; `legalFirm.ts` re-validates every row. */
export function createRemoteLegalFirmStore(options: RpcOptions = {}): LegalFirmStore {
  const connect = connector(options), timeoutMs = options.timeoutMs ?? 30_000;
  const call = (method: string, args: unknown[]) => rpcCall(connect, timeoutMs, method, args);
  return {
    putFirmDeviceMembership: async (...args) => await call('putFirmDeviceMembership', args) === true,
    inviteLegalOrganizationMember: async (...args) => await call('inviteLegalOrganizationMember', args) as Awaited<ReturnType<NonNullable<LegalFirmStore['inviteLegalOrganizationMember']>>>,
    submitLegalOrganizationKeyCandidate: async (...args) => { await call('submitLegalOrganizationKeyCandidate', args); },
    listFirmDevices: async (...args) => await call('listFirmDevices', args) as Awaited<ReturnType<LegalFirmStore['listFirmDevices']>>,
    getFirmDevice: async (...args) => await call('getFirmDevice', args) as Awaited<ReturnType<LegalFirmStore['getFirmDevice']>>,
    putFirmDevice: async (...args) => await call('putFirmDevice', args) === true,
    removeFirmDevice: async (...args) => await call('removeFirmDevice', args) === true,
    getFirmSharedList: async (...args) => await call('getFirmSharedList', args) as Awaited<ReturnType<LegalFirmStore['getFirmSharedList']>>,
    putFirmSharedList: async (...args) => await call('putFirmSharedList', args) === true,
    getOrganizationSetup: async (...args) => await call('getOrganizationSetup', args) as Awaited<ReturnType<LegalFirmStore['getOrganizationSetup']>>,
    putOrganizationSetup: async (...args) => await call('putOrganizationSetup', args) === true,
  };
}

/** Invitation persistence. Issuance is authorized by the measured admin identity
 * policy inside the enclave; the host RPC itself grants no authority. `commitEnrollment` must be one host transaction. */
export function createRemoteEnrollmentStore(options: RpcOptions = {}): EnrollmentStore {
  const connect = connector(options), timeoutMs = options.timeoutMs ?? 30_000;
  return {
    getApplicationApproval: (...args) => rpcCall(connect, timeoutMs, 'getApplicationApproval', args) as Promise<string | null>,
    queueFirstApplicationKeyReview: async (...args) => { await rpcCall(connect, timeoutMs, 'queueFirstApplicationKeyReview', args); },
    registerFirstApplicationKey: async (...args) => { await rpcCall(connect, timeoutMs, 'registerFirstApplicationKey', args); },
    getOrganization: (...args) => rpcCall(connect, timeoutMs, 'getOrganization', args) as ReturnType<EnrollmentStore['getOrganization']>,
    getInvitation: (...args) => rpcCall(connect, timeoutMs, 'getInvitation', args) as ReturnType<EnrollmentStore['getInvitation']>,
    commitEnrollment: async (...args) => await rpcCall(connect, timeoutMs, 'commitEnrollment', args) === true,
    getLegalOrganizationRecord: (...args) => rpcCall(connect, timeoutMs, 'getLegalOrganizationKeySetup', args) as ReturnType<NonNullable<EnrollmentStore['getLegalOrganizationRecord']>>,
    submitLegalOrganizationKeyCandidate: async (...args) => { await rpcCall(connect, timeoutMs, 'submitLegalOrganizationKeyCandidate', args); },
    upsertLegalOrganization: async (...args) => { await rpcCall(connect, timeoutMs, 'upsertLegalOrganization', args); },
    insertInvitation: async (...args) => { await rpcCall(connect, timeoutMs, 'insertInvitation', args); },
  };
}

/** Host-supplied identity policy. Shape checks do not establish authenticity:
 * confidential-server verifies the digest pinned inside the measured image
 * before constructing any legal dispatcher. */
export async function fetchLegalIdentityPolicy(options: RpcOptions = {}): Promise<LegalIdentityPolicy | null> {
  const value = await rpcCall(connector(options), options.timeoutMs ?? 30_000, 'getLegalIdentityPolicy', []);
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'audience,clientId,issuer,jwks' || JSON.stringify(value).length > 65_536) throw new Error(FAILURE);
  const policy = value as LegalIdentityPolicy;
  if (typeof policy.issuer !== 'string' || typeof policy.audience !== 'string' || typeof policy.clientId !== 'string' ||
      !policy.jwks || typeof policy.jwks !== 'object' || !Array.isArray(policy.jwks.keys)) throw new Error(FAILURE);
  return JSON.parse(JSON.stringify(policy)) as LegalIdentityPolicy;
}
