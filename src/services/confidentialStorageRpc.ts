import net from 'node:net';
import type { RoughtimeRelay } from './confidentialRoughtime';

/** Host side of the enclave storage RPC (mirror of enclave/src/cases/storageRpc.ts).
 * Serves only the allowlisted methods of the untrusted ciphertext store. The
 * enclave initiates every call; this server never reaches into the enclave and
 * holds no keys. Errors are generic so storage details are not echoed.
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
  'getMember', 'getOrganization', 'getInvitation', 'commitEnrollment', 'insertInvitation', 'upsertLegalOrganization',
  'getApplicationApproval', 'registerFirstApplicationKey', 'queueFirstApplicationKeyReview',
  'getLegalOrganizationKeySetup', 'submitLegalOrganizationKeyCandidate', 'inviteLegalOrganizationMember', 'putFirmDeviceMembership',
  'countMembers',
  // Member devices and the organization's shared request list (ciphertext and public keys; re-checked in the enclave).
  'listFirmDevices', 'getFirmDevice', 'putFirmDevice', 'removeFirmDevice', 'getFirmSharedList', 'putFirmSharedList',
  // Organization setup: signed setup statements and the enrolled members for this key (re-verified in the enclave).
  'getOrganizationSetup', 'putOrganizationSetup', 'listMembers',
] as const;
export const CASE_STORE_RPC_MAX_FRAME = 48 * 1024 * 1024;

type Store = { [method: string]: unknown };

/** Store methods build Mongo filters and update paths from their arguments. No
 * legitimate argument carries an object key that Mongo would read as an operator
 * (`$…`), so refuse any such key anywhere in the
 * argument tree before dispatch. This keeps a malformed or hostile caller of the
 * socket from turning an equality match (for example the compare-and-set on the
 * current checkpoint digest) into an operator query. Iterative: no recursion
 * depth follows the caller's nesting. */
export function storageRpcArgumentsSafe(args: unknown[]): boolean {
  const pending: unknown[] = [...args];
  while (pending.length) {
    const value = pending.pop();
    if (value === null || typeof value !== 'object') continue;
    if (Array.isArray(value)) { pending.push(...value); continue; }
    for (const [key, item] of Object.entries(value)) {
      if (key.startsWith('$')) return false;
      pending.push(item);
    }
  }
  return true;
}

function frame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/** `releaseManifest` is the canonical manifest of the deployed EIF; the enclave
 * trusts it only after matching it to its own NSM-reported PCRs.
 * `legalIdentityPolicy` ({issuer, audience, clientId, jwks}) enables firm
 * operations; the enclave accepts it only when its digest matches the policy
 * pin in the measured configuration. Absent means firm ops stay off. */
export function createConfidentialStorageServer(store: Store,
  options: { timeoutMs?: number; releaseManifest?: string; legalIdentityPolicy?: unknown;
    releaseWithdrawals?: () => string | null; roughtime?: RoughtimeRelay } = {}): net.Server {
  const timeoutMs = options.timeoutMs ?? 60_000;
  return net.createServer(socket => {
    // Chunks are joined once, when the frame is complete: concatenating on every
    // chunk copies a large frame quadratically.
    let chunks: Buffer[] = [], received = 0, handled = false, buffer = Buffer.alloc(0);
    socket.setTimeout(timeoutMs, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.on('data', async (chunk: Buffer) => {
      if (handled) return socket.destroy();
      chunks.push(chunk); received += chunk.length;
      if (received < 4) return;
      if (chunks.length > 1 && chunks[0].length < 4) { chunks = [Buffer.concat(chunks)]; }
      const length = chunks[0].readUInt32BE(0);
      if (length > CASE_STORE_RPC_MAX_FRAME || received > length + 4) return socket.destroy();
      if (received < length + 4) return;
      handled = true;
      buffer = Buffer.concat(chunks, received); chunks = [];
      let reply: unknown;
      try {
        const request = JSON.parse(buffer.subarray(4).toString('utf8'));
        buffer = Buffer.alloc(0);
        if (request?.method === 'getReleaseManifest' && Object.keys(request).sort().join(',') === 'args,method' &&
            Array.isArray(request.args) && !request.args.length && typeof options.releaseManifest === 'string') {
          socket.end(frame({ result: options.releaseManifest }));
          return;
        }
        // Signed withdrawal list (releaseWithdrawals.ts); the enclave verifies it.
        if (request?.method === 'getReleaseWithdrawals' && Object.keys(request).sort().join(',') === 'args,method' &&
            Array.isArray(request.args) && !request.args.length) {
          socket.end(frame({ result: options.releaseWithdrawals?.() ?? null }));
          return;
        }
        // Optional Roughtime relay (confidentialRoughtime.ts): the enclave
        // authenticates the answer; this only forwards to an allowlisted server.
        if (request?.method === 'roughtimeExchange' && Object.keys(request).sort().join(',') === 'args,method' &&
            Array.isArray(request.args) && request.args.length === 2 && typeof request.args[0] === 'string' &&
            typeof request.args[1] === 'string' && request.args[1].length <= 4096 && /^[A-Za-z0-9+/]+={0,2}$/.test(request.args[1])) {
          const answer = options.roughtime ? await options.roughtime(request.args[0], Buffer.from(request.args[1], 'base64')).catch(() => null) : null;
          socket.end(frame({ result: answer ? answer.toString('base64') : null }));
          return;
        }
        if (request?.method === 'getLegalIdentityPolicy' && Object.keys(request).sort().join(',') === 'args,method' &&
            Array.isArray(request.args) && !request.args.length) {
          socket.end(frame({ result: options.legalIdentityPolicy ?? null }));
          return;
        }
        if (!request || typeof request !== 'object' || Array.isArray(request) ||
            Object.keys(request).sort().join(',') !== 'args,method' || !Array.isArray(request.args) ||
            !(CASE_STORE_RPC_METHODS as readonly string[]).includes(request.method) ||
            typeof store[request.method] !== 'function' || !storageRpcArgumentsSafe(request.args)) throw new Error();
        const result = await (store[request.method] as (...args: unknown[]) => Promise<unknown>)
          .apply(store, request.args);
        reply = { result: result === undefined ? null : result };
      } catch {
        reply = { error: 'unavailable' };
      }
      socket.end(frame(reply));
    });
  });
}

/** Binds the storage RPC either to host loopback TCP or, for the bridge-mode API
 * task, to a Unix socket in the host directory the parent's vsock 5005 bridge
 * connects to. Only a stale socket file is replaced; any other file fails. */
export async function listenConfidentialStorage(server: net.Server,
  target: { path: string } | { port: number }): Promise<void> {
  if ('path' in target) {
    const { lstatSync, rmSync, chmodSync } = await import('node:fs');
    if (typeof target.path !== 'string' || !target.path.startsWith('/')) throw new Error('Storage socket path must be absolute');
    try {
      if (!lstatSync(target.path).isSocket()) throw new Error('Storage socket path is not a socket');
      rmSync(target.path);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(target.path, () => resolve()); });
    chmodSync(target.path, 0o600);
    return;
  }
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(target.port, '127.0.0.1', () => resolve()); });
}
