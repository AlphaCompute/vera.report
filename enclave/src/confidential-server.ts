import { authenticatedRoster } from './cases/authenticatedRoster.js';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { measuredLegalAdministration, measuredReleaseWithdrawalKey, measuredRoughtimePolicy, verifyMeasuredConfiguration, verifyMeasuredLegalPolicy } from './cases/measuredConfiguration.js';
import { createReleaseWithdrawalGuard } from './cases/releaseWithdrawalGuard.js';
import { randomBytes } from 'node:crypto';
import { createApplicationChannelIdentity } from './application-channel-identity.js';
import { ChannelSessionRejected, createSessionCore } from './application-channel-sessions.js';
import { performance } from 'node:perf_hooks';
import type { ChannelDispatch } from './application-channel-sessions.js';
import { createOwnerCaseControlDispatcher } from './cases/ownerChannel.js';
import { createLegalCaseDispatcher } from './cases/legalChannel.js';
import { createCaseKeyring, createSealedCaseStore } from './cases/sealedStore.js';
import type { CaseKeyring } from './cases/sealedStore.js';
import { installFatalHandlers } from './fatal.js';
import {
  createRemoteCaseStore, createRemoteEnrollmentStore, createRemoteLegalFirmStore, createRemoteLegalMembershipStore, fetchLegalIdentityPolicy,
  fetchReleaseManifest, fetchReleaseWithdrawals, roughtimeExchange,
} from './cases/storageRpc.js';
import type { RpcOptions } from './cases/storageRpc.js';
import type { LegalIdentityPolicy } from './legal/identity.js';
import { verifySelfRelease } from './cases/selfRelease.js';
import { createTrustedClock } from './cases/trustedClock.js';
import { sampleRoughtime } from './cases/roughtime.js';
import { retryBounded } from './cases/startupRetry.js';

/** Confidential case channel server (enclave). The host relays opaque session
 * open/call frames on 127.0.0.1:5004 (bridged from vsock); every private byte is
 * inside the attested application channel. Storage is the untrusted host store
 * reached over the outbound storage RPC, sealed on this side with participant
 * state keys held only in memory. No plaintext, key or case metadata is logged.
 */
/** Largest inbound frame, envelope included. The host relay caps call ciphertext
 * below this (src/api/confidentialChannel.ts `MAX_CIPHERTEXT`). */
export const MAX_FRAME = 1024 * 1024;
const PORT = 5004, AUDIENCE = 'vera-confidential-cases';

function frame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8'), header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/** Frame handler over an attested session manager; injectable for local tests. */
export function createConfidentialFrameServer(sessions: {
  open(nonce: string): Promise<{ document: string; publicKey: string }>;
  execute(nonce: string, ciphertext: string, options?: { last?: boolean }): Promise<string>;
  hasPendingSession?(nonce: string): boolean;
  release?(nonce: string): boolean;
}): net.Server {
  return net.createServer(socket => {
    let buffer = Buffer.alloc(0), handled = false;
    socket.setTimeout(20_000, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    socket.on('data', async chunk => {
      if (handled) return socket.destroy();
      buffer = Buffer.concat([buffer, typeof chunk === 'string' ? Buffer.from(chunk) : chunk]);
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (length > MAX_FRAME || buffer.length > length + 4) return socket.destroy();
      if (buffer.length < length + 4) return;
      handled = true;
      let reply: unknown, calledNonce: string | undefined;
      try {
        const request = JSON.parse(buffer.subarray(4).toString('utf8'));
        if (request?.op === 'open' && Object.keys(request).sort().join(',') === 'nonce,op') {
          const evidence = await sessions.open(request.nonce);
          reply = { document: evidence.document, publicKey: evidence.publicKey };
        } else if (request?.op === 'close' && Object.keys(request).sort().join(',') === 'nonce,op' &&
            typeof request.nonce === 'string' && /^[a-f0-9]{64}$/.test(request.nonce) && sessions.release) {
          // Relay-initiated close of an idle session (availability only: the
          // host can already refuse service). A busy session is never closed.
          reply = { closed: sessions.release(request.nonce) };
        } else if (request?.op === 'call' && (Object.keys(request).sort().join(',') === 'ciphertext,nonce,op' ||
            (Object.keys(request).sort().join(',') === 'ciphertext,last,nonce,op' && request.last === true)) &&
            typeof request.ciphertext === 'string' && typeof request.nonce === 'string' && /^[a-f0-9]{64}$/.test(request.nonce)) {
          calledNonce = request.nonce;
          const ciphertext = await sessions.execute(request.nonce, request.ciphertext, { last: request.last === true });
          // Lets the relay keep its admission lease while the enclave keeps the
          // session for a follow-up request, and release it once it is gone.
          reply = { ciphertext, sessionOpen: sessions.hasPendingSession?.(request.nonce) === true };
        } else throw new Error();
      } catch (error) {
        // Only the enclave manager can confirm the slot is gone. A generic
        // socket error or a rejected duplicate while work is pending cannot.
        reply = { error: 'unavailable', sessionClosed: calledNonce !== undefined &&
          sessions.hasPendingSession !== undefined && !sessions.hasPendingSession(calledNonce),
          // Refused before any work; see ChannelSessionRejected.
          ...(calledNonce !== undefined && error instanceof ChannelSessionRejected ? { session: error.session } : {}) };
      }
      socket.end(frame(reply));
    });
  });
}

/** Routes by operation prefix only: `case.*` to the owner dispatcher, `legal.*`
 * to the firm dispatcher (absent when no legal identity policy is configured).
 * Each dispatcher re-parses and fully validates its own request. */
export function createCaseChannelDispatch(owner: ChannelDispatch, legal: ChannelDispatch | null): ChannelDispatch {
  return async (body, context) => {
    let operation: unknown;
    try {
      if (body instanceof Uint8Array && body.length <= 256 * 1024) {
        operation = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))?.operation;
      }
    } catch { /* denied below */ }
    if (typeof operation === 'string' && operation.startsWith('case.')) return owner(body, context);
    if (legal && typeof operation === 'string' && operation.startsWith('legal.')) return legal(body, context);
    throw new Error('Confidential case operation unavailable');
  };
}

/** Hardware and deployment bindings of the enclave process. Production uses
 * `productionDependencies()` only: the measured file baked into the image, the
 * NSM-backed channel identity, the storage bridge on 127.0.0.1:5005 and the
 * session port 5004. The local browser test stack (qa/e2e) supplies synthetic
 * NSM evidence and loopback ports; it is an internal composition seam like
 * `createSessionCore`, never reachable from a frame, request or environment variable. */
export type ConfidentialServerDependencies = {
  measuredConfiguration: Uint8Array;
  identityFactory: typeof createApplicationChannelIdentity;
  storage: RpcOptions;
  port: number;
  sessionClock: () => number;
  retry?: Parameters<typeof retryBounded>[1];
  /** Test-only (qa/e2e): moves this composition's time forward, for example past
   * a grant's end. Never set by `productionDependencies()`. */
  timeShift?: TimeShift;
};
/** A forward-only offset that the local browser stack adds, together, to the
 * synthetic NSM timestamps, its own process's wall clock (which OpenPGP signature
 * times are checked against), the trusted clock's host clock (`now`) and its
 * participants' clocks, so attested time moves as if that much time had passed.
 * `onShift` listeners run (and are awaited) after each change. */
export type TimeShift = { offsetMs(): number; now(): number; onShift(listener: () => Promise<void>): void };

function productionDependencies(): ConfidentialServerDependencies {
  return { measuredConfiguration: new Uint8Array(readFileSync('/app/confidential-config.json')),
    identityFactory: createApplicationChannelIdentity, storage: {}, port: PORT, sessionClock: () => performance.now() };
}

/** Keyrings this process holds, zeroed by the fatal handler. */
const liveKeyrings = new Set<CaseKeyring>();

export async function startConfidentialServer(): Promise<net.Server> {
  return composeConfidentialServer(productionDependencies());
}

export async function composeConfidentialServer(deps: ConfidentialServerDependencies): Promise<net.Server> {
  const rpc = deps.storage;
  const remote = createRemoteCaseStore(rpc);
  // Obtain and self-verify this enclave's release identity before serving. Until
  // the host supplies a manifest matching our own NSM measurements, nothing
  // listens. Retries are bounded; on exhaustion this process exits and the
  // entrypoint supervisor restarts it with backoff, never stopping legacy crypto.
  const measuredConfiguration = deps.measuredConfiguration;
  const { releaseDigest, legalPolicyPin, administration, withdrawalKey, roughtime } = await retryBounded(async () => {
    const manifest = await fetchReleaseManifest(rpc);
    const self = await deps.identityFactory(randomBytes(32).toString('hex'));
    try {
      const verifiedRelease = await verifySelfRelease(manifest, new Uint8Array(Buffer.from(self.evidence.document, 'base64')));
      return { releaseDigest: verifiedRelease, legalPolicyPin: await verifyMeasuredConfiguration(manifest, measuredConfiguration),
        administration: await measuredLegalAdministration(manifest, measuredConfiguration),
        withdrawalKey: await measuredReleaseWithdrawalKey(manifest, measuredConfiguration),
        roughtime: await measuredRoughtimePolicy(manifest, measuredConfiguration) };
    } finally { self.close(); }
  }, deps.retry);
  // Trusted time: anchored on local NSM attestation timestamps plus a monotonic
  // clock; the host clock is only a consistency check (see trustedClock.ts).
  // When the measured configuration pins Roughtime servers, NSM time must also
  // agree with their signed answers, relayed (unforgeably) by the host.
  const shift = deps.timeShift;
  const trusted = await retryBounded(() => createTrustedClock({ attest: async () => {
    const identity = await deps.identityFactory(randomBytes(32).toString('hex'));
    try { return new Uint8Array(Buffer.from(identity.evidence.document, 'base64')); } finally { identity.close(); }
  }, ...(shift ? { hostClock: shift.now } : {}), ...(roughtime ? { external: { quorum: roughtime.quorum, toleranceMs: roughtime.toleranceMs,
    sample: monotonic => sampleRoughtime(roughtime.servers, (address, packet) => roughtimeExchange(rpc, address, packet), monotonic) } } : {}),
  }), deps.retry);
  // A shift moves the host clock past the anchor; re-anchor on a (shifted) NSM document.
  shift?.onShift(() => trusted.refresh());
  const clock = () => trusted.now();
  // The measured image pins the identity policy; host substitution cannot enable
  // another issuer or JWKS. A disabled policy never needs a host RPC response.
  const policy: LegalIdentityPolicy | null = legalPolicyPin === null ? null :
    await retryBounded(async () => verifyMeasuredLegalPolicy(legalPolicyPin, await fetchLegalIdentityPolicy(rpc)), deps.retry);
  const keyring = createCaseKeyring({ clock });
  liveKeyrings.add(keyring);
  const options = { store: authenticatedRoster(createSealedCaseStore(remote, keyring), administration?.onboardingPublicKey, clock, administration?.initialApprovalPublicKey), keyring, clock, audience: AUDIENCE, releaseDigest };
  let legal: ChannelDispatch | null = null;
  if (policy) {
    try { legal = createLegalCaseDispatcher({ ...options, identity: policy, members: createRemoteLegalMembershipStore(rpc),
      enrollment: createRemoteEnrollmentStore(rpc), administration, firm: createRemoteLegalFirmStore(rpc) }); }
    catch { process.stderr.write('Confidential legal operations disabled: invalid identity policy\n'); }
  }
  // Withdrawn or unconfirmed release: pause all case operations (never switch
  // release). Disabled when the measured configuration pins no withdrawal key.
  const withdrawal = await createReleaseWithdrawalGuard({ publicKey: withdrawalKey, releaseDigest,
    fetchList: () => fetchReleaseWithdrawals(rpc), clock });
  const sessions = createSessionCore(withdrawal.wrap(
    createCaseChannelDispatch(createOwnerCaseControlDispatcher(options), legal)), deps.identityFactory, deps.sessionClock);
  const server = createConfidentialFrameServer(sessions);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(deps.port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  return server;
}

if (require.main === module) {
  installFatalHandlers('Confidential case server', () => { for (const keyring of liveKeyrings) keyring.clear(); });
  // Exits on failure; enclave/entrypoint.sh supervises and restarts this process.
  startConfidentialServer().catch(() => { process.stderr.write('Confidential case server failed\n'); process.exit(1); });
}
