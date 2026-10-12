import { createApplicationChannelSessions } from '../application-channel-sessions.js';
import type { ChannelDispatch } from '../application-channel-sessions.js';
import { CaseServiceError, createCaseService } from './service.js';
import type { CaseServiceOptions } from './service.js';

type Options = Omit<CaseServiceOptions, 'channel'>;
const MAX_BODY = 128 * 1024;
/** One 512 KiB evidence chunk as base64 plus framing; see caseChunks.ts. */
export const CHUNK_REPLY_LIMIT = 720 * 1024;
function denied(): never { throw new Error('Owner case operation unavailable'); }

/** Bounded owner-control operations only. The session layer decrypts before
 * dispatch and encrypts the reply. Never mount this until the backing storage
 * satisfies encrypted private-state custody and independent freshness.
 * Evidence is read through `case.read-object`: bounded ranges or one chunk per reply.
 */
export function createOwnerCaseControlDispatcher(options: Options): ChannelDispatch {
  const settings = { ...options, limits: { ...options.limits } };
  return async (body, context) => {
    let operationBody: Uint8Array | undefined;
    try {
      if (!(body instanceof Uint8Array) || body.length > 192 * 1024 || context.signal.aborted) denied();
      const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
      if (!request || typeof request !== 'object' || Array.isArray(request)) denied();
      const service = createCaseService({ ...settings,
        channel: { nonce: context.nonce, serverKeyId: context.serverKeyId, authenticated: context.authenticated,
          challenges: context.challenges } });
      let result: unknown, replyLimit = 4096;
      if (request.operation === 'case.challenge') {
        // `{operation}` issues one challenge; `{operation, count}` a small batch for
        // the next operations of this same session (see session-challenges.ts).
        const fields = Object.keys(request).sort().join(',');
        if (fields === 'operation') result = await service.issueChallenge();
        else if (fields === 'count,operation' && Number.isSafeInteger(request.count)) result = await service.issueChallenges(request.count);
        else denied();
      } else if (request.operation === 'case.release-approvals') {
        if (Object.keys(request).sort().join(',') !== 'caseId,operation' || typeof request.caseId !== 'string') denied();
        result = await service.releaseApprovals(request.caseId);
        replyLimit = 128 * 1024;
      } else if (request.operation === 'case.recovery-package') {
        // Account-free recovery: the package is ciphertext under a participant secret.
        if (Object.keys(request).sort().join(',') !== 'caseId,operation' || typeof request.caseId !== 'string') denied();
        result = await service.getRecoveryPackage(request.caseId);
        replyLimit = 160 * 1024;
      } else {
        // Private conversation is retired: no owner message delivery route.
        // Keep legacy inbox ciphertext readable without changing signed case formats.
        const handlers: Record<string, [(body: Uint8Array, proof: string) => Promise<unknown>, number]> = {
          'case.publish-case': [(b, p) => service.publishCase(b, p), 4096],
          'case.decline-request': [(b, p) => service.declineAccessRequest(b, p), 4096],
          'case.commit-transition': [(b, p) => service.commitTransition(b, p), 4096],
          'case.unlock-case': [(b, p) => service.unlockCase(b, p, null), 4096],
          'case.read-state-keys': [(b, p) => service.getStateEnvelopes(b, p, null), 240 * 1024],
          'case.read-inbox': [(b, p) => service.readInbox(b, p), 240 * 1024],
          'case.read-owner-envelopes': [(b, p) => service.readOwnerEnvelopes(b, p), 240 * 1024],
          'case.read-legal-roster': [(b, p) => service.legalRoster(b, p), 240 * 1024],
          'case.read-state': [(b, p) => service.readState(b, p), 240 * 1024],
          'case.read-object': [(b, p) => service.readObject(b, p), CHUNK_REPLY_LIMIT],
        };
        const handler = Object.prototype.hasOwnProperty.call(handlers, request.operation) ? handlers[request.operation] : null;
        if (Object.keys(request).sort().join(',') !== 'body,operation,proof' || !handler ||
            typeof request.proof !== 'string' || request.proof.length > 20000 ||
            typeof request.body !== 'string' || request.body.length > Math.ceil(MAX_BODY / 3) * 4) denied();
        operationBody = new Uint8Array(Buffer.from(request.body, 'base64'));
        if (operationBody.length > MAX_BODY || Buffer.from(operationBody).toString('base64') !== request.body) denied();
        if (context.signal.aborted) denied();
        try {
          result = await handler![0](operationBody, request.proof);
        } catch (error) {
          // The client must learn these two states to prompt unlock or release
          // approval; the reply is encrypted to it, so the host learns nothing.
          if (error instanceof CaseServiceError && (error.code === 'locked' || error.code === 'release-not-approved')) {
            result = { error: error.code };
          } else throw error;
        }
        replyLimit = handler![1];
      }
      if (context.signal.aborted) denied();
      const reply = new TextEncoder().encode(JSON.stringify(result));
      if (reply.length > replyLimit) { reply.fill(0); denied(); }
      return reply;
    } catch { return denied(); } finally { operationBody?.fill(0); }
  };
}

/** Fixed production attestor; no caller-selected key, helper or plaintext route. */
export function createOwnerCaseControlChannel(options: Options) {
  return createApplicationChannelSessions(createOwnerCaseControlDispatcher(options));
}
