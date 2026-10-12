import { sealCapability, openCapability } from './recipientCapability';
/**
 * Evidence escrow release (VERA-PDR-001 §10 / FR-5).
 *
 * Packets never carry decryption keys: agencies receive CIDs and digests,
 * and decryption is a separate, consent-gated escrow release. When an
 * agency asks for the underlying evidence, an admin releases escrow for
 * that channel, which mints a time-limited, authenticated encrypted token. The token
 * scopes one (trackingId, entityId) pair and grants access to the
 * decrypted evidence files through the existing decrypt chain — the keys
 * themselves are never handed over.
 */

import crypto from 'node:crypto';
import type { SubmissionDoc } from './types';
import { workspaceAssignmentKey } from './counselWorkspace';

const DEFAULT_TTL_DAYS = 14;

export interface EscrowScope {
  kind: 'escrow';
  trackingId: string;
  entityId: string;
  binding: string;
  exp: number; // epoch millis
}


export function makeEscrowToken(
  trackingId: string,
  entityId: string,
  binding: string,
  ttlDays = Number(process.env.ESCROW_TOKEN_TTL_DAYS) || DEFAULT_TTL_DAYS,
): string {
  const scope: EscrowScope = {
    kind: 'escrow',
    trackingId,
    entityId,
    binding,
    exp: Date.now() + ttlDays * 24 * 3600 * 1000,
  };
  return sealCapability('escrow', scope);
}

export function verifyEscrowToken(token: string): EscrowScope | null {
  try {
    const scope = openCapability('escrow', token) as EscrowScope;
    if (
      scope.kind !== 'escrow' ||
      typeof scope.trackingId !== 'string' ||
      typeof scope.entityId !== 'string' ||
      typeof scope.binding !== 'string' || !scope.binding ||
      typeof scope.exp !== 'number' || !Number.isFinite(scope.exp) ||
      scope.exp <= Date.now()
    ) {
      return null;
    }
    return scope;
  } catch {
    return null;
  }
}

/** Absolute escrow URL for handing to the receiving entity. */
export function escrowUrl(trackingId: string, entityId: string, binding: string): { url: string; token: string } {
  const base =
    process.env.DISSEMINATION_PUBLIC_BASE_URL ||
    process.env.APP_BASE_URL ||
    'http://localhost:3001';
  const token = makeEscrowToken(trackingId, entityId, binding);
  return { url: `${base.replace(/\/$/, '')}/api/dissemination/escrow/${token}`, token };
}

/** Withdrawn/replaced submissions and changed counsel invalidate prior releases. */
export function escrowBinding(submission: Pick<SubmissionDoc, 'submissionId' | 'counsel'>): string {
  return crypto.createHash('sha256').update(JSON.stringify([
    submission.submissionId, submission.counsel ? workspaceAssignmentKey(submission.counsel) : null,
  ])).digest('hex');
}
