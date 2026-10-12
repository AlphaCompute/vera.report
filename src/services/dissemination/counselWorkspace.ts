import { sealCapability, openCapability } from './recipientCapability';
/**
 * Scoped counsel workspace links (Phase 3b, VERA-PDR-001 Tier C).
 *
 * Counsel receives the redacted packet (and pre-filled filing form where
 * one exists) through a time-limited, authenticated encrypted link — no Auth0 account,
 * no admin access, no reporter identity. The token scopes exactly one
 * (trackingId, entityId) pair; tampering with either invalidates the
 * signature.
 */

import crypto from 'node:crypto';
import type { CounselAssignment } from './types';

const DEFAULT_TTL_DAYS = 30;

export interface WorkspaceScope {
  trackingId: string;
  entityId: string;
  assignmentKey: string;
  exp: number; // epoch millis
}


export function makeWorkspaceToken(
  trackingId: string,
  entityId: string,
  assignmentKey: string,
  ttlDays = DEFAULT_TTL_DAYS,
): string {
  const scope: WorkspaceScope = {
    trackingId,
    entityId,
    assignmentKey,
    exp: Date.now() + ttlDays * 24 * 3600 * 1000,
  };
  return sealCapability('workspace', scope);
}

export function verifyWorkspaceToken(token: string): WorkspaceScope | null {
  try {
    const scope = openCapability('workspace', token) as WorkspaceScope;
    if (
      typeof scope.trackingId !== 'string' ||
      typeof scope.entityId !== 'string' ||
      typeof scope.assignmentKey !== 'string' || !scope.assignmentKey ||
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

/** Bind tokens to the current counsel and matter; legacy unbound tokens fail closed. */
export function workspaceAssignmentKey(assignment: CounselAssignment): string {
  return crypto.createHash('sha256').update(JSON.stringify([
    assignment.counselId, assignment.matterCode,
  ])).digest('hex');
}

/** Absolute workspace URL for sharing with counsel. */
export function workspaceUrl(trackingId: string, entityId: string, assignment: CounselAssignment): string {
  const base =
    process.env.DISSEMINATION_PUBLIC_BASE_URL ||
    process.env.APP_BASE_URL ||
    'http://localhost:3001';
  const token = makeWorkspaceToken(trackingId, entityId, workspaceAssignmentKey(assignment));
  return `${base.replace(/\/$/, '')}/api/dissemination/counsel-workspace/${token}`;
}
