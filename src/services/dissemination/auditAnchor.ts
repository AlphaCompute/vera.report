/**
 * Merkle-root audit anchors (Phase 4b, VERA-PDR-001 §16 follow-up).
 *
 * The dissemination audit log is append-only by convention; anchoring
 * made it tamper-EVIDENT: a periodic job batched new audit events, built a
 * Merkle tree over their canonical hashes, and anchored the root on Midnight.
 * That job no longer runs. This module serves the anchors already recorded:
 * history export and per-event inclusion proofs. A local proof is not chain
 * evidence. Version 2 binds the batch root, count and previous committed root.
 * Historical unversioned roots do not authenticate their prevRoot link.
 * Event inclusion is verifiable against an independently trusted root;
 * this does not establish completeness or integrity of the batch history.
 */

import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { disseminationPersistence } from './disseminationPersistence';
import type { AuditAnchorDoc, AuditEventDoc, AuditHistoryEntry } from './types';

const MAX_BATCH = 2048;

function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Canonical leaf hash for an audit event. Key order is fixed here — not
 * inherited from the document — so the hash is stable across storage
 * round-trips.
 */
export function hashAuditEvent(event: AuditEventDoc): string {
  return sha256(
    JSON.stringify({
      eventId: event.eventId,
      trackingId: event.trackingId,
      entityId: event.entityId ?? null,
      event: event.event,
      actor: event.actor,
      at: new Date(event.at).toISOString(),
      detail: event.detail ?? null,
    }),
  );
}

function parentHash(left: string, right: string): string {
  return sha256(left + right);
}

/** Merkle root over ordered leaf hashes (odd nodes promoted unchanged). */
export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) throw new Error('Cannot build a Merkle tree over zero leaves');
  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? parentHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

export interface InclusionStep {
  hash: string;
  position: 'left' | 'right';
}

/** Sibling path from a leaf to the root; verify with verifyInclusion. */
export function inclusionProof(leaves: string[], index: number): InclusionStep[] {
  if (index < 0 || index >= leaves.length) throw new Error('Leaf index out of range');
  const proof: InclusionStep[] = [];
  let level = leaves;
  let i = index;
  while (level.length > 1) {
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) {
      if (j + 1 < level.length) {
        next.push(parentHash(level[j], level[j + 1]));
      } else {
        next.push(level[j]);
      }
    }
    const sibling = i % 2 === 0 ? i + 1 : i - 1;
    if (sibling < level.length) {
      proof.push({ hash: level[sibling], position: sibling < i ? 'left' : 'right' });
    }
    i = Math.floor(i / 2);
    level = next;
  }
  return proof;
}

export function verifyInclusion(leafHash: string, proof: InclusionStep[], root: string): boolean {
  let current = leafHash;
  for (const step of proof) {
    current = step.position === 'left' ? parentHash(step.hash, current) : parentHash(current, step.hash);
  }
  return current === root;
}

export type AuditCommitment = Pick<AuditAnchorDoc, 'root' | 'commitmentVersion' | 'batchRoot' | 'eventCount' | 'prevRoot'>;
const isDigest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

export function auditCommitmentRoot(batchRoot: string, eventCount: number, prevRoot?: string): string {
  if (!isDigest(batchRoot) || !Number.isSafeInteger(eventCount) || eventCount < 1 || eventCount > MAX_BATCH ||
      (prevRoot !== undefined && !isDigest(prevRoot))) throw new Error('Invalid audit commitment');
  return sha256(JSON.stringify(['vera:audit:history:v2', batchRoot, eventCount, prevRoot ?? null]));
}

/** Checks inclusion against a caller-trusted commitment; does not establish trust in that root. */
export function verifyAuditInclusion(leafHash: string, proof: InclusionStep[], anchor: AuditCommitment): boolean {
  try {
    if (!isDigest(leafHash) || !isDigest(anchor.root) || !Array.isArray(proof) || proof.length > 11 ||
        proof.some(step => !step || !isDigest(step.hash) || !['left', 'right'].includes(step.position))) return false;
    if (anchor.commitmentVersion === undefined) {
      return anchor.batchRoot === undefined && verifyInclusion(leafHash, proof, anchor.root);
    }
    return anchor.commitmentVersion === 2 && isDigest(anchor.batchRoot) &&
      auditCommitmentRoot(anchor.batchRoot, anchor.eventCount, anchor.prevRoot) === anchor.root &&
      verifyInclusion(leafHash, proof, anchor.batchRoot);
  } catch { return false; }
}

export interface AuditHistoryPage {
  head: string;
  checkpoint: string | null;
  anchors: AuditHistoryEntry[];
  nextRoot: string | null;
  complete: boolean;
  stopReason: 'checkpoint' | 'page_limit' | 'legacy_boundary' | 'missing_anchor' | 'checkpoint_unreachable';
}

export class AuditAnchorService {
  private stopping = false;
  private readonly operations = new Set<Promise<unknown>>();

  async close(): Promise<void> {
    this.stopping = true;
    const results = await Promise.allSettled([...this.operations]);
    const failure = results.find(result => result.status === 'rejected');
    if (failure?.status === 'rejected') throw failure.reason;
  }

  exportHistory(head: string, checkpoint: string | null, limit = 100): Promise<AuditHistoryPage> {
    if (this.stopping) return Promise.reject(new Error('Audit service is stopping'));
    const operation = this.readHistory(head, checkpoint, limit).finally(() => this.operations.delete(operation));
    this.operations.add(operation);
    return operation;
  }

  private async readHistory(head: string, checkpoint: string | null, limit: number): Promise<AuditHistoryPage> {
    if (!isDigest(head) || (checkpoint !== null && !isDigest(checkpoint)) || !Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error('Invalid audit history request');
    }
    const deadline = performance.now() + 10_000;
    const anchors: AuditHistoryEntry[] = [];
    const seen = new Set<string>();
    let nextRoot: string | null = head;
    let stopReason: 'page_limit' | 'legacy_boundary' | 'missing_anchor' = 'page_limit';
    while (nextRoot !== checkpoint && nextRoot !== null && anchors.length < limit) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) throw new Error('Audit history traversal timed out');
      if (seen.has(nextRoot)) throw new Error('Cyclic audit history');
      seen.add(nextRoot);
      const entry = await disseminationPersistence.findAuditHistoryEntry(nextRoot, Math.max(1, Math.min(Math.floor(remaining), 1000)));
      if (performance.now() >= deadline) throw new Error('Audit history traversal timed out');
      if (!entry) { stopReason = 'missing_anchor'; break; }
      if (entry.commitmentVersion === undefined) { stopReason = 'legacy_boundary'; break; }
      if (entry.commitmentVersion !== 2 || !isDigest(entry.batchRoot) ||
          auditCommitmentRoot(entry.batchRoot, entry.eventCount, entry.prevRoot) !== nextRoot) throw new Error('Invalid audit history commitment');
      if ((entry.proofHash !== undefined && !isDigest(entry.proofHash)) ||
          (entry.txHash !== undefined && (typeof entry.txHash !== 'string' || !entry.txHash.length || entry.txHash.length > 512)) ||
          !['local', 'midnight'].includes(entry.network)) throw new Error('Invalid audit history receipt metadata');
      anchors.push(entry);
      nextRoot = entry.prevRoot ?? null;
    }
    const complete = nextRoot === checkpoint;
    return { head, checkpoint, anchors, nextRoot, complete,
      stopReason: complete ? 'checkpoint' : nextRoot === null ? 'checkpoint_unreachable' : stopReason };
  }

  /**
   * Inclusion proof for one audit event: which anchor holds it, the
   * sibling path to the root, and whether the stored event still hashes
   * to its anchored leaf (tamper check).
   */
  async proveEvent(event: AuditEventDoc): Promise<{
    anchored: boolean;
    tampered?: boolean;
    root?: string;
    commitmentVersion?: 2;
    batchRoot?: string;
    eventCount?: number;
    prevRoot?: string;
    txHash?: string;
    network?: string;
    anchoredAt?: Date;
    proof?: InclusionStep[];
  }> {
    const anchor = await disseminationPersistence.findAnchorForEvent(event.eventId);
    if (!anchor) return { anchored: false };

    const isHash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
    if (!isHash(anchor.root) || !Array.isArray(anchor.leaves) || anchor.leaves.length === 0 ||
        anchor.leaves.length > MAX_BATCH || anchor.eventCount !== anchor.leaves.length ||
        anchor.leaves.some(leaf => !leaf || typeof leaf.eventId !== 'string' || !leaf.eventId || !isHash(leaf.leafHash)) ||
        new Set(anchor.leaves.map(leaf => leaf.eventId)).size !== anchor.leaves.length) {
      throw new Error('Invalid stored audit anchor');
    }
    const index = anchor.leaves.findIndex((l) => l.eventId === event.eventId);
    if (index < 0) throw new Error('Audit anchor does not contain the requested event');
    const leafHashes = anchor.leaves.map((l) => l.leafHash);
    const proof = inclusionProof(leafHashes, index);
    const currentHash = hashAuditEvent(event);
    // Matching the stored leaf alone does not validate the sibling path or root.
    const tampered = currentHash !== anchor.leaves[index].leafHash ||
      !verifyAuditInclusion(currentHash, proof, anchor);

    return {
      anchored: true,
      tampered,
      root: anchor.root,
      commitmentVersion: anchor.commitmentVersion,
      batchRoot: anchor.batchRoot,
      eventCount: anchor.eventCount,
      prevRoot: anchor.prevRoot,
      txHash: anchor.txHash,
      network: anchor.txHash ? anchor.network : 'local',
      anchoredAt: anchor.anchoredAt,
      proof,
    };
  }
}

export const auditAnchorService = new AuditAnchorService();
