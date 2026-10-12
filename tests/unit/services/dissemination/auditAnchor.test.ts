/**
 * Merkle audit anchor tests (Phase 4b): tree math, inclusion proofs against
 * historical anchors, previous-root references, tamper detection, and history
 * export draining.
 */

import crypto from 'node:crypto';
import {
  auditAnchorService,
  AuditAnchorService,
  auditCommitmentRoot,
  hashAuditEvent,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  verifyAuditInclusion,
} from '../../../../src/services/dissemination/auditAnchor';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';
import type { AuditAnchorDoc, AuditEventDoc } from '../../../../src/services/dissemination/types';

function leaf(seed: string): string {
  return crypto.createHash('sha256').update(seed).digest('hex');
}

let lastRoot: string | undefined;
/** Records a historical anchor over the unanchored events, as the retired anchoring job did. */
async function seedAnchor(receipt: Partial<Pick<AuditAnchorDoc, 'proofHash' | 'txHash' | 'network'>> = { proofHash: 'b'.repeat(64), txHash: '0xanchor-tx', network: 'midnight' }): Promise<AuditAnchorDoc | null> {
  const fresh = await disseminationPersistence.getUnanchoredAuditEvents();
  if (!fresh.length) return null;
  const leaves = fresh.map(event => ({ eventId: event.eventId, leafHash: hashAuditEvent(event) }));
  const batchRoot = merkleRoot(leaves.map(entry => entry.leafHash));
  const anchor: AuditAnchorDoc = {
    anchorId: crypto.randomUUID(), commitmentVersion: 2, batchRoot,
    root: auditCommitmentRoot(batchRoot, fresh.length, lastRoot), leaves, eventCount: fresh.length,
    firstEventAt: fresh[0].at, lastEventAt: fresh[fresh.length - 1].at, ...(lastRoot ? { prevRoot: lastRoot } : {}),
    network: 'local', anchoredAt: new Date(), ...receipt,
  };
  await disseminationPersistence.ensureAuditAnchor(anchor);
  lastRoot = anchor.root;
  return anchor;
}

describe('merkle tree math', () => {
  it('computes a stable root and rejects empty input', () => {
    const leaves = ['a', 'b', 'c', 'd', 'e'].map(leaf);
    const root = merkleRoot(leaves);
    expect(root).toMatch(/^[a-f0-9]{64}$/);
    expect(merkleRoot(leaves)).toBe(root);
    expect(merkleRoot([leaves[0]])).toBe(leaves[0]);
    expect(() => merkleRoot([])).toThrow();
  });

  it('inclusion proofs verify for every leaf, at every tree size', () => {
    for (let size = 1; size <= 9; size++) {
      const leaves = Array.from({ length: size }, (_, i) => leaf(`leaf-${i}`));
      const root = merkleRoot(leaves);
      for (let i = 0; i < size; i++) {
        const proof = inclusionProof(leaves, i);
        expect(verifyInclusion(leaves[i], proof, root)).toBe(true);
        // A different leaf must not verify with this proof.
        expect(verifyInclusion(leaf('forged'), proof, root)).toBe(false);
      }
    }
  });
});

describe('canonical event hashing', () => {
  const event: AuditEventDoc = {
    eventId: 'evt-1',
    trackingId: 'VRA-0000000000000001',
    entityId: 'cisa',
    event: 'channel_approved',
    actor: 'admin@test',
    detail: { idempotencyKey: 'k' },
    at: new Date('2026-07-01T00:00:00Z'),
  };

  it('is stable across storage round-trips and sensitive to edits', () => {
    const h1 = hashAuditEvent(event);
    const roundTripped = JSON.parse(JSON.stringify(event));
    roundTripped.at = new Date(roundTripped.at);
    expect(hashAuditEvent(roundTripped)).toBe(h1);

    expect(hashAuditEvent({ ...event, actor: 'attacker@evil' })).not.toBe(h1);
    expect(hashAuditEvent({ ...event, event: 'channel_withdrawn' })).not.toBe(h1);
  });
});

describe('historical anchors', () => {
  it('drains every accepted history export before shutdown even when another export fails', async () => {
    const worker = new AuditAnchorService();
    let rejectFirst!: (error: Error) => void;
    let finishSecond!: (value: null) => void;
    const firstRead = new Promise<null>((_resolve, reject) => { rejectFirst = reject; });
    const secondRead = new Promise<null>(resolve => { finishSecond = resolve; });
    const read = jest.spyOn(disseminationPersistence, 'findAuditHistoryEntry')
      .mockImplementationOnce(() => firstRead).mockImplementationOnce(() => secondRead);
    const first = worker.exportHistory(leaf('first-history'), null).catch(error => error);
    const second = worker.exportHistory(leaf('second-history'), null);
    let closed = false;
    const closing = worker.close().then(() => { closed = true; return null; }, error => { closed = true; return error; });
    try {
      rejectFirst(new Error('history lookup failed'));
      expect(await first).toEqual(new Error('history lookup failed'));
      expect(closed).toBe(false);
      await expect(worker.exportHistory(leaf('late-history'), null)).rejects.toThrow('Audit service is stopping');
      expect(read).toHaveBeenCalledTimes(2);
      finishSecond(null);
      expect((await second).stopReason).toBe('missing_anchor');
      expect(await closing).toEqual(new Error('history lookup failed'));
      expect(closed).toBe(true);
    } finally {
      rejectFirst(new Error('test cleanup')); finishSecond(null);
      await Promise.allSettled([first, second, closing]);
      read.mockRestore();
    }
  });

  it('proves inclusion against stored anchors that reference the previous root', async () => {
    const t1 = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    await disseminationPersistence.appendAudit({ trackingId: t1, event: 'channel_approved', actor: 'admin@test' });
    await disseminationPersistence.appendAudit({ trackingId: t1, event: 'dispatch_succeeded', actor: 'system', entityId: 'cisa' });

    const first = await seedAnchor();
    expect(first).not.toBeNull();
    expect(first!.eventCount).toBeGreaterThanOrEqual(2);

    await disseminationPersistence.appendAudit({ trackingId: t1, event: 'receipt_recorded', actor: 'admin@test' });
    const second = await seedAnchor();
    expect(second!.prevRoot).toBe(first!.root);

    // History export walks the stored chain back through the first anchor.
    const history = await auditAnchorService.exportHistory(second!.root, first!.root);
    expect(history).toMatchObject({ complete: true, stopReason: 'checkpoint' });
    expect(history.anchors.map(entry => entry.root)).toEqual([second!.root]);

    // Inclusion proof for a stored event verifies against its anchor root.
    const events = await disseminationPersistence.getAuditForReport(t1);
    const proved = await auditAnchorService.proveEvent(events[events.length - 1]);
    expect(proved.anchored).toBe(true);
    expect(proved.tampered).toBe(false);
    expect(verifyAuditInclusion(hashAuditEvent(events[events.length - 1]), proved.proof!, { ...proved, root: proved.root!, eventCount: proved.eventCount! })).toBe(true);
  });

  it('detects a tampered event against its anchored leaf', async () => {
    const t2 = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    await disseminationPersistence.appendAudit({ trackingId: t2, event: 'channel_approved', actor: 'admin@test' });
    await seedAnchor();

    const [event] = await disseminationPersistence.getAuditForReport(t2);
    const tamperedEvent = { ...event, actor: 'someone-else@evil' };
    const proved = await auditAnchorService.proveEvent(tamperedEvent);
    expect(proved.anchored).toBe(true);
    expect(proved.tampered).toBe(true);
  });

  it('detects root, sibling and ordering corruption and refuses malformed stored anchors', async () => {
    const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    for (let i = 0; i < 3; i++) {
      await disseminationPersistence.appendAudit({ trackingId, event: 'approved', actor: `actor-${i}` });
    }
    const anchor = (await seedAnchor())!;
    const events = await disseminationPersistence.getAuditForReport(trackingId);
    const event = events.find(candidate => candidate.eventId === anchor.leaves[0].eventId)!;
    const lookup = jest.spyOn(disseminationPersistence, 'findAnchorForEvent');
    try {
      for (const damage of ['root', 'sibling', 'order'] as const) {
        const corrupted = structuredClone(anchor);
        if (damage === 'root') corrupted.root = leaf('different-root');
        if (damage === 'sibling') corrupted.leaves[1].leafHash = leaf('different-sibling');
        if (damage === 'order') corrupted.leaves.reverse();
        lookup.mockResolvedValueOnce(corrupted);
        const result = await auditAnchorService.proveEvent(event);
        expect(result.tampered).toBe(true);
        expect(verifyAuditInclusion(hashAuditEvent(event), result.proof!, { ...result, root: result.root!, eventCount: result.eventCount! })).toBe(false);
      }
      for (const damage of ['count', 'duplicate', 'missing', 'hash', 'empty'] as const) {
        const corrupted = structuredClone(anchor);
        if (damage === 'count') corrupted.eventCount++;
        if (damage === 'duplicate') corrupted.leaves[1] = { ...corrupted.leaves[0] };
        if (damage === 'missing') corrupted.leaves[0].eventId = 'unrelated-event';
        if (damage === 'hash') corrupted.leaves[1].leafHash = 'invalid';
        if (damage === 'empty') corrupted.leaves = [];
        lookup.mockResolvedValueOnce(corrupted);
        await expect(auditAnchorService.proveEvent(event)).rejects.toThrow(/audit anchor|Audit anchor/);
      }
    } finally {
      lookup.mockRestore();
    }
  });

  it.each(['hash_commitment', 'compact_circuit'])('reports a %s anchor without a transaction as local evidence', async (proofType) => {
    const trackingId = `VRA-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    await disseminationPersistence.appendAudit({ trackingId, event: 'approved', actor: 'test' });
    const anchor = (await seedAnchor({ proofHash: leaf(`local-proof-${proofType}`), network: 'local' }))!;
    const [event] = await disseminationPersistence.getAuditForReport(trackingId);
    const proof = await auditAnchorService.proveEvent(event);
    expect(proof).toMatchObject({ anchored: true, tampered: false, network: 'local' });
    expect(verifyAuditInclusion(hashAuditEvent(event), proof.proof!, { ...proof, root: proof.root!, eventCount: proof.eventCount! })).toBe(true);

    // Historical labels must not turn a transaction-free record into chain evidence.
    const lookup = jest.spyOn(disseminationPersistence, 'findAnchorForEvent');
    try {
      lookup.mockResolvedValueOnce({ ...anchor, network: `midnight-${proofType}` });
      expect((await auditAnchorService.proveEvent(event)).network).toBe('local');
    } finally {
      lookup.mockRestore();
    }
  });
});

afterAll(async () => {
  await auditAnchorService.close();
});
