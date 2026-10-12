import express from 'express';
import request from 'supertest';
import router from '../../../src/api/dissemination';
import { disseminationPersistence } from '../../../src/services/dissemination/disseminationPersistence';
import { auditCommitmentRoot, hashAuditEvent, verifyAuditInclusion } from '../../../src/services/dissemination/auditAnchor';
import type { AuditAnchorDoc, AuditEventDoc } from '../../../src/services/dissemination/types';

const app = express().use('/api/dissemination', router);
const originalSecret = process.env.INTERNAL_API_SECRET;
afterEach(() => {
  jest.restoreAllMocks();
  if (originalSecret === undefined) delete process.env.INTERNAL_API_SECRET;
  else process.env.INTERNAL_API_SECRET = originalSecret;
});

it('labels historical transaction-free anchors as local at the authenticated list endpoint', async () => {
  process.env.INTERNAL_API_SECRET = 'synthetic-audit-test-secret';
  const anchors: AuditAnchorDoc[] = ['midnight-hash_commitment', 'midnight-compact_circuit', 'midnight'].map((network, index) => ({
    anchorId: `synthetic-${index}`, root: 'a'.repeat(64), leaves: [], eventCount: 0,
    firstEventAt: new Date(0), lastEventAt: new Date(0), anchoredAt: new Date(0),
    proofHash: 'b'.repeat(64), network,
    ...(index === 2 ? { txHash: 'synthetic-transaction' } : {}),
  }));
  const listing = jest.spyOn(disseminationPersistence, 'listAuditAnchors').mockResolvedValue(anchors);
  expect((await request(app).get('/api/dissemination/anchors')).status).toBe(401);
  expect(listing).not.toHaveBeenCalled();
  const response = await request(app).get('/api/dissemination/anchors')
    .set('x-internal-secret', process.env.INTERNAL_API_SECRET);
  expect(response.status).toBe(200);
  expect(response.body.success).toBe(true);
  expect(response.body.anchors.map((anchor: { network: string }) => anchor.network)).toEqual(['local', 'local', 'midnight']);
  expect(response.body.anchors[2].txHash).toBe('synthetic-transaction');
  expect(anchors.map(anchor => anchor.network)).toEqual(['midnight-hash_commitment', 'midnight-compact_circuit', 'midnight']);
});


it('returns verifiable history metadata through the actual list and inclusion handlers', async () => {
  process.env.INTERNAL_API_SECRET = 'synthetic-audit-test-secret';
  const event: AuditEventDoc = { eventId: 'history-event', trackingId: 'VRA-1234567890ABCDEF', event: 'approved', actor: 'synthetic', at: new Date(0) };
  const batchRoot = hashAuditEvent(event), prevRoot = 'a'.repeat(64);
  const anchor: AuditAnchorDoc = { anchorId: 'history-anchor', commitmentVersion: 2, batchRoot, prevRoot,
    root: auditCommitmentRoot(batchRoot, 1, prevRoot), leaves: [{ eventId: event.eventId, leafHash: batchRoot }], eventCount: 1,
    firstEventAt: event.at, lastEventAt: event.at, anchoredAt: event.at, network: 'local' };
  jest.spyOn(disseminationPersistence, 'listAuditAnchors').mockResolvedValue([anchor]);
  jest.spyOn(disseminationPersistence, 'getAuditForReport').mockResolvedValue([event]);
  const lookup = jest.spyOn(disseminationPersistence, 'findAnchorForEvent').mockResolvedValue(anchor);
  const list = await request(app).get('/api/dissemination/anchors').set('x-internal-secret', process.env.INTERNAL_API_SECRET);
  expect(list.status).toBe(200);
  expect(list.body.anchors[0]).toMatchObject({ root: anchor.root, batchRoot, commitmentVersion: 2, prevRoot, eventCount: 1 });
  const getProof = () => request(app).get('/api/dissemination/VRA-1234567890ABCDEF/audit-proofs').set('x-internal-secret', process.env.INTERNAL_API_SECRET!);
  const response = await getProof();
  expect(response.status).toBe(200);
  const proof = response.body.proofs[0];
  expect(proof).toMatchObject({ root: anchor.root, batchRoot, commitmentVersion: 2, prevRoot, eventCount: 1, tampered: false, network: 'local' });
  expect(verifyAuditInclusion(batchRoot, proof.proof, proof)).toBe(true);
  lookup.mockResolvedValueOnce({ ...anchor, prevRoot: 'b'.repeat(64) });
  const tampered = await getProof();
  expect(tampered.body.proofs[0].tampered).toBe(true);
});
