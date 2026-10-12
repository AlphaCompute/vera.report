import express from 'express';
import request from 'supertest';
import { createLegalEntryRouter } from '../../../src/api/legalEntry';

const secret = 'synthetic-entry-secret-'.repeat(3);
const body = { operation: 'lookup', clientId: 'legal-spa', connectionId: 'con_email', email: 'member@firm.example' };
function fixture(pending = true) {
  const target = { organizationId: 'a'.repeat(64), providerOrganizationId: 'org_approved', domain: 'firm.example', email: body.email, pending };
  const store = { legalSignInTarget: jest.fn(async () => target as typeof target | null), consumeLegalSignInApproval: jest.fn(async () => {}) };
  const provider = { organization: jest.fn(), invite: jest.fn(), existingMember: jest.fn(async () => null as string | null),
    completeSignIn: jest.fn(async () => 'email|approved') };
  const app = express().use('/entry', createLegalEntryRouter({ secret, connectionId: 'con_email', source: async () => ({ store, provider, clientId: 'legal-spa' }) }));
  return { store, provider, app, post: (value: object = body, auth = secret) => request(app).post('/entry').set('Authorization', `Bearer ${auth}`).send(value) };
}
test('approval lookup never creates a user or membership; verified completion attaches the exact subject', async () => {
  const f = fixture();
  expect((await f.post()).body).toEqual({ approved: true, organization: 'org_approved' });
  expect(f.provider.completeSignIn).not.toHaveBeenCalled();
  expect(f.store.consumeLegalSignInApproval).not.toHaveBeenCalled();
  const result = await f.post({ ...body, operation: 'complete', subject: 'email|approved' });
  expect(result.status).toBe(200);
  expect(f.provider.completeSignIn).toHaveBeenCalledWith(expect.objectContaining({ email: body.email }), 'email|approved', expect.any(AbortSignal), true);
  expect(f.store.consumeLegalSignInApproval).toHaveBeenCalledWith('a'.repeat(64), body.email, 'email|approved');
});
test('requires the private Action credential and pinned client/connection', async () => {
  const f = fixture();
  expect((await f.post(body, 'wrong')).status).toBe(401);
  expect((await f.post({ ...body, clientId: 'foreign' })).status).toBe(403);
  expect((await f.post({ ...body, connectionId: 'con_other' })).status).toBe(400);
  expect(f.provider.completeSignIn).not.toHaveBeenCalled();
  expect((await f.post({ ...body, padding: 'x'.repeat(3000) })).status).toBe(413);
});
test('same domain, unapproved/revoked firm and removed memberships do not allow sign-in', async () => {
  const f = fixture(false);
  expect((await f.post()).status).toBe(403);
  f.provider.existingMember.mockResolvedValue('email|approved');
  expect((await f.post()).status).toBe(200);
  expect((await f.post({ ...body, operation: 'complete', subject: 'email|attacker' })).status).toBe(403);
  f.store.legalSignInTarget.mockResolvedValue(null);
  expect((await f.post()).status).toBe(403);
  expect(f.provider.completeSignIn).not.toHaveBeenCalled();
});
test('failed identity verification or approval revocation during completion cannot consume approval', async () => {
  const f = fixture();
  f.provider.completeSignIn.mockRejectedValueOnce(new Error('unverified email'));
  const complete = { ...body, operation: 'complete', subject: 'email|approved' };
  expect((await f.post(complete)).status).toBe(403);
  f.store.legalSignInTarget.mockResolvedValueOnce({ organizationId: 'a'.repeat(64), providerOrganizationId: 'org_approved', domain: 'firm.example', email: body.email, pending: true }).mockResolvedValueOnce(null);
  expect((await f.post(complete)).status).toBe(403);
  expect(f.store.consumeLegalSignInApproval).not.toHaveBeenCalled();
});
