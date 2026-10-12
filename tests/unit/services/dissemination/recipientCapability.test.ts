import crypto from 'node:crypto';
import { sealCapability, recipientCaseReference } from '../../../../src/services/dissemination/recipientCapability';
import { makeWorkspaceToken, verifyWorkspaceToken } from '../../../../src/services/dissemination/counselWorkspace';
import { makeEscrowToken, verifyEscrowToken } from '../../../../src/services/dissemination/escrowRelease';
import { makeSecureLinkToken, verifySecureLinkToken } from '../../../../src/services/dissemination/secureLink';

const reporterCredential = 'VRA-ABCDEF0123456789';
beforeEach(() => { process.env.DISSEMINATION_WEBHOOK_SECRET = 'capability-test-secret'; });
it('all recipient capabilities conceal the reporter credential and reject cross-purpose use', () => {
  const tokens = [makeWorkspaceToken(reporterCredential, 'eeoc', 'assignment'), makeEscrowToken(reporterCredential, 'eeoc', 'binding'), makeSecureLinkToken(reporterCredential)];
  const verifiers = [verifyWorkspaceToken, verifyEscrowToken, verifySecureLinkToken];
  tokens.forEach((token, index) => {
    expect(token).not.toContain(reporterCredential);
    for (const piece of token.split('.')) expect(Buffer.from(piece, 'base64url').toString()).not.toContain(reporterCredential);
    verifiers.forEach((verify, purpose) => expect(verify(token)?.trackingId ?? null).toBe(index === purpose ? reporterCredential : null));
    const pieces = token.split('.');
    const bytes = Buffer.from(pieces[2], 'base64url'); bytes[0] ^= 1; pieces[2] = bytes.toString('base64url');
    expect(verifiers[index](pieces.join('.'))).toBeNull();
  });
});
it('rejects every legacy readable signed token even with valid expiry and binding', () => {
  const payload = Buffer.from(JSON.stringify({ trackingId: reporterCredential, entityId: 'eeoc', assignmentKey: 'assignment', binding: 'binding', kind: 'escrow', exp: Date.now() + 10000 })).toString('base64url');
  const token = payload + '.' + crypto.createHmac('sha256', process.env.DISSEMINATION_WEBHOOK_SECRET!).update(payload).digest('base64url');
  expect(verifyWorkspaceToken(token)).toBeNull(); expect(verifyEscrowToken(token)).toBeNull(); expect(verifySecureLinkToken(token)).toBeNull();
});
it('rejects expired authenticated capabilities and uses non-authorizing channel-specific references', () => {
  expect(verifyWorkspaceToken(sealCapability('workspace', { trackingId: reporterCredential, entityId: 'eeoc', assignmentKey: 'a', exp: Date.now() - 1 }))).toBeNull();
  const reference = recipientCaseReference(reporterCredential, 'eeoc');
  expect(reference).toMatch(/^CASE-[a-f0-9]{24}$/);
  expect(reference).not.toMatch(/^VRA-[A-F0-9]{16}$/);
  expect(reference).not.toBe(recipientCaseReference(reporterCredential, 'sec-tcr'));
});
