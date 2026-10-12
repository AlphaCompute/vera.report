import { updateSummary, declineAccess, ConfidentialRollbackError } from '../../../lib/confidential/ownerCase';
import type { OwnerSession, OwnerInbox, VerifiedRequest } from '../../../lib/confidential/ownerCase';

test('retained history conflicts stop both signing and request mutation before relay work', async () => {
  const relay = { open: jest.fn(), call: jest.fn() };
  const assertDeviceHistory = jest.fn(() => { throw new ConfidentialRollbackError(); });
  const session = { assertDeviceHistory, relay } as unknown as OwnerSession;
  await expect(updateSummary(session, {} as OwnerInbox, 'Published summary', Date.now()))
    .rejects.toBeInstanceOf(ConfidentialRollbackError);
  // A request decline uses the operation guard, rather than checkpoint signing.
  session.trust = { caseId: 'a'.repeat(64) } as OwnerSession['trust'];
  await expect(declineAccess(session, { delivery: { organizationId: 'b'.repeat(64), requestId: 'c'.repeat(64) } } as VerifiedRequest, Date.now()))
    .rejects.toBeInstanceOf(ConfidentialRollbackError);
  expect(assertDeviceHistory).toHaveBeenCalledTimes(2);
  expect(relay.open).not.toHaveBeenCalled();
  expect(relay.call).not.toHaveBeenCalled();
});
