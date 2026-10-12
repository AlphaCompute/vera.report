import { completeLegalSetup, matchingMembershipLease } from '../../../lib/confidential/completeLegalSetup';
import { ConfidentialUnavailableError } from '../../../lib/confidential/client';
import { FirmCaseError, redeemInvitation } from '../../../lib/confidential/firmCase';
import { readMembershipStatus } from '../../../lib/confidential/firmOnboarding';
jest.mock('../../../lib/confidential/firmCase', () => ({
  ...jest.requireActual('../../../lib/confidential/firmCase'), redeemInvitation: jest.fn() }));
jest.mock('../../../lib/confidential/firmOnboarding', () => ({ readMembershipStatus: jest.fn() }));
const input = { invitation: 'signed-approval', firm: { organizationId: 'a'.repeat(64), recipientKeyId: 'b'.repeat(64) } } as any;
const lost = () => new ConfidentialUnavailableError('offline');
const enrolled = (leaseExpiresAt: number, keyMatches = true) => ({ state: 'enrolled', keyMatches, leaseExpiresAt, members: 1 });
beforeEach(() => jest.resetAllMocks());

test('activation redeems the signed approval with the held key', async () => {
  (redeemInvitation as jest.Mock).mockResolvedValue({});
  await completeLegalSetup(input, 0);
  expect(redeemInvitation).toHaveBeenCalledWith(input);
  expect(readMembershipStatus).not.toHaveBeenCalled();
});
test('a lost response is confirmed only by a newer matching membership', async () => {
  (redeemInvitation as jest.Mock).mockRejectedValue(lost());
  (readMembershipStatus as jest.Mock).mockResolvedValue(enrolled(Date.now() + 60_000));
  await expect(completeLegalSetup(input, 0)).resolves.toBeUndefined();
  expect(readMembershipStatus).toHaveBeenCalledWith(input);
});
test('an older membership cannot make a revoked or expired renewal link look accepted', async () => {
  const lease = Date.now() + 60_000;
  (redeemInvitation as jest.Mock).mockRejectedValue(lost());
  (readMembershipStatus as jest.Mock).mockResolvedValue(enrolled(lease));
  await expect(completeLegalSetup(input, lease)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
});
test('without a baseline read, a failed redemption is never treated as success', async () => {
  (redeemInvitation as jest.Mock).mockRejectedValue(lost());
  (readMembershipStatus as jest.Mock).mockResolvedValue(enrolled(Date.now() + 60_000));
  await expect(completeLegalSetup(input, null)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
  expect(readMembershipStatus).not.toHaveBeenCalled();
});
test.each([new FirmCaseError('wrong-firm-key'), new Error('This invitation link is not valid.')])('a local rejection is never recovered: %s', async error => {
  (redeemInvitation as jest.Mock).mockRejectedValue(error);
  (readMembershipStatus as jest.Mock).mockResolvedValue(enrolled(Date.now() + 60_000));
  await expect(completeLegalSetup(input, 0)).rejects.toBe(error);
  expect(readMembershipStatus).not.toHaveBeenCalled();
});
test.each([{ state: 'not-enrolled' }, { state: 'lapsed' }, enrolled(Date.now() + 60_000, false), enrolled(1)])(
  'never activates with invalid membership %j', async status => {
    (redeemInvitation as jest.Mock).mockRejectedValue(lost());
    (readMembershipStatus as jest.Mock).mockResolvedValue(status);
    await expect(completeLegalSetup(input, 0)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
  });
test('an unavailable membership check cannot confirm activation', async () => {
  (redeemInvitation as jest.Mock).mockRejectedValue(lost());
  (readMembershipStatus as jest.Mock).mockRejectedValue(new Error('Offline'));
  await expect(completeLegalSetup(input, 0)).rejects.toBeInstanceOf(ConfidentialUnavailableError);
});
test('the baseline is the matching lease, 0 without one, and null when unreadable', async () => {
  (readMembershipStatus as jest.Mock).mockResolvedValueOnce(enrolled(5000)).mockResolvedValueOnce(enrolled(5000, false))
    .mockResolvedValueOnce({ state: 'lapsed' }).mockRejectedValueOnce(new Error('Offline'));
  expect(await matchingMembershipLease(input)).toBe(5000);
  expect(await matchingMembershipLease(input)).toBe(0);
  expect(await matchingMembershipLease(input)).toBe(0);
  expect(await matchingMembershipLease(input)).toBeNull();
});
