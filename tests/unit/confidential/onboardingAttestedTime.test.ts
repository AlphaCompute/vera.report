import { issueLegalInvitation } from '../../../lib/confidential/onboarding';
import { exchange, verifiedSession } from '../../../lib/confidential/client';
import { recordAttestedTime, resetTrustedTime, setAttestedTimeClocksForTests } from '../../../lib/confidential/attestedTime';
import { verifyFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { signMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import { signOrganizationRegistration } from '../../../enclave/src/confidential/organizationRegistration';

jest.mock('../../../lib/confidential/client', () => ({
  ...jest.requireActual('../../../lib/confidential/client'),
  verifiedSession: jest.fn(), exchange: jest.fn(),
}));
jest.mock('../../../enclave/src/confidential/firmKeyBinding', () => ({ verifyFirmKeyBinding: jest.fn() }));
jest.mock('../../../enclave/src/confidential/membershipAuthorization', () => ({ signMembershipAuthorization: jest.fn() }));
jest.mock('../../../enclave/src/confidential/organizationRegistration', () => ({ signOrganizationRegistration: jest.fn() }));

const T = 1_800_000_000_000, DAY = 86_400_000;
const input = {
  relay: { call: jest.fn() }, releaseManifest: 'synthetic-manifest', accessToken: 'synthetic-token',
  authority: {} as Parameters<typeof issueLegalInvitation>[0]['authority'],
  organizationId: 'a'.repeat(64), providerOrganizationId: 'org_synthetic', recipientKeyId: 'b'.repeat(64),
  subject: 'auth0|synthetic', now: T + 60_000, lifetimeMs: DAY,
  registration: { domain: 'counsel.example', displayName: 'Synthetic Counsel',
    bindingDocument: 'synthetic-binding', continuity: 'synthetic-signed-continuity' },
};

beforeEach(() => {
  jest.clearAllMocks();
  setAttestedTimeClocksForTests({ device: () => input.now, monotonic: () => 1000 });
  recordAttestedTime(T);
  jest.mocked(verifiedSession).mockResolvedValue({} as never);
  jest.mocked(verifyFirmKeyBinding).mockResolvedValue({
    binding: { recipientKeyId: input.recipientKeyId }, publicKey: { armor: () => 'synthetic-public-key' },
  } as never);
  jest.mocked(signMembershipAuthorization).mockResolvedValue('synthetic-membership');
  jest.mocked(signOrganizationRegistration).mockResolvedValue('synthetic-registration');
  jest.mocked(exchange).mockResolvedValue({ token: 't'.repeat(43), expiresAt: T + DAY });
});

afterEach(() => { setAttestedTimeClocksForTests(undefined); resetTrustedTime(); });

test('key continuity survives onboarding while both authorizations use attested time', async () => {
  await expect(issueLegalInvitation(input)).resolves.toEqual({ token: 't'.repeat(43), expiresAt: T + DAY });
  expect(signOrganizationRegistration).toHaveBeenCalledWith(expect.objectContaining({ issuedAt: T }), input.authority);
  expect(signMembershipAuthorization).toHaveBeenCalledWith(expect.objectContaining({ issuedAt: T, expiresAt: T + DAY }), input.authority);
  const request = jest.mocked(exchange).mock.calls[0][2];
  const body = JSON.parse(Buffer.from(request.body as string, 'base64').toString('utf8'));
  expect(body.registration).toMatchObject({ continuity: input.registration.continuity, authorization: 'synthetic-registration' });
  expect(body.authorization).toBe('synthetic-membership');
});

test('a response using the skewed device expiry is refused', async () => {
  jest.mocked(exchange).mockResolvedValue({ token: 't'.repeat(43), expiresAt: input.now + DAY });
  await expect(issueLegalInvitation(input)).rejects.toThrow();
});

test.each([null, T - 60_000])('signs only after the current session replaces the clock anchor (%s)', async previous => {
  resetTrustedTime();
  if (previous !== null) recordAttestedTime(previous);
  jest.mocked(verifiedSession).mockImplementation(async () => {
    expect(signOrganizationRegistration).not.toHaveBeenCalled();
    expect(signMembershipAuthorization).not.toHaveBeenCalled();
    expect(exchange).not.toHaveBeenCalled();
    recordAttestedTime(T);
    return {} as never;
  });
  await expect(issueLegalInvitation(input)).resolves.toEqual({ token: 't'.repeat(43), expiresAt: T + DAY });
  expect(signOrganizationRegistration).toHaveBeenCalledWith(expect.objectContaining({ issuedAt: T }), input.authority);
  expect(signMembershipAuthorization).toHaveBeenCalledWith(expect.objectContaining({ issuedAt: T, expiresAt: T + DAY }), input.authority);
});

test('failed attestation issues no registration or membership authorization', async () => {
  resetTrustedTime();
  jest.mocked(verifiedSession).mockRejectedValue(new Error('unverified session'));
  await expect(issueLegalInvitation(input)).rejects.toThrow();
  expect(signOrganizationRegistration).not.toHaveBeenCalled();
  expect(signMembershipAuthorization).not.toHaveBeenCalled();
  expect(exchange).not.toHaveBeenCalled();
});
