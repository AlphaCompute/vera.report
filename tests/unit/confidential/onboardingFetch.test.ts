import { issueLegalInvitation } from '../../../lib/confidential/onboarding';

test.each(['', 'x'.repeat(65537), '{}'])('rejects invalid submitted bindings without external fetching', async bindingDocument => {
  const original = global.fetch;
  const fetchMock = jest.fn(); global.fetch = fetchMock;
  const relay = { call: jest.fn() };
  try {
    await expect(issueLegalInvitation({ relay, releaseManifest: '', accessToken: '', authority: undefined as any,
      organizationId: 'a'.repeat(64), providerOrganizationId: 'org_test', recipientKeyId: 'b'.repeat(64), subject: 'auth0|member',
      now: Date.now(), registration: { domain: 'counsel.example', displayName: 'Counsel', bindingDocument } })).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(relay.call).not.toHaveBeenCalled();
  } finally { global.fetch = original; }
});
