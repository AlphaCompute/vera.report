import { legalApplicationProvisioner } from '../../../src/services/legalApplicationAuth0';

const env = { LEGAL_AUTH0_MGMT_DOMAIN: 'legal.example', LEGAL_AUTH0_MGMT_CLIENT_ID: 'synthetic-client',
  LEGAL_AUTH0_MGMT_CLIENT_SECRET: 'synthetic-secret', LEGAL_AUTH0_CONNECTION_ID: 'con_test' };
const policy = { issuer: 'https://legal.example/', clientId: 'legal-client', audience: 'https://legal-api.example' };
const org = { id: 'org_firm', name: `vera-legal-${'a'.repeat(32)}`, display_name: 'Murphy Law',
  metadata: { vera_application_version: '1', vera_application_id: 'a'.repeat(64), vera_domain: 'firm.example', vera_approval_status: 'pending' } };
const response = (body: unknown, status = 200) => new Response(status === 204 ? null : JSON.stringify(body), { status });
const token = () => response({ access_token: 'synthetic-token', token_type: 'Bearer', expires_in: 3600 });
const signal = () => AbortSignal.timeout(45000);
const provider = () => legalApplicationProvisioner(env, policy)!;
afterEach(() => jest.restoreAllMocks());

it('creates a pending application without an account, email or automatic membership', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response(org, 201));
  const { id: _id, ...pending } = org;
  expect(await provider().applicationOrganizations!.create(pending, signal())).toEqual(org);
  expect(JSON.parse(String(fetchMock.mock.calls[1][1]!.body))).toMatchObject({ metadata: { vera_approval_status: 'pending' },
    enabled_connections: [{ connection_id: 'con_test', assign_membership_on_login: false }] });
  expect(fetchMock.mock.calls.map(([url]) => new URL(String(url)).pathname)).toEqual(['/oauth/token', '/api/v2/organizations']);
});
it.each([401, 403, 429, 500])('does not mistake Auth0 HTTP %i for a deleted organization', async status => {
  jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({}, status));
  await expect(provider().applicationOrganizations!.getById(org.id, signal())).rejects.toThrow();
});
it('treats only an explicit 404 as an absent organization', async () => {
  jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({}, 404));
  expect(await provider().applicationOrganizations!.getById(org.id, signal())).toBeNull();
});
it('paginates and fails closed instead of deciding against an incomplete Auth0 directory', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token());
  fetchMock.mockImplementation(async () => response(Array(100).fill(org)));
  await expect(provider().applicationOrganizations!.list(signal())).rejects.toMatchObject({ code: 'lookup_limit' });
  expect(fetchMock).toHaveBeenCalledTimes(11);
});
it('rejects metadata beyond Auth0 limits before any request', async () => {
  const fetchMock = jest.spyOn(global, 'fetch');
  const directory = provider().applicationOrganizations!;
  await expect(directory.update({ ...org, metadata: { too_long: 'x'.repeat(256) } }, signal())).rejects.toMatchObject({ code: 'provider_configuration' });
  await expect(directory.update({ ...org, metadata: Object.fromEntries(Array.from({ length: 26 }, (_, i) => [`key${i}`, 'value'])) }, signal())).rejects.toThrow();
  expect(fetchMock).not.toHaveBeenCalled();
});
it('will not recreate an approved organization deleted between application lookup and provisioning', async () => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockResolvedValueOnce(response({}, 404));
  await expect(provider().organization({ id: 'a'.repeat(64), displayName: 'Murphy Law', domain: 'firm.example', email: 'lawyer@firm.example',
    lawyerName: 'Lawyer', jurisdiction: 'NC', registrationNumber: 'TEST', status: 'approved', createdAt: Date.now(), providerOrganizationId: org.id }, signal())).rejects.toMatchObject({ code: 'provider_binding' });
  expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith('/organizations') && init?.method === 'POST')).toBe(false);
});
it.each(['pending', 'denied'])('stale work cannot promote a %s organization or create its contact account', async status => {
  const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce(token()).mockImplementation(async () => response({ ...org, metadata: { ...org.metadata, vera_approval_status: status } }));
  const p = provider(), target = { providerOrganizationId: org.id, domain: 'firm.example', email: 'lawyer@firm.example', expires: Date.now() + 60000 };
  await expect(p.registrationApproval!(target, signal())).rejects.toMatchObject({ code: 'provider_binding' });
  await expect(p.createApprovedAccount!(target, signal())).rejects.toMatchObject({ code: 'provider_binding' });
  expect(fetchMock.mock.calls.filter(([url, init]) => !String(url).endsWith('/oauth/token') && init?.method !== 'GET')).toEqual([]);
});
