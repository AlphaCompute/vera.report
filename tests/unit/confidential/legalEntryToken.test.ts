import { exchangeLegalEntry } from '../../../lib/confidential/identityToken';
const now = Math.floor(Date.now() / 1000);
const claims = { iss: 'https://identity.example/', aud: 'legal-client', sub: 'email|approved', nonce: 'nonce',
  iat: now, exp: now + 300, 'https://vera.app/legal-entry': { organization: 'org_approved' } };
afterEach(() => jest.restoreAllMocks());
test.each([{ aud: 'other' }, { iss: 'https://foreign.example/' }, { nonce: 'replay' }, { exp: now - 1 },
  { iat: now + 100 }, { iat: now - 1000 }, { 'https://vera.app/legal-entry': { organization: 'bad' } }])('rejects an invalid entry binding: %j', async change => {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id_token:
    `${encode({ alg: 'RS256' })}.${encode({ ...claims, ...change })}.signature` })));
  await expect(exchangeLegalEntry('identity.example', 'legal-client', 'nonce', { code: 'code', code_verifier: 'verifier' })).rejects.toThrow();
});
