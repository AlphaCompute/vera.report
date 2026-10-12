import { LEGAL_SETUP_CLAIM, membershipInvitation, setupFromIdentityToken } from '../../../lib/confidential/legalSetup';

const config = { domain: 'identity.example', clientId: 'legal-client', audience: 'legal-api', organization: 'org_approved' };
const setup = { organizationId: 'a'.repeat(64), providerOrganizationId: 'org_approved', domain: 'counsel.example', displayName: 'Approved Counsel' };
const claims = { iss: 'https://identity.example/', azp: config.clientId, aud: config.audience, org_id: config.organization,
  exp: Math.floor(Date.now() / 1000) + 240, [LEGAL_SETUP_CLAIM]: setup };
const jwt = (body: unknown) => `e30.${Buffer.from(JSON.stringify(body)).toString('base64url')}.synthetic`;

test('setup projects only the current organization labels from an identity response', () => {
  expect(setupFromIdentityToken(jwt({ ...claims, [LEGAL_SETUP_CLAIM]: { ...setup, secret: 'drop' } }), config)).toEqual(setup);
  expect(setupFromIdentityToken(jwt({ ...claims, aud: [config.audience, 'userinfo'] }), config)).toEqual(setup);
});
test.each([
  { iss: 'https://foreign.example/' }, { azp: 'other-client' }, { aud: 'other-api' }, { org_id: 'org_other' },
  { exp: 1 }, { exp: 'later' }, { [LEGAL_SETUP_CLAIM]: undefined },
  { [LEGAL_SETUP_CLAIM]: { ...setup, domain: 'https://counsel.example/' } },
  { [LEGAL_SETUP_CLAIM]: { ...setup, organizationId: 'org_approved' } },
  { [LEGAL_SETUP_CLAIM]: { ...setup, displayName: 'Bad\nName' } },
])('foreign, expired or malformed setup context is not offered: %j', change => {
  expect(setupFromIdentityToken(jwt({ ...claims, ...change }), config)).toBeNull();
});
test('a deployment pin and malformed JWT cannot supply setup context', () => {
  expect(setupFromIdentityToken(jwt(claims), { ...config, organization: 'org_elsewhere' })).toBeNull();
  for (const token of ['opaque', 'a.!!!!.c', 'a.' + 'a'.repeat(17_000) + '.c']) expect(setupFromIdentityToken(token, config)).toBeNull();
});

const origin = 'https://vera.example', invitation = 'a'.repeat(43);
test('only an exact same-site membership link is consumed in place', () => {
  expect(membershipInvitation(`${origin}/legal/enroll#invitation=${invitation}`, origin)).toBe(invitation);
  for (const link of [
    `https://foreign.example/legal/enroll#invitation=${invitation}`, `${origin}/legal#invitation=${invitation}`,
    `${origin}/legal/enroll?invitation=${invitation}`, `${origin}/legal/enroll#invitation=${invitation}&invitation=${invitation}`,
    `${origin}/legal/enroll#invitation=${invitation}&other=anything`, `https://user@vera.example/legal/enroll#invitation=${invitation}`,
    `${origin}/legal/enroll#invitation=short`,
  ]) expect(membershipInvitation(link, origin)).toBeNull();
});

test('setup labels are available only from the matching live login and disappear on sign-out', async () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const storage = new Map<string, string>();
  const location = { origin, pathname: '/legal', search: '', assign: jest.fn() };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {
    location, history: { replaceState: () => { location.search = ''; } }, sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
    },
  } });
  try {
    jest.resetModules();
    const api = require('../../../lib/confidential/legalAuth');
    const token = jwt(claims);
    jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ access_token: token, token_type: 'Bearer', expires_in: 240 })));
    expect(api.legalSetupContext(config)).toBeNull();
    await api.beginLegalSignIn(config, '/legal/enroll');
    const pending = JSON.parse(storage.get('vera-legal-auth-pending')!);
    location.search = `?code=synthetic&state=${pending.state}`;
    await api.completeLegalSignIn(config);
    expect(api.legalSetupContext(config)).toEqual(setup);
    expect(api.legalSetupContext({ ...config, organization: 'org_other' })).toBeNull();
    expect(JSON.stringify([...storage.values()])).not.toContain(token);
    expect(JSON.stringify([...storage.values()])).not.toContain(setup.domain);
    api.signOutLegal(config);
    expect(api.legalSetupContext(config)).toBeNull();
  } finally {
    jest.restoreAllMocks(); jest.resetModules();
    if (previous) Object.defineProperty(globalThis, 'window', previous); else delete (globalThis as any).window;
  }
});
