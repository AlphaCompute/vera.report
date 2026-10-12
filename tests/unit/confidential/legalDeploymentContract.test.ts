import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { LEGAL_CALLBACK_PATH, authorizeUrl } from '../../../lib/confidential/legalAuth';

test('browser login returns to the legal page with scoped authorization', () => {
  expect(existsSync(resolve(__dirname, `../../../pages${LEGAL_CALLBACK_PATH}/index.tsx`))).toBe(true);
  const url = new URL(authorizeUrl({ domain: 'identity.example', clientId: 'legal-test', audience: 'https://legal.example',
    organization: null, connection: 'email' }, { challenge: 'challenge', state: 'state', mode: 'entry', redirectUri: `https://vera.example${LEGAL_CALLBACK_PATH}` }));
  expect(url.searchParams.get('redirect_uri')).toBe(`https://vera.example${LEGAL_CALLBACK_PATH}`);
  // Entry carries no legal authority or fixed firm. The approved routing claim
  // selects the organization for a separate legal API authorization.
  expect(url.searchParams.has('organization')).toBe(false);
  expect(url.searchParams.get('audience')).toBe('https://identity.example/userinfo');
  expect(url.searchParams.get('scope')).toBe('openid email');
  expect(url.searchParams.get('scope')?.split(' ')).not.toContain('offline_access');
  const member = new URL(authorizeUrl({ domain: 'identity.example', clientId: 'legal-test', audience: 'https://legal.example',
    organization: 'org_approved', connection: 'email' }, { challenge: 'member-challenge', state: 'member-state', mode: 'probe', redirectUri: `https://vera.example${LEGAL_CALLBACK_PATH}` }));
  expect(member.searchParams.get('organization')).toBe('org_approved');
  expect(member.searchParams.get('audience')).toBe('https://legal.example');
  expect(member.searchParams.get('scope')).toBe('openid legal:directory legal:case legal:enroll');
});
