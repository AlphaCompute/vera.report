import { webcrypto } from 'node:crypto';
import { generateKey } from '../../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { canonicalFirmProfile, createFirmKeyBinding, verifyFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import type { FirmProfile } from '../../../enclave/src/confidential/firmKeyBinding';

const org = '1'.repeat(64);
let firm: PrivateKey, operator: PrivateKey;

beforeAll(async () => {
  if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  [firm, operator] = await Promise.all(['firm', 'operator'].map(async name =>
    (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: `Synthetic ${name}` }],
      format: 'object' })).privateKey));
});

describe('firm-domain key binding', () => {
  test('binds the firm key to its own domain and Vera organization', async () => {
    const document = await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now() }, firm);
    const verified = await verifyFirmKeyBinding(document, { domain: 'counsel.example', organizationId: org });
    expect(verified.binding.recipientKeyId).toBe(await caseRecipientKeyId(firm.toPublic()));
  });

  test('operator key substitution, another domain or another organization fails', async () => {
    const document = JSON.parse(await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now() }, firm));
    const substituted = { ...document, publicKey: operator.toPublic().armor() };
    await expect(verifyFirmKeyBinding(JSON.stringify(substituted), { domain: 'counsel.example', organizationId: org })).rejects.toThrow();
    const resigned = JSON.parse(await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now() }, operator));
    // Operator-signed binding verifies only as the operator's own key; pinning the firm's ID catches it.
    const operatorResult = await verifyFirmKeyBinding(JSON.stringify(resigned), { domain: 'counsel.example', organizationId: org });
    expect(operatorResult.binding.recipientKeyId).not.toBe(await caseRecipientKeyId(firm.toPublic()));
    await expect(verifyFirmKeyBinding(JSON.stringify(document), { domain: 'evil.example', organizationId: org })).rejects.toThrow();
    await expect(verifyFirmKeyBinding(JSON.stringify(document), { domain: 'counsel.example', organizationId: '2'.repeat(64) })).rejects.toThrow();
    await expect(verifyFirmKeyBinding(JSON.stringify({ ...document, binding: { ...document.binding, recipientKeyId: '3'.repeat(64) } }),
      { domain: 'counsel.example', organizationId: org })).rejects.toThrow();
  });

  test.each(['COUNSEL.example', 'counsel', '-bad.example', 'a..example', 'x'.repeat(254)])('rejects malformed domain %s', async domain => {
    await expect(createFirmKeyBinding({ domain, organizationId: org, issuedAt: Date.now() }, firm)).rejects.toThrow();
  });
});

describe('firm-signed profile in the key submission (v2)', () => {
  const profile: FirmProfile = { practiceAreas: ['whistleblower', 'securities'], jurisdiction: 'US federal courts; New York',
    website: 'https://www.counsel.example/team' };

  test('round-trips the signed profile; v1 documents stay valid without one', async () => {
    const document = await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now(), profile }, firm);
    expect(JSON.parse(document).binding.format).toBe('vera-firm-key-binding/v2');
    const verified = await verifyFirmKeyBinding(document, { domain: 'counsel.example', organizationId: org });
    expect(verified.profile).toEqual(profile);
    const v1 = await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now() }, firm);
    expect(JSON.parse(v1).binding.format).toBe('vera-firm-key-binding/v1');
    expect((await verifyFirmKeyBinding(v1, { domain: 'counsel.example', organizationId: org })).profile).toBeNull();
  });

  test('optional contact methods are signed, canonical and cannot be replaced or stripped', async () => {
    const contacts = { email: 'intake@counsel.example', phone: '+1 555 0100', imessage: 'intake@counsel.example', signal: 'counsel.12', telegram: '@counsel' };
    const document = JSON.parse(await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org,
      issuedAt: Date.now(), profile: { ...profile, contacts } }, firm));
    const expected = { domain: 'counsel.example', organizationId: org };
    expect((await verifyFirmKeyBinding(JSON.stringify(document), expected)).profile?.contacts).toEqual(contacts);
    for (const altered of [undefined, { ...contacts, email: 'attacker@example.org' }]) {
      await expect(verifyFirmKeyBinding(JSON.stringify({ ...document, binding: { ...document.binding,
        profile: { ...profile, ...(altered ? { contacts: altered } : {}) } } }), expected)).rejects.toThrow();
    }
    for (const invalid of [{ email: 'not-an-email' }, { signal: '<script>' }, { phone: 'x'.repeat(201) }, { unsupported: 'x' }, {}]) {
      await expect(createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now(),
        profile: { ...profile, contacts: invalid } as FirmProfile }, firm)).rejects.toThrow();
    }
  });

  test('a host cannot alter, add or strip the signed profile', async () => {
    const document = JSON.parse(await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now(), profile }, firm));
    const expected = { domain: 'counsel.example', organizationId: org };
    for (const changed of [
      { ...document.binding, profile: { ...profile, jurisdiction: 'Anywhere' } },
      { ...document.binding, profile: { ...profile, practiceAreas: ['criminal'] } },
      { ...document.binding, format: 'vera-firm-key-binding/v1' },
      (({ profile: _removed, ...rest }) => rest)(document.binding),
    ]) await expect(verifyFirmKeyBinding(JSON.stringify({ ...document, binding: changed }), expected)).rejects.toThrow();
    const v1 = JSON.parse(await createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now() }, firm));
    await expect(verifyFirmKeyBinding(JSON.stringify({ ...v1, binding: { ...v1.binding, profile } }), expected)).rejects.toThrow();
  });

  test.each([
    ['unknown practice area', { ...profile, practiceAreas: ['astrology'] }],
    ['no practice area', { ...profile, practiceAreas: [] }],
    ['duplicate practice area', { ...profile, practiceAreas: ['tax', 'tax'] }],
    ['too many practice areas', { ...profile, practiceAreas: ['tax', 'privacy', 'criminal', 'consumer', 'securities', 'employment', 'healthcare'] }],
    ['website on another domain', { ...profile, website: 'https://counsel-example.attacker.example/' }],
    ['website look-alike suffix', { ...profile, website: 'https://evilcounsel.example/' }],
    ['plain http website', { ...profile, website: 'http://counsel.example/' }],
    ['website with credentials', { ...profile, website: 'https://user:pass@counsel.example/' }],
    ['non-canonical website', { ...profile, website: 'https://counsel.example' }],
    ['markup in jurisdiction', { ...profile, jurisdiction: '<b>Everywhere</b>' }],
    ['untrimmed jurisdiction', { ...profile, jurisdiction: ' New York ' }],
    ['overlong jurisdiction', { ...profile, jurisdiction: 'x'.repeat(121) }],
    ['extra field', { ...profile, phone: '+1 555 0100' }],
  ])('rejects a profile with %s', async (_name, bad) => {
    await expect(createFirmKeyBinding({ domain: 'counsel.example', organizationId: org, issuedAt: Date.now(),
      profile: bad as FirmProfile }, firm)).rejects.toThrow();
  });

  test('form input is normalized into a canonical profile or a clear message', () => {
    expect(canonicalFirmProfile({ practiceAreas: ['tax', 'tax', 'privacy'], jurisdiction: '  England   and Wales ', website: 'counsel.example' },
      'counsel.example')).toEqual({ error: null, profile: { practiceAreas: ['tax', 'privacy'], jurisdiction: 'England and Wales',
      website: 'https://counsel.example/' } });
    expect(canonicalFirmProfile({ practiceAreas: [], jurisdiction: 'Ontario', website: 'https://counsel.example/' }, 'counsel.example').error)
      .toBe('Choose at least one practice area.');
    expect(canonicalFirmProfile({ practiceAreas: ['tax'], jurisdiction: 'Ontario', website: 'https://other.example/' }, 'counsel.example').error)
      .toContain('must be on counsel.example');
    expect(canonicalFirmProfile({ practiceAreas: ['tax'], jurisdiction: 'x', website: 'https://counsel.example/' }, 'counsel.example').error)
      .toContain('Enter where your lawyers practice');
    expect(canonicalFirmProfile({ practiceAreas: ['tax'], jurisdiction: 'Ontario', website: 'https://counsel.example:8443/' }, 'counsel.example').error)
      .toContain('without a port');
  });
});
