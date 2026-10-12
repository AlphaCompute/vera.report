import { generateKeyPairSync, webcrypto } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readKey } from '../../../enclave/src/confidential/pgp';
import { signMembershipAuthorization, verifyMembershipAuthorization } from '../../../enclave/src/confidential/membershipAuthorization';
import { importFirmIdentity } from '../../../lib/confidential/firmKey';

// The onboarding authority key must be creatable by an operator: the script's
// output has to open in /legal/administration (importFirmIdentity) and its public
// half has to pin through `pin --onboarding-key`.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { main } = require('../../../scripts/security/confidential-legal-identity.cjs');

const ROOT = path.resolve(__dirname, '../../..');
let dir: string;
beforeAll(() => { if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto }); });
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vera-onboarding-key-')); });
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

async function keygen() {
  const keyFile = path.join(dir, 'onboarding-authority.txt'), publicFile = path.join(dir, 'onboarding-public.asc');
  const result = await main(['onboarding-keygen', '--out-key', keyFile, '--out-public', publicFile]);
  return { keyFile, publicFile, result };
}

describe('confidential-legal-identity onboarding-keygen', () => {
  test('writes a key file the administration page opens, and a public key that matches it', async () => {
    const { keyFile, publicFile, result } = await keygen();
    expect(result.recoveryCode).toMatch(/^VERA-FIRM-1\.[A-Za-z0-9_-]{43}$/);
    const file = fs.readFileSync(keyFile, 'utf8');
    expect(file).not.toContain(result.recoveryCode);
    expect(file).toContain('PRIVATE. DO NOT SHARE');
    expect(fs.statSync(keyFile).mode & 0o077).toBe(0);

    const authority = await importFirmIdentity(file, result.recoveryCode);
    expect(authority.recipientKeyId).toBe(result.keyId);
    const armoredPublic = fs.readFileSync(publicFile, 'utf8');
    expect(armoredPublic.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')).toBe(true);
    expect(armoredPublic).not.toContain('PRIVATE KEY');
    const publicKey = await readKey({ armoredKey: armoredPublic });
    expect(publicKey.getFingerprint()).toBe(authority.privateKey.getFingerprint());

    // An invitation signed by the imported authority verifies against the pinned public key.
    const now = Date.now();
    const invitation = { format: 'vera-membership-authorization/v1' as const, organizationId: '1'.repeat(64),
      providerOrganizationId: 'org_firm', subject: 'auth0|lawyer', recipientKeyId: '2'.repeat(64), issuedAt: now, expiresAt: now + 60_000 };
    await expect(verifyMembershipAuthorization(await signMembershipAuthorization(invitation, authority.privateKey), publicKey, now))
      .resolves.toEqual(invitation);

    await expect(importFirmIdentity(file, 'VERA-FIRM-1.' + 'A'.repeat(43))).rejects.toThrow();
  }, 60_000);

  test('the public key pins through `pin --onboarding-key` into the measured configuration', async () => {
    const { publicFile } = await keygen();
    const write = (name: string, value: unknown) => {
      const file = path.join(dir, name);
      fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
      return file;
    };
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] };
    const config = write('confidential-config.json', fs.readFileSync(path.join(ROOT, 'enclave/confidential-config.json'), 'utf8'));
    main(['pin', '--auth0-output', write('legal.json', { issuer: 'https://legal.example/', audience: 'https://api.example/legal', clientId: 'legal-client' }),
      '--jwks', write('a.json', jwks), '--jwks-witness', write('b.json', jwks),
      '--admin-output', write('admin.json', { issuer: 'https://legal.example/', audience: 'https://api.example/admin', clientId: 'admin-client', organizationId: 'org_internal1' }),
      '--onboarding-key', publicFile, '--config', config, '--out', path.join(dir, 'policy.json')]);
    const pinned = JSON.parse(fs.readFileSync(config, 'utf8')).legalAdministration;
    expect(pinned.onboardingPublicKey).toBe(fs.readFileSync(publicFile, 'utf8').trim());
  }, 60_000);

  test('never overwrites an existing key or public file', async () => {
    const { keyFile, publicFile } = await keygen();
    const before = fs.readFileSync(keyFile, 'utf8');
    await expect(main(['onboarding-keygen', '--out-key', keyFile, '--out-public', path.join(dir, 'other.asc')])).rejects.toThrow(/already exists/);
    await expect(main(['onboarding-keygen', '--out-key', path.join(dir, 'other.txt'), '--out-public', publicFile])).rejects.toThrow(/already exists/);
    expect(fs.readFileSync(keyFile, 'utf8')).toBe(before);
    expect(fs.existsSync(path.join(dir, 'other.txt'))).toBe(false);
  }, 60_000);
});
