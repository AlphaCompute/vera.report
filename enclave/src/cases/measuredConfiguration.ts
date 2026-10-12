import { createHash } from 'node:crypto';
import { readKey } from '../confidential/pgp.js';
import { readReleaseManifest } from '../confidential/releaseManifest.js';
import type { LegalIdentityPolicy } from '../legal/identity.js';

const hash = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
/** The fixed-path bytes must come from the measured image, never a host mount or
 * environment-selected path. The manifest and RPC policy are untrusted inputs. */
export async function verifyMeasuredConfiguration(manifestWire: string, bytes: Uint8Array): Promise<string | null> {
  try {
    if (!bytes.length || bytes.length > 65536) throw new Error();
    const { manifest } = await readReleaseManifest(manifestWire);
    if (hash(bytes) !== manifest.configurationSha256) throw new Error();
    const config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (config.format !== 'vera-confidential-configuration/v1' ||
        config.protocolVersion !== manifest.protocolVersion || config.dataFormatVersion !== manifest.dataFormatVersion ||
        config.channelAudience !== 'vera-confidential-cases') throw new Error();
    const pin = config.legalIdentityPolicySha256;
    if (pin !== null && (typeof pin !== 'string' || !/^[a-f0-9]{64}$/.test(pin) || /^0+$/.test(pin))) throw new Error();
    return pin;
  } catch { throw new Error('Confidential measured configuration mismatch'); }
}

/** Digest canonical field order; JWKS bytes retain their published array/key
 * order. Any key rotation requires a newly measured and owner-approved release. */
export function legalIdentityPolicyDigest(policy: LegalIdentityPolicy): string {
  if (!policy || Object.keys(policy).sort().join(',') !== 'audience,clientId,issuer,jwks') {
    throw new Error('Invalid legal identity policy');
  }
  return hash(JSON.stringify({ issuer: policy.issuer, audience: policy.audience, clientId: policy.clientId, jwks: policy.jwks }));
}
export function verifyMeasuredLegalPolicy(pin: string | null, policy: LegalIdentityPolicy | null): LegalIdentityPolicy | null {
  if (pin === null) return null; // Disabled in measured configuration, regardless of host input.
  if (!policy || legalIdentityPolicyDigest(policy) !== pin) throw new Error('Legal identity policy does not match measured configuration');
  return JSON.parse(JSON.stringify(policy)) as LegalIdentityPolicy;
}

/** Public administration policy is embedded in the image rather than supplied
 * by an environment variable. This function independently verifies its bytes. */
export async function measuredLegalAdministration(manifestWire: string, bytes: Uint8Array): Promise<{
  identity: LegalIdentityPolicy; organizationId: string; onboardingPublicKey: string; initialApprovalPublicKey?: string;
} | undefined> {
  await verifyMeasuredConfiguration(manifestWire, bytes);
  const config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const value = config.legalAdministration;
  if (value === undefined || value === null) return undefined;
  if (!value || !['identity,onboardingPublicKey,organizationId', 'identity,initialApprovalPublicKey,onboardingPublicKey,organizationId'].includes(Object.keys(value).sort().join(',')) ||
      !/^org_[a-zA-Z0-9]{1,64}$/.test(value.organizationId) || typeof value.onboardingPublicKey !== 'string' ||
      value.onboardingPublicKey.length > 16384 || (!value.onboardingPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || value.onboardingPublicKey.includes('PRIVATE KEY'))) throw new Error('Invalid measured administration policy');
  legalIdentityPolicyDigest(value.identity);
  if (value.initialApprovalPublicKey !== undefined) {
    if (typeof value.initialApprovalPublicKey !== 'string' || value.initialApprovalPublicKey.length > 16384) throw new Error('Invalid initial approval policy');
    const [root, worker] = await Promise.all([value.onboardingPublicKey, value.initialApprovalPublicKey].map(armoredKey => readKey({ armoredKey })));
    if (root.isPrivate() || worker.isPrivate() || root.getFingerprint() === worker.getFingerprint()) throw new Error('Invalid initial approval policy');
  }
  return value;
}

/** Public key that signs release withdrawal lists (releaseWithdrawals.ts), or
 * null when withdrawal checks are not configured for this release. Pinned in the
 * measured image so the host cannot substitute a key or disable the check. */
export async function measuredReleaseWithdrawalKey(manifestWire: string, bytes: Uint8Array): Promise<string | null> {
  await verifyMeasuredConfiguration(manifestWire, bytes);
  const config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const value = config.releaseWithdrawal;
  if (value === undefined || value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join(',') !== 'publicKey' ||
      typeof value.publicKey !== 'string' || value.publicKey.length > 16384 ||
      !value.publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----') || value.publicKey.includes('PRIVATE KEY')) {
    throw new Error('Invalid measured release withdrawal policy');
  }
  return value.publicKey;
}

/** Pinned Roughtime servers for the optional external time bound
 * (trustedClock.ts, roughtime.ts), or null when not configured (time then
 * rests on NSM timestamps alone, exactly as before). Measured, so the host
 * cannot add, remove or substitute a server key, or disable the check. */
export type MeasuredRoughtimePolicy = {
  servers: { name: string; address: string; publicKey: Uint8Array }[]; quorum: number; toleranceMs: number;
};
export function parseRoughtimePolicy(value: unknown): MeasuredRoughtimePolicy | null {
  if (value === undefined || value === null) return null;
  const invalid = (): never => { throw new Error('Invalid measured Roughtime policy'); };
  if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'quorum,servers,toleranceMs') invalid();
  const { servers, quorum, toleranceMs } = value as Record<string, unknown>;
  if (!Array.isArray(servers) || servers.length < 1 || servers.length > 8) invalid();
  const parsed = (servers as unknown[]).map(server => {
    if (!server || typeof server !== 'object' || Array.isArray(server) ||
        Object.keys(server).sort().join(',') !== 'address,name,publicKey') invalid();
    const { name, address, publicKey } = server as Record<string, unknown>;
    if (typeof name !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(name) || typeof address !== 'string' ||
        !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?:\d{1,5}$/.test(address) ||
        Number(address.slice(address.lastIndexOf(':') + 1)) < 1 || Number(address.slice(address.lastIndexOf(':') + 1)) > 65535 ||
        typeof publicKey !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(publicKey)) invalid();
    const key = new Uint8Array(Buffer.from(publicKey as string, 'base64'));
    if (key.length !== 32 || Buffer.from(key).toString('base64') !== publicKey) invalid();
    return { name: name as string, address: address as string, publicKey: key };
  });
  if (new Set(parsed.map(server => server.name)).size !== parsed.length ||
      new Set(parsed.map(server => Buffer.from(server.publicKey).toString('hex'))).size !== parsed.length) invalid();
  if (!Number.isSafeInteger(quorum) || (quorum as number) < 1 || (quorum as number) > parsed.length ||
      !Number.isSafeInteger(toleranceMs) || (toleranceMs as number) < 1_000 || (toleranceMs as number) > 600_000) invalid();
  return { servers: parsed, quorum: quorum as number, toleranceMs: toleranceMs as number };
}
export async function measuredRoughtimePolicy(manifestWire: string, bytes: Uint8Array): Promise<MeasuredRoughtimePolicy | null> {
  await verifyMeasuredConfiguration(manifestWire, bytes);
  return parseRoughtimePolicy(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)).roughtime);
}
