import { createMessage, readKey, readSignature, sign, verify } from './pgp.ts';
import { issuedNotAfter } from './clockSkew.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';

export type OrganizationRegistration = { format: 'vera-organization-registration/v1'; organizationId: string;
  providerOrganizationId: string; recipientKeyId: string; publicKey: string; displayName: string; domain: string;
  approved: boolean; issuedAt: number };
function canonical(v: OrganizationRegistration): OrganizationRegistration {
  if (!v || Object.keys(v).sort().join(',') !== 'approved,displayName,domain,format,issuedAt,organizationId,providerOrganizationId,publicKey,recipientKeyId' ||
      v.format !== 'vera-organization-registration/v1' || ![v.organizationId, v.recipientKeyId].every(x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x)) ||
      !/^org_[a-zA-Z0-9]{1,64}$/.test(v.providerOrganizationId) || typeof v.publicKey !== 'string' || v.publicKey.length > 16384 ||
      typeof v.displayName !== 'string' || !v.displayName.trim() || v.displayName.length > 160 ||
      typeof v.domain !== 'string' || v.domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v.domain) ||
      typeof v.approved !== 'boolean' || !Number.isSafeInteger(v.issuedAt) || v.issuedAt <= 0) throw new Error('Invalid firm registration');
  return { format: v.format, organizationId: v.organizationId, providerOrganizationId: v.providerOrganizationId,
    recipientKeyId: v.recipientKeyId, publicKey: v.publicKey, displayName: v.displayName, domain: v.domain, approved: v.approved, issuedAt: v.issuedAt };
}
export async function signOrganizationRegistration(value: OrganizationRegistration, authority: PrivateKey): Promise<string> {
  const statement = canonical(value);
  return JSON.stringify({ statement, signature: await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
    signingKeys: authority, detached: true, format: 'armored' }) });
}
export async function verifyOrganizationRegistration(wire: string, authority: PublicKey, now: number): Promise<OrganizationRegistration> {
  try {
    if (typeof wire !== 'string' || wire.length > 40000 || authority.isPrivate()) throw new Error();
    const v = JSON.parse(wire);
    if (!v || Object.keys(v).sort().join(',') !== 'signature,statement' || typeof v.signature !== 'string') throw new Error();
    const statement = canonical(v.statement);
    if (!Number.isSafeInteger(now) || !issuedNotAfter(statement.issuedAt, now)) throw new Error();
    const key = await readKey({ armoredKey: statement.publicKey });
    if (key.isPrivate() || await caseRecipientKeyId(key) !== statement.recipientKeyId || key.getFingerprint() === authority.getFingerprint()) throw new Error();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
      signature: await readSignature({ armoredSignature: v.signature }), verificationKeys: authority, expectSigned: true, format: 'binary' });
    const checks = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (checks.length !== 1 || checks[0].status !== 'fulfilled') throw new Error();
    return statement;
  } catch { throw new Error('Invalid firm registration'); }
}
