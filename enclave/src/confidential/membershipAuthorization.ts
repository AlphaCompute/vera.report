import { createMessage, readSignature, sign, verify } from './pgp.ts';
import { issuedNotAfter } from './clockSkew.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';

/** Independent onboarding authority: this key must never be the shared firm key. */
export type MembershipAuthorization = {
  format: 'vera-membership-authorization/v1'; organizationId: string; providerOrganizationId: string;
  subject: string; recipientKeyId: string; issuedAt: number; expiresAt: number;
};
function canonical(value: MembershipAuthorization): MembershipAuthorization {
  if (!value || Object.keys(value).sort().join(',') !== 'expiresAt,format,issuedAt,organizationId,providerOrganizationId,recipientKeyId,subject' ||
      value.format !== 'vera-membership-authorization/v1' ||
      ![value.organizationId, value.recipientKeyId].every(id => typeof id === 'string' && /^[a-f0-9]{64}$/.test(id)) ||
      !/^org_[a-zA-Z0-9]{1,64}$/.test(value.providerOrganizationId) ||
      !/^[a-zA-Z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/.test(value.subject) ||
      !Number.isSafeInteger(value.issuedAt) || value.issuedAt <= 0 || !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 7 * 86400000) throw new Error('Invalid membership authorization');
  return { format: value.format, organizationId: value.organizationId, providerOrganizationId: value.providerOrganizationId,
    subject: value.subject, recipientKeyId: value.recipientKeyId, issuedAt: value.issuedAt, expiresAt: value.expiresAt };
}
export async function signMembershipAuthorization(input: MembershipAuthorization, authority: PrivateKey): Promise<string> {
  const statement = canonical(input);
  const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
    signingKeys: authority, detached: true, format: 'armored' });
  return JSON.stringify({ statement, signature });
}
export async function verifyMembershipAuthorization(document: string, authority: PublicKey, now: number): Promise<MembershipAuthorization> {
  try {
    if (typeof document !== 'string' || document.length > 20000 || authority.isPrivate()) throw new Error();
    const value = JSON.parse(document);
    if (!value || Object.keys(value).sort().join(',') !== 'signature,statement' || typeof value.signature !== 'string') throw new Error();
    const statement = canonical(value.statement);
    if (!Number.isSafeInteger(now) || !issuedNotAfter(statement.issuedAt, now) || statement.expiresAt <= now) throw new Error();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(statement)) }),
      signature: await readSignature({ armoredSignature: value.signature }), verificationKeys: authority, expectSigned: true, format: 'binary' });
    const checks = await Promise.allSettled(result.signatures.map(signature => signature.verified));
    if (checks.length !== 1 || checks[0].status !== 'fulfilled') throw new Error();
    return statement;
  } catch { throw new Error('Invalid membership authorization'); }
}
