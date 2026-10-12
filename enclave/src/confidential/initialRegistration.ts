import { createMessage, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { verifyOrganizationRegistration } from './organizationRegistration.ts';
import { verifyMembershipAuthorization } from './membershipAuthorization.ts';
import { applicationOrganizationId } from './applicationOrganization.ts';

const FORMAT = 'vera-initial-registration/v1';
type Statement = { format: typeof FORMAT; registration: string; authorization: string };
function statement(value: Statement): Statement {
  if (!value || Object.keys(value).sort().join(',') !== 'authorization,format,registration' || value.format !== FORMAT ||
      typeof value.registration !== 'string' || value.registration.length > 40000 ||
      typeof value.authorization !== 'string' || value.authorization.length > 20000) throw new Error('Invalid initial registration');
  return { format: FORMAT, registration: value.registration, authorization: value.authorization };
}
function initial(wire: string): boolean {
  if (typeof wire !== 'string' || wire.length > 100000) throw new Error('Invalid initial registration');
  try { return JSON.parse(wire)?.statement?.format === FORMAT; } catch { return false; }
}

/** The worker attests only a key-derived first organization and its exact first
 * member lease. This certificate is never an administrator invitation/replacement
 * authorization. The long-lived registration retains the original, bounded lease. */
export async function signInitialRegistration(registration: string, authorization: string, authority: PrivateKey): Promise<string> {
  const value = statement({ format: FORMAT, registration, authorization });
  return JSON.stringify({ statement: value, signature: await sign({
    message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
    signingKeys: authority, detached: true, format: 'armored' }) });
}
export async function verifyInitialRegistration(wire: string, authority: PublicKey, now: number) {
  if (typeof wire !== 'string' || wire.length > 100000 || authority.isPrivate() || !Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid initial registration');
  const envelope = JSON.parse(wire);
  if (!envelope || Object.keys(envelope).sort().join(',') !== 'signature,statement' ||
      typeof envelope.signature !== 'string' || envelope.signature.length > 16384) throw new Error('Invalid initial registration');
  const value = statement(envelope.statement);
  const verified = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
    signature: await readSignature({ armoredSignature: envelope.signature }), verificationKeys: authority, expectSigned: true, format: 'binary' });
  if (verified.signatures.length !== 1) throw new Error('Invalid initial registration');
  await verified.signatures[0].verified;
  const registration = await verifyOrganizationRegistration(value.registration, authority, now);
  // Registration survives lease expiry. Verify the original lease as of issuance;
  // callers admitting a member must separately check its current expiry below.
  const authorization = await verifyMembershipAuthorization(value.authorization, authority, registration.issuedAt);
  if (!registration.approved || registration.organizationId !== await applicationOrganizationId(registration.recipientKeyId) ||
      authorization.organizationId !== registration.organizationId || authorization.recipientKeyId !== registration.recipientKeyId ||
      authorization.providerOrganizationId !== registration.providerOrganizationId || authorization.issuedAt !== registration.issuedAt) {
    throw new Error('Invalid initial registration');
  }
  return { registration, authorization, authorizationWire: value.authorization };
}
function initialKey(authority: PublicKey, worker?: PublicKey): PublicKey {
  if (!worker || worker.isPrivate() || worker.getFingerprint() === authority.getFingerprint()) throw new Error('Invalid initial authority');
  return worker;
}
/** Ordinary onboarding signatures remain accepted. Worker signatures are accepted
 * only inside the scoped certificate, never as a general registration signature. */
export async function verifyApprovedOrganization(wire: string, authority: PublicKey, now: number, worker?: PublicKey) {
  return initial(wire) ? (await verifyInitialRegistration(wire, initialKey(authority, worker), now)).registration
    : verifyOrganizationRegistration(wire, authority, now);
}
export async function verifyApprovedMembership(wire: string, registration: string, authority: PublicKey, now: number, worker?: PublicKey) {
  if (initial(registration)) {
    const key = initialKey(authority, worker), first = await verifyInitialRegistration(registration, key, now);
    // A later administrator-issued lease is still allowed, but the worker cannot
    // mint a new subject/deadline outside the certificate's original first lease.
    if (wire === first.authorizationWire) return verifyMembershipAuthorization(wire, key, now);
  }
  return verifyMembershipAuthorization(wire, authority, now);
}
