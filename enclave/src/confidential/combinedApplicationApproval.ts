import { createMessage, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { signOrganizationRegistration } from './organizationRegistration.ts';
import { signInitialRegistration, verifyInitialRegistration } from './initialRegistration.ts';
import { verifyMembershipAuthorization, signMembershipAuthorization } from './membershipAuthorization.ts';
import { verifyFirmKeyBinding } from './firmKeyBinding.ts';
import { issuedNotAfter } from './clockSkew.ts';

export const COMBINED_APPROVAL_MAX_AGE_MS = 7 * 86400000;

/** The review, not a delayed worker run, starts the first-member window. */
export function combinedApprovalExpiresAt(decidedAt: number): number {
  const expiresAt = decidedAt + COMBINED_APPROVAL_MAX_AGE_MS;
  if (!Number.isSafeInteger(decidedAt) || decidedAt <= 0 || !Number.isSafeInteger(expiresAt)) {
    throw new Error('Invalid combined approval');
  }
  return expiresAt;
}

type Statement = { format: 'vera-combined-application-approval/v1'; applicationDigest: string; actor: string; decidedAt: number;
  registration: string; authorization: string; bindingDocument: string };
function statement(value: unknown): Statement {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid combined approval');
  const v = value as Statement;
  if (Object.keys(v).sort().join(',') !== 'actor,applicationDigest,authorization,bindingDocument,decidedAt,format,registration' ||
      v.format !== 'vera-combined-application-approval/v1' || !/^[a-f0-9]{64}$/.test(v.applicationDigest) ||
      !/^slack:T[A-Z0-9]+:U[A-Z0-9]+$/.test(v.actor) || !Number.isSafeInteger(v.decidedAt) || v.decidedAt <= 0 ||
      typeof v.registration !== 'string' || v.registration.length > 100000 ||
      typeof v.authorization !== 'string' || v.authorization.length > 20000 ||
      typeof v.bindingDocument !== 'string' || v.bindingDocument.length > 65536) throw new Error('Invalid combined approval');
  return { format: v.format, applicationDigest: v.applicationDigest, actor: v.actor, decidedAt: v.decidedAt,
    registration: v.registration, authorization: v.authorization, bindingDocument: v.bindingDocument };
}
export async function verifyCombinedApplicationApproval(wire: string, authority: PublicKey, now: number) {
  try {
    if (typeof wire !== 'string' || wire.length > 150000 || authority.isPrivate()) throw new Error();
    const envelope = JSON.parse(wire);
    if (!envelope || Object.keys(envelope).sort().join(',') !== 'signature,statement' || typeof envelope.signature !== 'string' || envelope.signature.length > 16384) throw new Error();
    const value = statement(envelope.statement);
    const expiresAt = combinedApprovalExpiresAt(value.decidedAt);
    if (now <= 0 || !issuedNotAfter(value.decidedAt, now) || now >= expiresAt) throw new Error();
    const result = await verify({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
      signature: await readSignature({ armoredSignature: envelope.signature }), verificationKeys: authority, expectSigned: true, format: 'binary' });
    if (result.signatures.length !== 1) throw new Error();
    await result.signatures[0].verified;
    const first = await verifyInitialRegistration(value.registration, authority, now);
    const registration = first.registration;
    if (value.authorization !== first.authorizationWire) throw new Error();
    const authorization = await verifyMembershipAuthorization(value.authorization, authority, now);
    const key = await verifyFirmKeyBinding(value.bindingDocument, registration);
    if (!registration.approved || registration.organizationId !== authorization.organizationId ||
        registration.providerOrganizationId !== authorization.providerOrganizationId || registration.recipientKeyId !== authorization.recipientKeyId ||
        registration.recipientKeyId !== key.binding.recipientKeyId || registration.publicKey !== key.publicKey.armor() ||
        registration.issuedAt < value.decidedAt || registration.issuedAt >= expiresAt ||
        authorization.issuedAt < value.decidedAt || authorization.expiresAt > expiresAt) throw new Error();
    return { statement: value, registration, authorization, key };
  } catch { throw new Error('Invalid combined approval'); }
}

/** Dedicated approval worker only. Never load this authority in the web app,
 * intake/provisioning backend, or ordinary Slack notification process. */
export async function signCombinedApplicationApproval(input: {
  organizationId: string; providerOrganizationId: string; domain: string; displayName: string; subject: string;
  bindingDocument: string; recipientKeyId: string; applicationDigest: string; actor: string; decidedAt: number; now: number;
}, authority: PrivateKey): Promise<string> {
  const expiresAt = combinedApprovalExpiresAt(input.decidedAt);
  if (!Number.isSafeInteger(input.now) || input.now < input.decidedAt || input.now >= expiresAt) throw new Error('Invalid combined approval');
  const key = await verifyFirmKeyBinding(input.bindingDocument, input);
  if (key.binding.recipientKeyId !== input.recipientKeyId) throw new Error('Invalid combined approval');
  const registrationStatement = await signOrganizationRegistration({ format: 'vera-organization-registration/v1', organizationId: input.organizationId,
    providerOrganizationId: input.providerOrganizationId, recipientKeyId: input.recipientKeyId, publicKey: key.publicKey.armor(),
    displayName: input.displayName, domain: input.domain, approved: true, issuedAt: input.now }, authority);
  const authorization = await signMembershipAuthorization({ format: 'vera-membership-authorization/v1', organizationId: input.organizationId,
    providerOrganizationId: input.providerOrganizationId, recipientKeyId: input.recipientKeyId, subject: input.subject,
    issuedAt: input.now, expiresAt }, authority);
  const registration = await signInitialRegistration(registrationStatement, authorization, authority);
  const value = statement({ format: 'vera-combined-application-approval/v1', applicationDigest: input.applicationDigest,
    actor: input.actor, decidedAt: input.decidedAt, registration, authorization, bindingDocument: input.bindingDocument });
  const wire = JSON.stringify({ statement: value, signature: await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(value)) }),
    signingKeys: authority, detached: true, format: 'armored' }) });
  await verifyCombinedApplicationApproval(wire, authority.toPublic(), input.now);
  return wire;
}
