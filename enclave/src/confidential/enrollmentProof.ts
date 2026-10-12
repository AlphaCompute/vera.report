import { createMessage, readSignature, sign, verify } from './pgp.ts';
import type { PrivateKey, PublicKey } from './pgp.ts';
import { caseRecipientKeyId } from './caseObject.ts';

export type EnrollmentChallenge = {
  format: 'vera-legal-enrollment/v1'; invitationId: string; organizationId: string;
  providerOrganizationId: string; subject: string; recipientKeyId: string; nonce: string; expiresAt: number;
};
function invalid(): never { throw new Error('Invalid legal enrollment proof'); }
function canonical(input: EnrollmentChallenge): EnrollmentChallenge {
  const fields = ['format', 'invitationId', 'organizationId', 'providerOrganizationId', 'subject', 'recipientKeyId', 'nonce', 'expiresAt'];
  if (!input || Object.keys(input).length !== fields.length || Object.keys(input).some(key => !fields.includes(key)) ||
      input.format !== 'vera-legal-enrollment/v1' ||
      [input.invitationId, input.organizationId, input.recipientKeyId, input.nonce].some(value => typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) ||
      typeof input.providerOrganizationId !== 'string' || !/^org_[a-zA-Z0-9]{1,64}$/.test(input.providerOrganizationId) ||
      typeof input.subject !== 'string' || !/^[a-zA-Z0-9_-]+\|[^\s\u0000-\u001f]{1,200}$/.test(input.subject) ||
      !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= 0) invalid();
  return { format: input.format, invitationId: input.invitationId, organizationId: input.organizationId,
    providerOrganizationId: input.providerOrganizationId, subject: input.subject,
    recipientKeyId: input.recipientKeyId, nonce: input.nonce, expiresAt: input.expiresAt };
}
export async function signEnrollmentChallenge(input: EnrollmentChallenge, firmKey: PrivateKey): Promise<string> {
  const challenge = canonical(input);
  if (await caseRecipientKeyId(firmKey.toPublic()) !== challenge.recipientKeyId) invalid();
  return sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(challenge)) }),
    signingKeys: firmKey, detached: true, format: 'armored' });
}
export async function verifyEnrollmentProof(input: EnrollmentChallenge, signature: string, pinnedFirmKey: PublicKey): Promise<void> {
  try {
    const challenge = canonical(input);
    if (typeof signature !== 'string' || signature.length > 16_384 ||
        await caseRecipientKeyId(pinnedFirmKey) !== challenge.recipientKeyId) invalid();
    const result = await verify({
      message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(challenge)) }),
      signature: await readSignature({ armoredSignature: signature }), verificationKeys: pinnedFirmKey,
      expectSigned: true, format: 'binary',
    });
    const verified = await Promise.allSettled(result.signatures.map(item => item.verified));
    if (verified.length !== 1 || verified[0].status !== 'fulfilled') invalid();
  } catch { return invalid(); }
}
