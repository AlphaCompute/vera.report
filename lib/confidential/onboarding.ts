import { signOrganizationRegistration } from '../../enclave/src/confidential/organizationRegistration';
import { verifyFirmKeyBinding } from '../../enclave/src/confidential/firmKeyBinding';
import { signMembershipAuthorization } from '../../enclave/src/confidential/membershipAuthorization';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { verifiedSession, exchange, base64, ConfidentialUnavailableError, trustedTime, unavailable } from './client';
import type { ChannelRelay } from './client';

/** This independent operator key can authorize membership, never case grants. */
export async function issueLegalInvitation(input: {
  relay: ChannelRelay; releaseManifest: string; accessToken: string; authority: PrivateKey;
  organizationId: string; providerOrganizationId: string; recipientKeyId: string; subject: string;
  now: number; lifetimeMs?: number;
  /** `continuity` (signed by the registered key and the new one) is required to
   * replace a registered organization's key; the enclave refuses without it. */
  registration?: { domain: string; displayName: string; bindingDocument: string; continuity?: string };
}): Promise<{ token: string; expiresAt: number }> {
  let candidate: { domain: string; displayName: string; bindingDocument: string; publicKey: string; continuity?: string } | undefined;
  if (input.registration) {
    const domain = input.registration.domain;
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new ConfidentialUnavailableError();
    const bindingDocument = input.registration.bindingDocument;
    if (typeof bindingDocument !== 'string' || new TextEncoder().encode(bindingDocument).length > 65536) throw new ConfidentialUnavailableError();
    const verified = await verifyFirmKeyBinding(bindingDocument, { domain, organizationId: input.organizationId });
    if (verified.binding.recipientKeyId !== input.recipientKeyId) throw new ConfidentialUnavailableError();
    const { continuity } = input.registration;
    if (continuity !== undefined && (typeof continuity !== 'string' || continuity.length > 65536)) throw new ConfidentialUnavailableError();
    candidate = { domain, displayName: input.registration.displayName.trim(), bindingDocument,
      publicKey: verified.publicKey.armor(), ...(continuity !== undefined ? { continuity } : {}) };
  }
  // Verify this session before signing: a fresh page has no attested clock yet,
  // and an earlier session's offset may be stale. Invalid bindings are still
  // rejected locally before opening a channel.
  const session = await verifiedSession(input.relay, input.releaseManifest, input.now);
  const issuedAt = trustedTime(input.now);
  let registration: { domain: string; displayName: string; bindingDocument: string; authorization: string; continuity?: string } | undefined;
  if (candidate) {
    const { publicKey, ...details } = candidate;
    registration = { ...details, authorization: await signOrganizationRegistration({ format: 'vera-organization-registration/v1',
        organizationId: input.organizationId, providerOrganizationId: input.providerOrganizationId, recipientKeyId: input.recipientKeyId,
        publicKey, displayName: details.displayName, domain: details.domain, approved: true, issuedAt }, input.authority) };
  }
  const lifetimeMs = input.lifetimeMs ?? 7 * 86400000;
  const authorization = await signMembershipAuthorization({ format: 'vera-membership-authorization/v1',
    organizationId: input.organizationId, providerOrganizationId: input.providerOrganizationId, recipientKeyId: input.recipientKeyId,
    subject: input.subject, issuedAt, expiresAt: issuedAt + lifetimeMs }, input.authority);
  try {
    const result = await exchange(input.relay, session, { operation: 'legal.issue-invitation', accessToken: input.accessToken,
      body: base64(new TextEncoder().encode(JSON.stringify({ organizationId: input.organizationId,
        subject: input.subject, lifetimeMs, authorization, ...(registration ? { registration } : {}) }))) }) as { token?: unknown; expiresAt?: unknown };
    if (typeof result.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(result.token) || result.expiresAt !== issuedAt + lifetimeMs) {
      throw new ConfidentialUnavailableError();
    }
    return { token: result.token, expiresAt: result.expiresAt as number };
  } catch (error) { throw unavailable(error); }
}
