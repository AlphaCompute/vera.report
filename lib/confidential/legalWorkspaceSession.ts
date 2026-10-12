import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import { CONFIDENTIAL_RELEASE_MANIFEST } from './config';
import { fetchRelay } from './client';
import { createFirmSession } from './firmCase';
import type { FirmSession } from './firmCase';
import type { FirmIdentity } from './firmKey';
import { readMembershipStatus } from './firmOnboarding';
import { OrganizationKeyPendingError, publishedOrganizationKey } from './firmMemberDevices';
import { legalAccessToken, legalIdentityVersion, LegalSignInRequired, subscribeLegalIdentityChange } from './legalAuth';
import type { LegalAuthConfig } from './legalAuth';
import { setFirmSession } from './firmPortal';

subscribeLegalIdentityChange(() => setFirmSession(null));

export class WorkspaceKeyMismatchError extends Error {
  constructor() {
    super('This key does not match your signed-in organization or its approved key. Choose the correct key or sign in to the correct organization.');
    this.name = 'WorkspaceKeyMismatchError';
  }
}

export class WorkspaceMembershipRequiredError extends Error {
  constructor(state: 'not-enrolled' | 'lapsed') {
    super(state === 'lapsed'
      ? 'Your organization membership has ended. Finish your approved setup before opening this workspace.'
      : 'Finish your approved organization setup before opening this workspace.');
    this.name = 'WorkspaceMembershipRequiredError';
  }
}

async function actualKey(session: FirmSession): Promise<void> {
  // Compare the actual public key, never just labels imported from a file.
  if (await caseRecipientKeyId(session.firm.privateKey.toPublic()) !== session.firm.recipientKeyId) throw new WorkspaceKeyMismatchError();
}

/** Fail closed before exposing a key, restored records, or an existing session. */
export async function validateFirmSession(config: LegalAuthConfig, session: FirmSession, signal?: AbortSignal): Promise<void> {
  const accessToken = await session.accessToken();
  await actualKey(session);
  const membership = await readMembershipStatus({ relay: session.relay, releaseManifest: session.releaseManifest,
    accessToken, firm: session.firm, now: Date.now() });
  if (membership.state === 'enrolled' && !membership.keyMatches) throw new WorkspaceKeyMismatchError();
  if (membership.state !== 'enrolled') throw new WorkspaceMembershipRequiredError(membership.state);
  // A login change or sign-out during verification must not publish its result.
  if (await legalAccessToken(config) !== accessToken) throw new LegalSignInRequired();
  signal?.throwIfAborted();
}

async function start(config: LegalAuthConfig, firm: FirmIdentity, signal: AbortSignal | undefined, setup: boolean): Promise<FirmSession> {
  const identity = legalIdentityVersion();
  const accessToken = await legalAccessToken(config);
  const session = await createFirmSession({ relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, firm,
    accessToken: async () => {
      if (identity !== legalIdentityVersion()) throw new LegalSignInRequired();
      return legalAccessToken(config);
    } });
  if (setup) {
    await actualKey(session);
    try {
      const approved = await publishedOrganizationKey(firm, { relay: session.relay, releaseManifest: session.releaseManifest, accessToken, now: Date.now() });
      if (await caseRecipientKeyId(approved) !== firm.recipientKeyId) throw new WorkspaceKeyMismatchError();
    } catch (error) {
      // Only the explicit setup screen accepts an attested first-key-pending
      // answer for THIS authenticated organization. It is not report authority.
      if (!(error instanceof OrganizationKeyPendingError)) throw error;
    }
  } else await validateFirmSession(config, session, signal);
  if (identity !== legalIdentityVersion() || await legalAccessToken(config) !== accessToken) throw new LegalSignInRequired();
  signal?.throwIfAborted();
  setFirmSession(session);
  return session;
}

export const startFirmSession = (config: LegalAuthConfig, firm: FirmIdentity, signal?: AbortSignal) => start(config, firm, signal, false);
/** Setup may precede enrollment, but the attested organization/key binding is still mandatory. */
export const startFirmSetupSession = (config: LegalAuthConfig, firm: FirmIdentity, signal?: AbortSignal) => start(config, firm, signal, true);
