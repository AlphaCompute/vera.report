import { CONFIDENTIAL_RELEASE_MANIFEST } from './config';
import { exchange, fetchRelay, verifiedSession, ConfidentialUnavailableError } from './client';
import { legalAccessToken } from './legalAuth';
import type { LegalAuthConfig } from './legalAuth';
import type { FirmIdentity } from './firmKey';
import { matchingMembershipLease, completeLegalSetup } from './completeLegalSetup';
import { startFirmSession } from '@/components/vera/confidential/LegalPortal';
import { prepareStewardDevice } from './firmDeviceSession';

export async function activateCombinedApplication(config: LegalAuthConfig, firm: FirmIdentity): Promise<boolean> {
  const input = { relay: fetchRelay(), releaseManifest: CONFIDENTIAL_RELEASE_MANIFEST, now: Date.now(),
    accessToken: await legalAccessToken(config), firm, invitation: '' };
  const before = await matchingMembershipLease(input);
  if (!(before && before > Date.now())) {
    const channel = await verifiedSession(input.relay, input.releaseManifest, input.now);
    const result = await exchange(input.relay, channel, { operation: 'legal.activate-application', accessToken: input.accessToken,
      organizationId: firm.organizationId }) as { state?: unknown; token?: unknown };
    if (result.state === 'pending') return false;
    if (result.state !== 'approved' || typeof result.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(result.token)) throw new ConfidentialUnavailableError();
    await completeLegalSetup({ ...input, invitation: result.token }, before);
  }
  const session = await startFirmSession(config, firm);
  await prepareStewardDevice(session, Date.now());
  return true;
}

/** Membership appears only after the first verified OTP. Allow the independent
 * Slack approval signer to observe it; pending never counts as approval. */
export async function waitForCombinedActivation(config: LegalAuthConfig, firm: FirmIdentity): Promise<void> {
  const deadline = Date.now() + 90_000;
  do {
    if (await activateCombinedApplication(config, firm)) return;
    await new Promise(resolve => setTimeout(resolve, 3000));
  } while (Date.now() < deadline);
  throw new ConfidentialUnavailableError();
}
