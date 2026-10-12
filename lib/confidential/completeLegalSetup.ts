import { ConfidentialUnavailableError } from './client';
import { redeemInvitation } from './firmCase';
import { readMembershipStatus } from './firmOnboarding';

type SetupInput = Parameters<typeof redeemInvitation>[0];

/** The current lease end for this exact organization key: 0 when it holds no
 * membership, null when the attested status could not be read. */
export async function matchingMembershipLease(input: SetupInput): Promise<number | null> {
  try {
    const status = await readMembershipStatus(input);
    return status.state === 'enrolled' && status.keyMatches ? status.leaseExpiresAt : 0;
  } catch { return null; }
}

/** Approval already carries the invitation request. Finish enrollment with the
 * saved key automatically, keeping Auth0 identity and signed membership checks.
 *
 * `before` is matchingMembershipLease() read before the first redemption attempt
 * of this link. A lost redemption reply counts as success only when the channel
 * failed (never a local key/organization mismatch) and the attested membership
 * for this key is now later than it was before. An existing, older membership
 * therefore cannot make a revoked or expired link look accepted. */
export async function completeLegalSetup(input: SetupInput, before: number | null): Promise<void> {
  try { await redeemInvitation(input); }
  catch (error) {
    if (before === null || !(error instanceof ConfidentialUnavailableError)) throw error;
    const after = await matchingMembershipLease(input);
    if (after !== null && after > before && after > Date.now()) return;
    throw error;
  }
}
