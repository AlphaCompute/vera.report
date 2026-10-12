/**
 * Which stored consent authorizes which channel (FR-8, #926).
 *
 * Every gate — routing, approval, dispatch, escrow and counsel access — asks
 * here, for both the live report consent and the disposition snapshot, so the
 * version-aware reading of `agency` cannot drift between call sites.
 */

import { agencyDispatchConsented, legalReviewConsented } from '../../utils/intakeConsent';
import { SECURE_LINK_ENTITY_ID } from './secureLink';

type ChannelConsent = {
  psst?: { granted?: unknown };
  agency?: unknown;
  legalReview?: unknown;
  press?: unknown;
  textVersion?: unknown;
} | null | undefined;

export function channelConsented(consent: ChannelConsent, entityId: string): boolean {
  if (entityId === 'psst-safe') return consent?.psst?.granted === true;
  if (entityId === 'securedrop') return consent?.press === true;
  if (entityId === SECURE_LINK_ENTITY_ID) return legalReviewConsented(consent);
  return agencyDispatchConsented(consent);
}
