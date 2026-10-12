import { CONFIDENTIAL_SUMMARY_LIMIT } from './config';
/** Only this owner-approved summary is published. Private report fields stay encrypted. */
export type ListingDraft = { summary: string };
export const EMPTY_LISTING_DRAFT: ListingDraft = { summary: '' };
export function listingDraftFrom(summary: string | null): ListingDraft { return { summary: summary ?? '' }; }
export function listingDraftProblem(draft: ListingDraft): string | null {
  if (!draft.summary.trim()) return 'Write a short summary for legal review.';
  if (draft.summary.length > CONFIDENTIAL_SUMMARY_LIMIT) return `Keep the summary to ${CONFIDENTIAL_SUMMARY_LIMIT} characters or fewer.`;
  return null;
}
