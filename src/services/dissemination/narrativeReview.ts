import type { DisseminationView, DispositionDoc } from './types';

/** An approval for a replacement narrative must not authorize an older view. */
export function reviewedNarrativeMatches(
    view: Pick<DisseminationView, 'narrative'>,
    disposition: Pick<DispositionDoc, 'narrativeOverride' | 'narrativeReviewedAt'> | null | undefined,
): boolean {
    const replacement = disposition?.narrativeOverride?.narrative;
    if (replacement?.trim()) return view.narrative === replacement;
    return !!disposition?.narrativeReviewedAt;
}
