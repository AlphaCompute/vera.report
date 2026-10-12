/** Closed lists for structured access request details, kept free of
 * cryptography so pages can use them without loading openpgp. accessRequest.ts
 * re-exports both and validates requests against them. */
export const FEE_BASES = ['no-fee', 'contingency', 'hourly', 'fixed', 'to-discuss'] as const;
export const RESPONSE_TIMES = ['two-days', 'one-week', 'two-weeks', 'one-month'] as const;
