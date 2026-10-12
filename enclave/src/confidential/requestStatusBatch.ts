/** Bound both enclave work and the encrypted request/reply size. One batch
 * covers a normal legal board; larger directories use bounded batches. */
export const REQUEST_STATUS_BATCH_LIMIT = 256;
export type RequestStatusTarget = { caseId: string; requestId: string | null };
