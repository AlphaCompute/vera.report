import type { ReleaseUpdate } from './releaseUpdate';

/** What changed, in one sentence. Kept free of cryptographic imports so the
 * status page can render it without bundling openpgp statically. */
export function releaseChangeSentence(update: ReleaseUpdate): string {
  if (update.notes) return update.notes.summary;
  return 'VERA replaced the secure service software that handles your encrypted report. ' +
    'VERA did not publish a description of this release; its source code is linked under technical details.';
}
