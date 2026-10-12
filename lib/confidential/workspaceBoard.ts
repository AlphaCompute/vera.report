import type { FirmCaseStatus } from './firmCaseView';

export type RequestBoardLane = 'waiting' | 'shared' | 'attention';

/** Unknown, failed and replaced-key checks must never look like confirmed access. */
export function requestBoardLane(status: FirmCaseStatus | undefined, replacedKey = false): RequestBoardLane {
  if (replacedKey) return 'attention';
  if (status?.kind === 'granted') return 'shared';
  if (status?.kind === 'waiting') return 'waiting';
  return 'attention';
}
