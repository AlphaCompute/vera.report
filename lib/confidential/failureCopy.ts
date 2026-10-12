import type { ConfidentialFailureReason } from './client';

/** Why the owner's report could not be opened, with the next step for each case.
 * Channel reasons are unauthenticated availability hints except `verification`,
 * so the copy never promises that a change was not applied. `refused`: a
 * verified service did not complete an operation for another reason.
 * `rollback`: the served history does not contain state this device (or the
 * recovery file) already holds. `recovery`: the recovery code or file did not
 * open on this device; an encrypted recovery lookup may already have been sent. */
export type OwnerFailure = ConfidentialFailureReason | 'refused' | 'rollback' | 'recovery';
export type FailureCopy = { title: string; body: string; steps: string[]; severity: 'notice' | 'warning' | 'danger';
  /** One line after a change (allow, revoke, add files, message, summary) was not confirmed. */
  action: string };

export const OWNER_FAILURE_COPY: Record<OwnerFailure, FailureCopy> = {
  offline: {
    title: 'You’re offline',
    body: 'This device could not reach VERA. Your recovery code stayed on this device.',
    steps: ['Check your internet connection.', 'This page will try again when your connection comes back, or choose Try again.'],
    severity: 'notice',
    action: 'You’re offline. Reconnect, then check your report before trying again.',
  },
  unavailable: {
    title: 'VERA’s secure service is temporarily unavailable',
    body: 'VERA’s website answered, but its secure service did not. This usually means maintenance or an update is in progress. ' +
      'Your recovery code stayed on this device.',
    steps: ['Try again in a few minutes.', 'If it lasts more than a day, come back later. Your recovery code keeps working.'],
    severity: 'notice',
    action: 'VERA’s secure service is temporarily unavailable. Check your report in a few minutes before trying again.',
  },
  busy: {
    title: 'VERA’s secure service is busy',
    body: 'Too many requests reached the secure service in a short time.',
    steps: ['Wait a minute, then choose Try again.'],
    severity: 'notice',
    action: 'VERA’s secure service is busy. Wait a minute, then check your report before trying again.',
  },
  clock: {
    title: 'This device’s date and time look wrong',
    body: 'Your browser could not verify VERA’s secure service because this device’s clock is far from the service’s time. ' +
      'Your recovery code stayed on this device.',
    steps: ['Set your date and time to update automatically, then choose Try again.'],
    severity: 'warning',
    action: 'This device’s date and time look wrong. Fix them, then check your report before trying again.',
  },
  verification: {
    title: 'We could not verify VERA’s secure service',
    body: 'Your browser checks that it is talking to the approved secure service, and that its encrypted replies are genuine. ' +
      'That check failed. Your recovery code stayed on this device. This can happen for a short time during an update, ' +
      'but it can also mean someone is interfering with your connection.',
    steps: [
      'Don’t try again on this network for now.',
      'Later, reload this page to get the latest version of VERA, and try from a different network, for example mobile data instead of public Wi-Fi.',
      'If it keeps failing on different networks, contact VERA through a channel you trust. Never send your recovery code.',
    ],
    severity: 'danger',
    action: 'The secure service could not be verified, which can mean someone is interfering with your connection. Don’t try again on this network for now.',
  },
  refused: {
    title: 'The secure service could not open your report',
    body: 'The connection was verified, but the service did not complete the request.',
    steps: ['Try again in a few minutes.', 'If you changed your report on another device, open your newest recovery file instead.'],
    severity: 'warning',
    action: 'The secure service did not complete it. Reload your report, check what it shows, then try again.',
  },
  rollback: {
    title: 'Your report’s history doesn’t match',
    body: 'The history VERA returned is older than, or different from, what this device or your recovery file already saw. ' +
      'Don’t rely on what VERA shows, and don’t share anything new, until this is resolved.',
    steps: ['Try again later.', 'Open your newest recovery file, or use a device where you opened your report most recently.'],
    severity: 'danger',
    action: 'Your report’s history doesn’t match what this device saw. Don’t share anything new; try again later.',
  },
  recovery: {
    title: 'That recovery code didn’t open a report',
    body: 'The recovery code or file could not open the report on this device. Your recovery code stayed on this device.',
    steps: ['Check that you copied the whole recovery code for this report, or open your recovery file instead.',
      'If you used a recovery file, it may be damaged. Try typing the recovery code instead.'],
    severity: 'warning',
    action: 'Open your report again with your recovery code, then try again.',
  },
};

/** Classify a failure from opening or changing a report. Uses error names so the
 * page need not load the cryptographic modules to render an error. */
export function ownerFailureOf(error: unknown, restored: boolean): OwnerFailure {
  if (error instanceof Error && error.name === 'ConfidentialRollbackError') return 'rollback';
  if (error instanceof Error && error.name === 'ConfidentialUnavailableError') {
    const reason = (error as Error & { reason?: unknown }).reason;
    if (typeof reason === 'string' && reason in OWNER_FAILURE_COPY && reason !== 'rollback' && reason !== 'recovery') {
      return reason as OwnerFailure;
    }
    return 'refused';
  }
  return restored ? 'refused' : 'recovery';
}
