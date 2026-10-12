/**
 * Curated reward-recipient registry (reporter-reward flow).
 *
 * The recipients a reporter can choose to receive a one-time secure link to
 * their identity-free disclosure packet — whistleblower attorneys / advocacy
 * orgs / reward-program contacts who can help pursue a reward.
 *
 * DISPLAY ONLY — this module carries NO email addresses and is safe to import
 * into the client bundle. The actual send addresses live server-side in the
 * `DISSEMINATION_RECIPIENT_EMAILS` env map (see securePacketSender.ts): the
 * client only ever sends a recipient `id`, and the server resolves it to a
 * vetted address. That id→email allowlist is what stops a tampered submission
 * from redirecting a packet to an arbitrary inbox.
 */

export interface RewardRecipient {
  /** Stable key — sent by the client, resolved to an email server-side. */
  id: string;
  /** Contact name shown to the reporter. */
  name: string;
  /** Organisation shown to the reporter. */
  org: string;
  /** One-line description of who they are / how they help. */
  blurb: string;
}

/**
 * The recipients offered at submission. Adding one is a deliberate code change
 * here (display) plus an entry in the server-side `DISSEMINATION_RECIPIENT_EMAILS`
 * env map (address). A recipient with no configured address is only sendable in
 * dryrun (routes to the test inbox); a live send to it is skipped.
 */
export const REWARD_RECIPIENTS: readonly RewardRecipient[] = [
  {
    id: 'whistleblower-org',
    name: 'Mary Inman',
    org: 'Whistleblower.org',
    blurb:
      'Whistleblower attorney — can help you pursue a reward and represent your disclosure.',
  },
];

export function isValidRecipientId(id: string): boolean {
  return REWARD_RECIPIENTS.some((r) => r.id === id);
}

export function getRewardRecipient(id: string): RewardRecipient | undefined {
  return REWARD_RECIPIENTS.find((r) => r.id === id);
}

/** Filter an arbitrary list down to the known, valid recipient ids (deduped). */
export function sanitizeRecipientIds(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  const seen = new Set<string>();
  for (const id of ids) {
    if (typeof id === 'string' && isValidRecipientId(id)) seen.add(id);
  }
  return [...seen];
}
