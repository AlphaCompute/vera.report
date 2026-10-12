/**
 * Reward-recipient registry — the curated allowlist a reporter picks from at
 * submission (reporter-reward flow). The allowlist is the security boundary:
 * the client sends only ids, the server resolves them to addresses, so an
 * unknown id must never survive.
 */
import {
  REWARD_RECIPIENTS,
  isValidRecipientId,
  getRewardRecipient,
  sanitizeRecipientIds,
} from '../../../../src/services/dissemination/rewardRecipients';

describe('reward-recipient registry', () => {
  it('ships the seeded recipient (Mary Inman / Whistleblower.org)', () => {
    const wb = getRewardRecipient('whistleblower-org');
    expect(wb).toBeDefined();
    expect(wb!.name).toBe('Mary Inman');
    expect(wb!.org).toBe('Whistleblower.org');
  });

  it('carries no email addresses (client-safe, display only)', () => {
    for (const r of REWARD_RECIPIENTS) {
      expect(JSON.stringify(r)).not.toMatch(/@/);
    }
  });

  it('validates ids against the allowlist', () => {
    expect(isValidRecipientId('whistleblower-org')).toBe(true);
    expect(isValidRecipientId('attacker-inbox')).toBe(false);
    expect(isValidRecipientId('')).toBe(false);
  });

  it('sanitizes an arbitrary list to known ids, deduped', () => {
    expect(sanitizeRecipientIds(['whistleblower-org', 'whistleblower-org'])).toEqual(['whistleblower-org']);
    expect(sanitizeRecipientIds(['whistleblower-org', 'nope', 42, null, {}])).toEqual(['whistleblower-org']);
    expect(sanitizeRecipientIds('whistleblower-org')).toEqual([]); // not an array
    expect(sanitizeRecipientIds(undefined)).toEqual([]);
    expect(sanitizeRecipientIds([])).toEqual([]);
  });
});
