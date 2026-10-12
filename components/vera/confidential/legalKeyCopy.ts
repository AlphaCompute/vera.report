/** User-facing copy for the offline `/legal/keys` ceremony. Kept here so the
 * one-term-per-concept rule (legal organization, reporter, access, recovery
 * code) is testable: this page is shown to legal organizations and must not
 * say "firm", "owner", "case", "grant" or "epoch". Technical detail (key
 * version, member key files) stays inside the advanced section. */
export type KeyCeremonyMode = 'create' | 'wrap' | 'unwrap' | 'rotate';

export const KEY_CEREMONY_COPY = {
  title: 'Organization key administration',
  intro: 'Use an individual device key for each lawyer and a separate steward key for distribution. Confirm public-key fingerprints through your organization before importing them. VERA cannot recover these keys.',
  actionLabel: 'Action',
  modes: {
    create: 'Create an individual or onboarding key',
    wrap: 'Prepare a key file for a member',
    unwrap: 'Open a key file prepared for me',
    rotate: 'Replace the organization key after removing a member',
  } satisfies Record<KeyCeremonyMode, string>,
  organizationId: 'Organization ID',
  organizationDomain: 'Organization domain',
  individualKeyFile: 'Your individual encrypted key file',
  organizationKeyFile: 'Encrypted organization key file',
  keyRecoveryCode: 'Key recovery code',
  stewardKeyFile: 'Encrypted steward key file',
  stewardRecoveryCode: 'Steward recovery code',
  memberPublicKey: 'Verified member public key',
  memberId: 'Organization-assigned member ID (64 lowercase hexadecimal characters)',
  memberKeyFile: 'Key file prepared for you',
  stewardPublicKey: 'Independently verified steward public key',
  organizationPublicKey: 'Independently verified organization public key',
  removedMembers: 'Removed member IDs, separated by spaces',
  rotateHint: 'Also remove departing members in your identity provider. Replacing the key cannot erase information or keys they already received. Every reporter must allow access again for the new key.',
  outputRecoveryCode: 'Recovery code for the new encrypted file (at least 16 characters; save separately)',
  advancedSummary: 'Advanced: key version',
  advancedHint: 'Leave this at 1 unless the organization key has been replaced before. It must match the version on the key files you use.',
  currentKeyVersion: 'Current key version',
  expectedKeyVersion: 'Expected key version',
  submit: 'Prepare files',
  rotated: 'Files prepared. Submit the replacement public key from the organization workspace for VERA approval, and give each remaining member a new key file. Every reporter must allow access again for the new key; current access does not move over.',
  prepared: 'Files prepared on this device. Keep private key files and their recovery codes separately.',
  failed: 'The keys or inputs could not be verified. Nothing was changed for your organization or for any report.',
} as const;
