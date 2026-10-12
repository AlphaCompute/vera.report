// What the click-through suite expects the receipt's recovery code to look
// like. Kept free of Playwright runtime imports so the unit suite can exercise it.
import { parseRecoveryCode, RECOVERY_CODE_GROUPS, RECOVERY_CODE_GROUP_SIZE } from '../../../enclave/src/confidential/recoveryCode';

/** Crockford base32 as displayed: upper case, no I, L, O or U. */
const CHAR = '[0-9A-HJKMNP-TV-Z]';
const GROUP = `${CHAR}{${RECOVERY_CODE_GROUP_SIZE}}`;

/** The displayed v2 recovery code: 14 groups of 4, joined with hyphens. */
export const DISPLAYED_RECOVERY_CODE = new RegExp(`^(?:${GROUP}-){${RECOVERY_CODE_GROUPS - 1}}${GROUP}$`);

/**
 * Why a code scraped from the receipt is not a restorable recovery code, or
 * null when it is: exactly the grouped display format and a valid checksum.
 * The reason never includes the code itself.
 */
export async function displayedRecoveryCodeProblem(code: string): Promise<string | null> {
  if (!DISPLAYED_RECOVERY_CODE.test(code)) return `not ${RECOVERY_CODE_GROUPS} groups of ${RECOVERY_CODE_GROUP_SIZE} recovery code characters`;
  try {
    const parsed = await parseRecoveryCode(code);
    parsed.secret.fill(0);
    return parsed.version === 'v2' && parsed.code === code ? null : 'not in its canonical display form';
  } catch {
    return 'checksum does not match';
  }
}
