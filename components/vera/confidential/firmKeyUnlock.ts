import type { FirmSession } from "@/lib/confidential/firmCase";
import type { FirmIdentity } from "@/lib/confidential/firmKey";

export const KEY_MISMATCH_MESSAGE = "That key file and recovery code or passphrase do not match.";
export const REPORT_FILE_MESSAGE = "This is a reporter recovery file. Open it on the Status page (/status). Here, select your organization's vera-legal-key-PRIVATE file instead.";
export const REPORT_CODE_MESSAGE = "That looks like a report recovery code. This key needs the organization's code beginning VERA-FIRM-1. or the passphrase chosen during key setup.";
export const SESSION_START_FALLBACK =
  "Your key file and recovery code match, but the secure connection could not be opened. Try again in a moment.";
/** For failures before the key file is checked, such as the page failing to load a module. */
export const CONNECTION_FALLBACK = "The secure connection could not be opened. Try again in a moment.";

export type FirmKeyUnlockResult = { ok: true; session: FirmSession } | { ok: false; message: string };

/** Key file + secret -> firm session, keeping the two failure kinds apart:
 * only a failed decrypt of the key file is reported as a credential mismatch.
 * Failures after that (organization or membership checks, release manifest
 * verification, attestation, relay, sign-in) keep their own guidance, so a
 * lawyer with correct credentials is never told to recheck them. */
export async function unlockFirmKey(keyFileText: string, secret: string, deps: {
  importIdentity: (keyFileText: string, secret: string) => Promise<FirmIdentity>;
  start: (firm: FirmIdentity) => Promise<FirmSession>;
  describeStartFailure: (error: unknown, fallback: string) => string;
}): Promise<FirmKeyUnlockResult> {
  let firm: FirmIdentity;
  try {
    firm = await deps.importIdentity(keyFileText, secret);
  } catch {
    // Explain a format mix-up only after decryption fails. A custom firm
    // passphrase may happen to look like a report code and must still work.
    if (keyFileText.split('\n').some(line => /^\s*\{\s*"format"\s*:\s*"vera-owner-recovery\//.test(line))) {
      return { ok: false, message: REPORT_FILE_MESSAGE };
    }
    if (/^(?:VERA-OWNER-1\.|[A-Z0-9]{4}(?:-[A-Z0-9]{4}){13}$)/i.test(secret.trim())) {
      return { ok: false, message: REPORT_CODE_MESSAGE };
    }
    return { ok: false, message: KEY_MISMATCH_MESSAGE };
  }
  try {
    return { ok: true, session: await deps.start(firm) };
  } catch (error) {
    return { ok: false, message: deps.describeStartFailure(error, SESSION_START_FALLBACK) };
  }
}
