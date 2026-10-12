/** Confidential-format identifiers that legacy readers must refuse before any
 * lookup. A recovery code is a device-held owner secret; it must never be sent
 * to, looked up by, or logged by a legacy route. Two formats exist: the legacy
 * long `VERA-OWNER-1.` code and the current bare secret written as 56 base32
 * characters in groups (`7K3M-9QXA-…`). The second has no prefix, so it is
 * recognised by shape, generously (a mistyped code with a group missing or
 * added is still a secret). Legacy report IDs (`VRA-`/`VRC-` + hex) never match.
 * A 64-hex confidential case ID never names a legacy report. Callers respond
 * with a generic error and never echo or log the value.
 * Keep in step with `recoveryCodeShape` in enclave/src/confidential/recoveryCode.ts. */
const OWNER_CODE_V1 = /^\s*VERA-OWNER-/i;
const LEGACY_REPORT_ID = /^\s*VR[AC]-/i;
const CASE_ID = /^\s*[a-f0-9]{64}\s*$/i;

function looksLikeShortOwnerCode(value: string): boolean {
  if (value.length > 256 || LEGACY_REPORT_ID.test(value)) return false;
  const chars = value.replace(/[\s\-_·–—]+/g, '');
  // No digit heuristic: valid codes can contain no digits, and typos stay private.
  // Long prose can conservatively match; only strict legacy IDs go to legacy lookup.
  return chars.length >= 40 && chars.length <= 72 && /^[0-9A-Za-z]+$/.test(chars);
}

export function isConfidentialOwnerCode(value: unknown): boolean {
  return typeof value === 'string' && (OWNER_CODE_V1.test(value) || looksLikeShortOwnerCode(value));
}

export function isConfidentialCaseId(value: unknown): boolean {
  return typeof value === 'string' && CASE_ID.test(value);
}

export function isConfidentialIdentifier(value: unknown): boolean {
  return isConfidentialOwnerCode(value) || isConfidentialCaseId(value);
}
