/** Confidential-case intake is the default; only an explicit 0 selects legacy intake. The
 * build carries the canonical release manifest the participant approves at Submit.
 * There is no runtime toggle from the server: the served build decides. */
export const CONFIDENTIAL_RELEASE_MANIFEST = process.env.NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST ?? '';
/** Optional operator description of the bundled release (see releaseUpdate.ts). */
export const CONFIDENTIAL_RELEASE_NOTES = process.env.NEXT_PUBLIC_CONFIDENTIAL_RELEASE_NOTES ?? '';

export function confidentialCasesEnabled(): boolean {
  // Missing/malformed manifest must keep the confidential path selected so its
  // verifier rejects submission; it must never select legacy plaintext intake.
  return process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '0';
}

export const CONFIDENTIAL_SUMMARY_LIMIT = 600;
export const CONFIDENTIAL_REVIEW_NOTICE =
  'Your full report is encrypted on this device before it is sent. VERA administrators cannot read it. ' +
  'Your short summary, submission time and whether you included attachments are visible to VERA administrators and approved legal organizations, including those that join later; ' +
  'a legal organization can read more only if you allow it. ' +
  'Encryption does not hide your network address. Use Tor Browser if your network identity could put you at risk, and avoid work-managed devices or connections.';
/** Residual metadata (architecture hole 12). Every stored part and every relayed
 * message is padded to a size bucket inside its encryption, so storage and the
 * relay see rounded sizes, not exact ones. The number of parts is not padded (it
 * shows how many files and optional details exist), timing is visible, and the
 * signed manifest shows granted organizations which kinds exist. */
export const CONFIDENTIAL_METADATA_NOTICE =
  'Some details about your report are not hidden. VERA’s storage can see how many encrypted parts it has, which shows how many files you attached ' +
  'and whether you added contact or identity details; their sizes, rounded up to fixed steps; and when you send or change them. ' +
  'A legal organization you allow can also see which kinds of information your report includes (for example, that you left contact details or attached files), ' +
  'even for parts you do not share with it. The contents stay encrypted.';
/** Evidence limits for confidential reports (chunked object format). Must equal
 * CONFIDENTIAL_FILE_LIMIT / CONFIDENTIAL_UPLOAD_LIMIT in
 * enclave/src/confidential/ownerSubmission.ts (unit-tested); the case service
 * enforces the same bound on stored chunks. The intake's own file-count and
 * type rules are in ./evidence.ts. */
export const CONFIDENTIAL_EVIDENCE_LIMIT = 256 * 1024 * 1024;
export const CONFIDENTIAL_EVIDENCE_UPLOAD_LIMIT = 256 * 1024 * 1024;
