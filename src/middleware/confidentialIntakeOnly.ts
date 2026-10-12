import type { RequestHandler } from 'express';

/** Plaintext intake requires an explicit legacy selection in this process.
 * A separately built frontend flag is not visible here: legacy deployments must
 * also set NEXT_PUBLIC_CONFIDENTIAL_CASES=0 in the backend runtime environment.
 * Either server-side cutover flag overrides that legacy selection. */
export function confidentialIntakeRequired(env: NodeJS.ProcessEnv = process.env): boolean {
  // CONFIDENTIAL_INTAKE_REQUIRED: dedicated layout, where confidential routes run
  // in a separate task but this legacy process must still refuse plaintext intake.
  return env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '0' || env.CONFIDENTIAL_CASES_ENABLED === 'true' ||
    env.CONFIDENTIAL_INTAKE_REQUIRED === 'true';
}

/** Reject before body parsing, upload admission, legacy processing or logging.
 * Historical reporter routes are unaffected. This also catches an old frontend
 * deployed against a confidential backend; it cannot silently store plaintext. */
export const confidentialIntakeOnly: RequestHandler = (_req, res, next) => {
  if (!confidentialIntakeRequired()) { next(); return; }
  res.setHeader('Cache-Control', 'no-store');
  res.status(409).json({ success: false, error: 'confidential_intake_required',
    message: 'Secure intake is required. Reload the application before submitting.' });
};
