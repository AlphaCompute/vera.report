import crypto from 'node:crypto';
import { sealPrivateValue, openPrivateValue } from './privateRecord';
export const REPORTER_CODE_PATTERN = /^VRC-[A-F0-9]{64}$/i;
export const LEGACY_REPORTER_CODE_PATTERN = /^VRA-[A-F0-9]{16}$/i;
export function reporterCodeHash(code: string): string {
  return crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
}
export async function createReporterAccess(trackingId: string) {
  const code = 'VRC-' + crypto.randomBytes(32).toString('hex').toUpperCase();
  return { hash: reporterCodeHash(code), encryptedCode: await sealPrivateValue(code, `report:${trackingId}`, 'reporterAccess') };
}
export async function receiptCode(report: { trackingId: string; reporterAccess?: { hash: string; encryptedCode: string } }): Promise<string> {
  if (!report.reporterAccess) return report.trackingId;
  const code = await openPrivateValue(report.reporterAccess.encryptedCode, `report:${report.trackingId}`, 'reporterAccess');
  if (typeof code !== 'string' || !REPORTER_CODE_PATTERN.test(code) || reporterCodeHash(code) !== report.reporterAccess.hash) throw new Error('Invalid stored reporter credential');
  return code;
}
