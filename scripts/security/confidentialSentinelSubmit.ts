/**
 * Sentinel submission for the sweep (scripts/security/confidential-sentinel-sweep.cjs).
 * Publishes one synthetic report whose every private field carries a marker,
 * through the real participant client: on-device encryption, the attested
 * channel (real attestation against a deployed stack) and ciphertext staging.
 *
 *   npx ts-node scripts/security/confidentialSentinelSubmit.ts \
 *     --base https://<rehearsal host>/api/confidential --manifest confidential-release-manifest.json \
 *     --sentinels sentinels.json
 *
 * Writes the recovery code next to the sentinel file (0600) so the operator can
 * continue the firm and message steps in the browser with the same markers.
 * Never run against production: the rehearsal stack is the deployed target.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { prepareConfidentialSubmission } from '../../enclave/src/confidential/ownerSubmission';
import { fetchRelay, publishPreparedCase } from '../../lib/confidential/client';
import type { ChannelRelay } from '../../lib/confidential/client';

export type SentinelValues = Record<'narrative' | 'contact' | 'identity' | 'fileName' | 'fileContent' | 'ownerMessage' |
  'firmMessage' | 'requestPurpose', string>;

/** The summary is public by design (admins and firms see it), so it carries no marker. */
export async function submitSentinelReport(input: { relay: ChannelRelay; releaseManifest: string; values: SentinelValues; now?: number }) {
  const now = input.now ?? Date.now();
  const content = new TextEncoder().encode(`${input.values.fileContent}\n`.repeat(64));
  const prepared = await prepareConfidentialSubmission({
    summary: 'Synthetic sentinel sweep report (no real data)',
    narrative: { description: input.values.narrative, location: input.values.narrative },
    contact: { contactValue: input.values.contact },
    identity: { name: input.values.identity },
    files: [{ name: `${input.values.fileName}.txt`, type: 'text/plain', bytes: content }],
  }, input.releaseManifest, now);
  await publishPreparedCase({ relay: input.relay, releaseManifest: input.releaseManifest, now, prepared });
  return { caseId: prepared.caseId, recoveryCode: prepared.recoveryCode, recoveryPackage: prepared.recoveryPackage, owner: prepared.owner };
}

function argument(name: string): string {
  const index = process.argv.indexOf(`--${name}`);
  const value = index > 0 ? process.argv[index + 1] : undefined;
  if (!value) throw new Error(`--${name} is required`);
  return value;
}

if (require.main === module) {
  (async () => {
    const base = argument('base').replace(/\/+$/, '');
    if (!/^https:\/\//.test(base) && !/^http:\/\/(127\.0\.0\.1|localhost)[:/]/.test(base)) throw new Error('--base must be https (or local http)');
    if (/\/\/(www\.)?vera\.report\//.test(`${base}/`)) throw new Error('Refusing to submit synthetic sentinels to production');
    const sentinels = JSON.parse(readFileSync(argument('sentinels'), 'utf8')) as { format: string; values: SentinelValues };
    if (sentinels.format !== 'vera-sentinels/v1') throw new Error('not a sentinel file');
    const releaseManifest = readFileSync(argument('manifest'), 'utf8').trim();
    const result = await submitSentinelReport({ relay: fetchRelay(`${base}/channel`, `${base}/objects`), releaseManifest, values: sentinels.values });
    writeFileSync(`${argument('sentinels')}.recovery`, `${result.recoveryCode}\n`, { mode: 0o600, flag: 'wx' });
    process.stdout.write('Sentinel report published; recovery code written beside the sentinel file.\n');
  })().catch(error => { process.stderr.write(`${error instanceof Error ? error.message : 'failed'}\n`); process.exit(1); });
}
