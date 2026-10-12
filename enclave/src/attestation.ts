import { execFile } from 'node:child_process';

const HELPER = '/app/bin/vera-nsm';
let busy = false;

/** Return NSM evidence for independent verification; this is not a trusted channel. */
export async function attestIdentity(params: Record<string, unknown>): Promise<{ document: string }> {
  if (Object.keys(params).length !== 1 || typeof params.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(params.nonce)) {
    throw new Error('A 32-byte lowercase hexadecimal nonce is required');
  }
  if (busy) throw new Error('Attestation already in progress');
  busy = true;
  try {
    const output = await new Promise<string>((resolve, reject) => {
      const child = execFile(HELPER, [], { timeout: 10_000, maxBuffer: 24 * 1024 }, (error, stdout) => {
        if (error) reject(new Error('NSM attestation unavailable'));
        else resolve(stdout);
      });
      child.stdin!.on('error', () => {}); // The child callback reports failed execution.
      child.stdin!.end(JSON.stringify({ nonce: Buffer.from(params.nonce as string, 'hex').toString('base64') }));
    });
    const result: unknown = JSON.parse(output);
    if (!result || typeof result !== 'object' || Array.isArray(result) || Object.keys(result).length !== 1) {
      throw new Error('Invalid NSM response');
    }
    const document = (result as Record<string, unknown>).document;
    if (typeof document !== 'string' || !document.length || document.length > 21848 ||
        Buffer.from(document, 'base64').toString('base64') !== document || Buffer.from(document, 'base64').length > 16384) {
      throw new Error('Invalid NSM document encoding');
    }
    return { document };
  } finally { busy = false; }
}
