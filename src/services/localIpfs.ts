import { archiveCiphertext, retrieveArchivedCiphertext, ciphertextArchiveEnabled, deleteArchivedCiphertext } from './ciphertextArchive';
import { MAX_STORED_EVIDENCE_BYTES, EVIDENCE_TRANSFER_TIMEOUT_MS } from '../utils/evidenceLimits';
import { logger } from '../utils/logger';
/** Encrypted storage through the Kubo add/cat/rm proxy: the API task's `ipfs`
 * sidecar, or the co-located enclave bridge. The Kubo node is disposable, so
 * production requires the S3 ciphertext archive as the source of truth.
 */
const LIMIT = MAX_STORED_EVIDENCE_BYTES;
// Loopback for a shared network namespace (Fargate awsvpc, local tests), or the
// ECS task link alias of the sidecar in bridge mode. Nothing else is accepted.
const HOSTS = ['127.0.0.1', 'localhost', '[::1]', 'ipfs'];
/** The only evidence ciphertext backend. There is no third-party fallback. */
export const LOCAL_IPFS_BACKEND = 'local-enclave';
/** Fails closed unless IPFS_STORAGE_BACKEND selects the self-hosted Kubo node
 * and, in production, the S3 archive and an explicit proxy origin are set. */
export function requireLocalIpfs(): void {
  if (process.env.IPFS_STORAGE_BACKEND !== LOCAL_IPFS_BACKEND) {
    throw new Error(`IPFS_STORAGE_BACKEND must be ${LOCAL_IPFS_BACKEND}`);
  }
  if (process.env.NODE_ENV === 'production') {
    if (!ciphertextArchiveEnabled()) throw new Error('Local IPFS in production requires the ciphertext archive');
    if (!process.env.ENCLAVE_IPFS_URL) throw new Error('Local IPFS in production requires an explicit ENCLAVE_IPFS_URL');
    endpoint('/');
  }
}
function endpoint(path: string): string {
  const url = new URL(process.env.ENCLAVE_IPFS_URL || 'http://127.0.0.1:15002');
  if (url.protocol !== 'http:' || !HOSTS.includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('Local IPFS URL must be an HTTP loopback or ipfs sidecar origin');
  }
  return new URL(path, url).href;
}
async function request(path: string, body: Uint8Array): Promise<Buffer> {
  const response = await fetch(endpoint(path), {
    method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'Connection': 'close' },
    body: body as BodyInit, redirect: 'error', signal: AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS),
  });
  if (!response.ok || !response.body) { await response.body?.cancel(); throw new Error('Local IPFS request failed'); }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > (path === '/cat' ? LIMIT : 4096)) throw new Error('Local IPFS response too large');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks);
}
const cidPattern = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})$/;
async function addCiphertext(ciphertext: Buffer): Promise<string> {
  if (!ciphertext.length || ciphertext.length > LIMIT) throw new Error('Ciphertext size outside local IPFS limit');
  const result = JSON.parse((await request('/add', ciphertext)).toString());
  if (typeof result.cid !== 'string' || !cidPattern.test(result.cid)) throw new Error('Invalid storage CID');
  return result.cid;
}
export async function storeLocalCiphertext(ciphertext: Buffer): Promise<string> {
  // Validate optional configuration before accepting even the temporary pin.
  ciphertextArchiveEnabled();
  const cid = await addCiphertext(ciphertext);
  await archiveCiphertext(cid, ciphertext);
  return cid;
}
export async function readLocalCiphertext(cid: string): Promise<Buffer> {
  if (!cidPattern.test(cid)) throw new Error('Invalid storage CID');
  const archived = ciphertextArchiveEnabled();
  try { return await request('/cat', Buffer.from(cid)); } catch (error) {
    if (!archived) throw error;
    const ciphertext = await retrieveArchivedCiphertext(cid);
    // Reconstruct the selected Kubo CID before exposing recovered bytes. A
    // malicious/corrupt archive cannot substitute content under an old CID.
    const restored = await addCiphertext(ciphertext);
    if (restored !== cid) {
      // The IpfsCidMismatch alarm matches this line; callers only log a category.
      logger.error('Archived ciphertext CID mismatch');
      throw new Error('Archived ciphertext CID mismatch');
    }
    return ciphertext;
  }
}
// Consent withdrawal: drop the Kubo pin and blocks, then every archived version.
// Both steps are idempotent, so a failed attempt can simply be retried.
export async function unpinLocalCiphertext(cid: string): Promise<void> {
  if (!cidPattern.test(cid)) throw new Error('Invalid storage CID');
  ciphertextArchiveEnabled();
  const result = JSON.parse((await request('/rm', Buffer.from(cid))).toString());
  if (result.cid !== cid) throw new Error('Local IPFS unpin not acknowledged');
  await deleteArchivedCiphertext(cid);
}
