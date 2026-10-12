import { createHash } from 'node:crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectVersionsCommand, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import { MAX_STORED_EVIDENCE_BYTES, EVIDENCE_TRANSFER_TIMEOUT_MS } from '../utils/evidenceLimits';

/** Optional second copy of already-encrypted evidence. No envelope keys or names. */
function configuration() {
  const bucket = process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET;
  if (!bucket) return null;
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket)) throw new Error('Invalid ciphertext archive bucket');
  const endpoint = process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT;
  if (endpoint) {
    const url = new URL(endpoint);
    if (process.env.NODE_ENV === 'production' || url.protocol !== 'http:' ||
        !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ||
        url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      throw new Error('Archive test endpoint must be non-production HTTP loopback');
    }
  }
  return { bucket, endpoint };
}
export function ciphertextArchiveEnabled(): boolean { return configuration() !== null; }
function key(cid: string) {
  if (!/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{20,120})$/.test(cid)) throw new Error('Invalid archive CID');
  return `ciphertext/v1/${cid}`;
}
function client(endpoint?: string) {
  return new S3Client({ region: process.env.AWS_REGION || 'us-east-2', maxAttempts: 2,
    ...(endpoint ? { endpoint, forcePathStyle: true, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } } : {}),
  });
}
export async function archiveCiphertext(cid: string, ciphertext: Buffer): Promise<void> {
  const config = configuration();
  if (!config) return;
  if (!ciphertext.length || ciphertext.length > MAX_STORED_EVIDENCE_BYTES) throw new Error('Invalid archive ciphertext size');
  const s3 = client(config.endpoint);
  try {
    const result = await s3.send(new PutObjectCommand({ Bucket: config.bucket, Key: key(cid), Body: ciphertext,
      ContentType: 'application/octet-stream', ChecksumSHA256: createHash('sha256').update(ciphertext).digest('base64'),
    }), { abortSignal: AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS) });
    if (result.$metadata.httpStatusCode !== 200 || !result.ETag) throw new Error('Archive write not acknowledged');
  } finally { s3.destroy(); }
}
export async function retrieveArchivedCiphertext(cid: string): Promise<Buffer> {
  const config = configuration();
  if (!config) throw new Error('Ciphertext archive not configured');
  const s3 = client(config.endpoint);
  let body: any;
  const controller = new AbortController();
  // Keep the deadline through stream consumption, not merely response headers.
  const timer = setTimeout(() => { controller.abort(); body?.destroy?.(new Error('Archive read timed out')); }, EVIDENCE_TRANSFER_TIMEOUT_MS);
  timer.unref();
  try {
    const result = await s3.send(new GetObjectCommand({ Bucket: config.bucket, Key: key(cid) }),
      { abortSignal: controller.signal });
    body = result.Body;
    if (result.$metadata.httpStatusCode !== 200 || !body ||
        (result.ContentLength !== undefined && result.ContentLength > MAX_STORED_EVIDENCE_BYTES)) throw new Error('Invalid archive response');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      size += chunk.length;
      if (size > MAX_STORED_EVIDENCE_BYTES) throw new Error('Oversized archive response');
      chunks.push(Buffer.from(chunk));
    }
    if (!size) throw new Error('Empty archive response');
    return Buffer.concat(chunks);
  } finally { clearTimeout(timer); body?.destroy?.(); s3.destroy(); }
}
// Consent withdrawal: remove every version and delete marker of the object so a
// versioned bucket keeps no recoverable copy. Returns how many entries were deleted.
export async function deleteArchivedCiphertext(cid: string): Promise<number> {
  const config = configuration();
  if (!config) return 0;
  const objectKey = key(cid);
  const s3 = client(config.endpoint);
  const signal = AbortSignal.timeout(EVIDENCE_TRANSFER_TIMEOUT_MS);
  async function versions() {
    const found: { Key: string; VersionId: string }[] = [];
    let KeyMarker: string | undefined, VersionIdMarker: string | undefined;
    do {
      const page = await s3.send(new ListObjectVersionsCommand({ Bucket: config!.bucket, Prefix: objectKey, KeyMarker, VersionIdMarker }), { abortSignal: signal });
      // The prefix can also match longer CIDv1 keys; only this exact key is removed.
      for (const entry of [...(page.Versions || []), ...(page.DeleteMarkers || [])]) {
        if (entry.Key === objectKey && entry.VersionId) found.push({ Key: objectKey, VersionId: entry.VersionId });
      }
      if (!page.IsTruncated) break;
      KeyMarker = page.NextKeyMarker; VersionIdMarker = page.NextVersionIdMarker;
      if (!KeyMarker) throw new Error('Invalid archive listing');
    } while (true);
    return found;
  }
  try {
    const found = await versions();
    for (let i = 0; i < found.length; i += 1000) {
      const result = await s3.send(new DeleteObjectsCommand({ Bucket: config.bucket, Delete: { Objects: found.slice(i, i + 1000), Quiet: true } }), { abortSignal: signal });
      if (result.Errors?.length) throw new Error('Archive deletion incomplete');
    }
    // A concurrent write would leave a version behind; report it rather than claim deletion.
    if ((await versions()).length) throw new Error('Archive deletion incomplete');
    return found.length;
  } finally { s3.destroy(); }
}
