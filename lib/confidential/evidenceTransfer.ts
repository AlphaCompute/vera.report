import { ConfidentialRateLimitError } from './readRetry';
import { LegalSignInRequired } from './legalAuth';
import { ConfidentialUnavailableError, base64 } from './client';
import { ChunkedObjectError, MAX_CHUNK_CIPHERTEXT_BYTES } from '../../enclave/src/confidential/caseChunks';
import type { ChunkedObjectReader } from '../../enclave/src/confidential/caseChunks';
import type { TransferProgress } from './evidence';
import { OPAQUE_DOWNLOAD_TYPE, safeDownloadName } from './safeDownload';
export { formatBytes, percent } from './evidence';
export type { TransferProgress } from './evidence';

/** Streaming download of chunked evidence on a participant device (reporter or
 * legal organization). Each chunk is fetched through the attested channel,
 * checked against the owner-signed index, decrypted and handed to a sink, so a
 * 256 MB file never has to sit in memory as ciphertext. Evidence is only ever
 * saved as a file, never rendered in this origin. */

/** Where decrypted bytes go. `close` completes the file; `abort` discards it. */
export type EvidenceSink = { write(bytes: Uint8Array): Promise<void>; close(): Promise<void>; abort(): Promise<void> };
/** A verified, currently authorized view of one chunked object. */
export type OpenedChunkedEvidence = {
  reader: ChunkedObjectReader;
  /** One authenticated chunk read through the attested channel (ciphertext). */
  fetchChunk(position: number): Promise<Uint8Array>;
};

export class EvidenceDownloadError extends Error {
  constructor(readonly reason: 'interrupted' | 'changed' | 'integrity') {
    super(reason === 'changed'
      ? 'This file changed or access was changed since the download started. Start the download again.'
      : reason === 'integrity'
        ? 'This file failed its integrity check and was not saved. It may have been altered in storage.'
        : 'The download was interrupted. Check your connection, then resume.');
  }
}

const RATE_WAITS = 6;

/** Resumable download of one chunked evidence file into one sink. `open` must
 * re-verify authorization (grant, release, checkpoint, manifest) every time it
 * is called; a resume continues only while the object's signed digest is
 * unchanged. Chunks already written stay written. */
export class EvidenceDownload {
  private next = 0;
  private done = 0;
  private digest: string | null = null;
  private finished = false;
  private cancelled = false;
  constructor(private readonly sink: EvidenceSink, private readonly open: () => Promise<OpenedChunkedEvidence>,
    private readonly wait: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms))) {}

  get progress(): TransferProgress { return { bytesDone: this.done, bytesTotal: this.total }; }
  private total = 0;

  /** Runs (or resumes) the download. Resolves when the complete file is saved. */
  async run(options: { onProgress?: (progress: TransferProgress) => void; signal?: AbortSignal } = {}): Promise<void> {
    if (this.finished || this.cancelled) throw new EvidenceDownloadError('changed');
    const checkActive = () => {
      if (this.cancelled || options.signal?.aborted) throw new EvidenceDownloadError('interrupted');
    };
    checkActive();
    const report = () => { try { options.onProgress?.(this.progress); } catch { /* display only */ } };
    let opened = await this.reopen();
    let refreshed = false;
    report();
    try {
      checkActive();
      while (this.next < opened.reader.index.chunkCount) {
        checkActive();
        let ciphertext: Uint8Array;
        try {
          ciphertext = await this.fetch(opened, this.next, checkActive);
        } catch (error) {
          checkActive();
          // An expired sign-in is not a changed report: stop here, keep what is
          // written, and resume after the caller renews the sign-in.
          if (error instanceof EvidenceDownloadError || error instanceof LegalSignInRequired) throw error;
          // A checkpoint change (for example new files added) ends a read session.
          // Re-verify once and continue if this object is still the same and allowed.
          if (refreshed) throw new EvidenceDownloadError('interrupted');
          refreshed = true;
          opened.reader.dispose();
          opened = await this.reopen();
          continue;
        }
        let plain: Uint8Array;
        try {
          checkActive();
          try { plain = await opened.reader.openChunk(this.next, ciphertext); }
          catch { throw new EvidenceDownloadError('integrity'); }
        }
        finally { ciphertext.fill(0); }
        try { checkActive(); await this.sink.write(plain); } finally { plain.fill(0); }
        this.done += plain.length;
        this.next++;
        refreshed = false;
        report();
        checkActive();
      }
      checkActive();
      if (this.done !== opened.reader.size) throw new EvidenceDownloadError('integrity');
      await this.sink.close();
      checkActive();
      this.finished = true;
    } catch (error) {
      if (error instanceof EvidenceDownloadError && error.reason === 'integrity') await this.cancel();
      throw error;
    } finally { opened.reader.dispose(); }
  }

  /** Discards the partial file. */
  async cancel(): Promise<void> {
    if (this.finished || this.cancelled) return;
    this.cancelled = true;
    try { await this.sink.abort(); } catch { /* already gone */ }
  }

  private async reopen(): Promise<OpenedChunkedEvidence> {
    let opened: OpenedChunkedEvidence;
    try { opened = await this.open(); }
    catch (error) {
      if (error instanceof ChunkedObjectError) throw new EvidenceDownloadError('integrity');
      throw error;
    }
    if (this.digest !== null && opened.reader.digest !== this.digest) {
      opened.reader.dispose();
      await this.cancel();
      throw new EvidenceDownloadError('changed');
    }
    this.digest = opened.reader.digest;
    this.total = opened.reader.size;
    return opened;
  }

  private async fetch(opened: OpenedChunkedEvidence, position: number, checkActive: () => void): Promise<Uint8Array> {
    for (let waits = 0; ; waits++) {
      checkActive();
      try { return await opened.fetchChunk(position); }
      catch (error) {
        if (!(error instanceof ConfidentialRateLimitError) || waits >= RATE_WAITS) throw error;
        await this.wait(error.delayMs);
      }
    }
  }
}

/** Strict (canonical) base64 from a channel reply. */
export function decodeBase64Strict(value: unknown, maxBytes = 16 * 1024 * 1024): Uint8Array {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(maxBytes / 3) || value.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new ConfidentialUnavailableError();
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (base64(bytes) !== value) throw new ConfidentialUnavailableError();
  return bytes;
}
/** One chunk's ciphertext; the reader then checks its exact size and digest. */
export function decodeChunk(value: unknown): Uint8Array { return decodeBase64Strict(value, MAX_CHUNK_CIPHERTEXT_BYTES); }

/** The evidence name comes from another participant; it gets the same hardened
 * cleaning as every other confidential download (no hidden files, no trailing
 * dots or spaces, no Windows device names, no path segments). */
export function safeFileName(name: unknown): string {
  return safeDownloadName(name);
}

/** In-memory sink (browsers without a save-file picker). Parts are Blobs, which
 * the browser may keep on disk; the file is offered only after it is complete. */
export function memorySink(name: string): EvidenceSink {
  let parts: Blob[] = [];
  return {
    async write(bytes) { parts.push(new Blob([new Uint8Array(bytes)])); },
    async close() {
      const url = URL.createObjectURL(new Blob(parts, { type: OPAQUE_DOWNLOAD_TYPE }));
      parts = [];
      const link = document.createElement('a');
      link.href = url; link.download = safeFileName(name); link.rel = 'noopener';
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    },
    async abort() { parts = []; },
  };
}

type SaveFilePicker = (options: { suggestedName: string }) => Promise<{
  createWritable(): Promise<{ write(data: Uint8Array): Promise<void>; close(): Promise<void>; abort(): Promise<void> }>;
}>;

/** Must be called directly from the click handler (browsers require a user
 * gesture for the save dialog). Writes straight to disk where supported; the
 * browser only commits the file on `close`, so a failed or cancelled download
 * leaves nothing behind. Returns null if the person closed the dialog. */
export async function chooseEvidenceSink(name: string): Promise<EvidenceSink | null> {
  const picker = (globalThis as { showSaveFilePicker?: SaveFilePicker }).showSaveFilePicker;
  if (typeof picker !== 'function') return memorySink(name);
  let handle: Awaited<ReturnType<SaveFilePicker>>;
  try { handle = await picker({ suggestedName: safeFileName(name) }); }
  catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return null;
    return memorySink(name);
  }
  const writable = await handle.createWritable();
  return {
    async write(bytes) { await writable.write(new Uint8Array(bytes)); },
    async close() { await writable.close(); },
    async abort() { await writable.abort(); },
  };
}
