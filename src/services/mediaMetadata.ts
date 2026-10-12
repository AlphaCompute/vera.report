import { MAX_MEDIA_BYTES, MAX_STORED_EVIDENCE_BYTES } from '../utils/evidenceLimits';
import { EvidenceValidationError } from '../utils/evidenceValidationError';
import { MEDIA_FORMATS as formats } from '../utils/mediaFormats';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, statfs, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
let active = false;

// Linux containers provide a task-local /dev/shm tmpfs, separate from the
// production /tmp host mount. Never fall back to disk in production.
export async function mediaScratchRoot(): Promise<string> {
  if (process.platform === 'linux') {
    const filesystem = await statfs('/dev/shm');
    if (filesystem.type !== 0x01021994) throw new Error('Media scratch must be tmpfs');
    return '/dev/shm';
  }
  if (process.env.NODE_ENV === 'production') throw new Error('Media scratch requires Linux tmpfs');
  return tmpdir(); // Synthetic local development fixtures only.
}

export function isSupportedMedia(type: string): boolean {
  return Object.prototype.hasOwnProperty.call(formats, type);
}

/** Kill the whole parser process group on timeout, overflow, or pipe failure. */
function runMemoryMedia(content: Buffer, args: string[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [path.resolve(__dirname, '../../scripts/media-memfd.py'),
      String(MAX_MEDIA_BYTES), String(MAX_STORED_EVIDENCE_BYTES), ...args], {
      detached: true, stdio: ['pipe', 'pipe', 'ignore'],
      env: { PATH: process.env.PATH, LANG: 'C', NODE_ENV: 'production' },
    });
    let chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    const fail = () => {
      failed = true; chunks = [];
      try { if (child.pid) process.kill(-child.pid, 'SIGKILL'); } catch { /* already exited */ }
    };
    const timeout = setTimeout(fail, 90_000);
    child.stdin.on('error', fail);
    child.stdout.on('error', fail);
    child.on('error', fail);
    child.stdout.on('data', (chunk: Buffer) => {
      if (failed) return;
      size += chunk.length;
      if (size > MAX_STORED_EVIDENCE_BYTES) { fail(); return; }
      chunks.push(chunk);
    });
    child.on('close', code => {
      clearTimeout(timeout);
      if (!failed && code === 2) reject(new EvidenceValidationError('media'));
      else if (failed || code !== 0 || !size) reject(new Error('Media worker failed'));
      else resolve(Buffer.concat(chunks, size));
    });
    child.stdin.end(content);
  });
}

/** Remux AV streams without transcoding. Container/stream tags, chapters,
 * embedded artwork and non-AV data streams are not carried into the output.
 * The file contents themselves can still identify a reporter. */
export async function stripMediaMetadata(content: Buffer, type: string): Promise<Buffer> {
  if (!isSupportedMedia(type)) throw new EvidenceValidationError('media');
  if (content.length === 0 || content.length > MAX_MEDIA_BYTES) throw new EvidenceValidationError('media');
  const format = formats[type];
  // One parser per process; the upload/download admission gate also bounds buffers.
  if (active) throw new Error('Media sanitizer is busy. Please retry.');
  active = true;
  let directory: string | undefined;
  try {
    if (process.platform !== 'linux') directory = await mkdtemp(path.join(await mediaScratchRoot(), 'vera-media-'));
    const input = directory ? path.join(directory, 'input') : '@INPUT@';
    const output = directory ? path.join(directory, 'output') : '@OUTPUT@';
    if (directory) await writeFile(input, content, { mode: 0o600 });
    const args = [
      '-nostdin', '-hide_banner', '-loglevel', 'error', '-y', '-xerror',
      '-max_alloc', String(64 * 1024 * 1024),
      '-protocol_whitelist', 'file,pipe', '-f', format.input,
      // Explicit demuxers prevent an uploaded playlist from fetching URLs.
      ...(format.input === 'mov' ? ['-enable_drefs', '0', '-use_absolute_path', '0'] : []),
      '-i', input,
      ...(format.video ? ['-map', '0:V', '-map', '0:a?'] : ['-map', '0:a']),
      '-map_metadata', '-1', '-map_metadata:s', '-1', '-map_chapters', '-1',
      '-c', 'copy', '-fflags', '+bitexact', '-fs', String(MAX_STORED_EVIDENCE_BYTES + 1), '-f', format.output, output,
    ];
    if (process.platform === 'linux') return await runMemoryMedia(content, args);
    await run('ffmpeg', args, {
      timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH, LANG: 'C', HOME: directory, NODE_ENV: 'production' },
    });
    const size = (await stat(output)).size;
    if (!size || size > MAX_STORED_EVIDENCE_BYTES) throw new EvidenceValidationError('media');
    return await readFile(output);
  } catch (error) {
    if (error instanceof EvidenceValidationError) throw error;
    // Older FFmpeg uses 1; newer releases expose AVERROR_INVALIDDATA/EOF/EINVAL.
    // Include the POSIX low byte and signed/unsigned Windows process statuses.
    // ENOENT,
    // signals, timeouts and scratch-storage failures remain service errors.
    const failure = error as { code?: string | number; killed?: boolean; signal?: string };
    if ([1, 183, 187, 234, -1094995529, -541478725, -22, 3199971767, 3753488571, 4294967274].includes(failure.code as number) &&
        !failure.killed && !failure.signal) throw new EvidenceValidationError('media');
    // Never persist the original when sanitization fails or expose tool stderr,
    // which can contain metadata or local paths supplied by the reporter.
    throw new Error('Unable to sanitize this media file. No original media was accepted.');
  } finally {
    try { if (directory) await rm(directory, { recursive: true, force: true }); }
    finally { active = false; }
  }
}
