import { spawn } from 'node:child_process';
import path from 'node:path';

const FAILURE = 'Report verification reader unavailable';
const MAX_FIELD = 8 * 1024 * 1024;
const MAX_PIPE = 12 * 1024 * 1024;
const KEY_ARN = /^arn:aws:kms:us-east-2:000000000000:key\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export interface AttestedVerificationReaderOptions {
  /** Explicit pinned Python environment; no ambient interpreter or credential discovery. */
  pythonExecutable: string;
  /** Absolute packaged directory containing enclave/verification; never derived from bundled __dirname. */
  moduleRoot: string;
  port: number;
  keyArn: string;
  pcrs: { '0': string; '1': string; '2': string };
  /** Authenticate the caller and authorize this exact report before returning its raw encrypted field. */
  loadAuthorized: (trackingId: string, signal: AbortSignal) => Promise<{ trackingId: string; verification: unknown } | null>;
  credentials: (signal: AbortSignal) => Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: string }>;
}

function binary(value: unknown, max: number, exact = false): void {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3)) throw new Error(FAILURE);
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value || decoded.length > max || (exact && decoded.length !== max)) throw new Error(FAILURE);
}
function envelope(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('private:v1:') || Buffer.byteLength(value) > MAX_PIPE) throw new Error(FAILURE);
  const stored = JSON.parse(value.slice('private:v1:'.length));
  if (!stored || typeof stored !== 'object' || Array.isArray(stored) || Object.keys(stored).sort().join(',') !== 'data,iv,key,tag' ||
      typeof stored.key !== 'string' || !stored.key.startsWith('enc:kms:v2:') || stored.key === 'enc:kms:v2:') throw new Error(FAILURE);
  binary(stored.key.slice('enc:kms:v2:'.length), 6144);
  binary(stored.iv, 12, true); binary(stored.tag, 16, true); binary(stored.data, MAX_FIELD);
  return value;
}

/** Used by the separately gated reporter endpoint; deployment activation defaults to false.
 * One authorized report field only. No key-envelope unwrap, raw-key RPC or local crypto fallback exists here.
 */
export class AttestedReportVerificationReader {
  private readonly options: AttestedVerificationReaderOptions;
  private readonly abort = new AbortController();
  private pending?: Promise<unknown>;
  private closed = false;

  constructor(options: AttestedVerificationReaderOptions) {
    if (!path.isAbsolute(options.pythonExecutable) || !path.isAbsolute(options.moduleRoot) || !Number.isInteger(options.port) || options.port < 1 || options.port > 65535 ||
        !KEY_ARN.test(options.keyArn) || Object.keys(options.pcrs).sort().join(',') !== '0,1,2' ||
        Object.values(options.pcrs).some(value => typeof value !== 'string' || !/^[a-fA-F0-9]{96}$/.test(value) || /^0+$/.test(value)) ||
        typeof options.loadAuthorized !== 'function' || typeof options.credentials !== 'function') throw new Error(FAILURE);
    this.options = { ...options, pcrs: { ...options.pcrs } };
  }

  read(trackingId: string): Promise<unknown> {
    if (this.closed || this.pending || typeof trackingId !== 'string' || !/^VRA-[A-F0-9]{16}$/.test(trackingId)) return Promise.reject(new Error(FAILURE));
    const timer = setTimeout(() => { this.closed = true; this.abort.abort(); }, 60_000);
    const operation = this.readAuthorized(trackingId).catch(() => { throw new Error(FAILURE); })
      .finally(() => { clearTimeout(timer); this.pending = undefined; });
    this.pending = operation;
    return operation;
  }

  private untilCancelled<T>(work: () => Promise<T>): Promise<T> {
    const signal = this.abort.signal;
    if (signal.aborted) return Promise.reject(new Error(FAILURE));
    return new Promise<T>((resolve, reject) => {
      const cancel = () => reject(new Error(FAILURE));
      signal.addEventListener('abort', cancel, { once: true });
      let result: Promise<T>;
      try { result = work(); } catch (error) { signal.removeEventListener('abort', cancel); reject(error); return; }
      // Consume late outcomes without continuing the reader after cancellation.
      Promise.resolve(result).then(value => { signal.removeEventListener('abort', cancel); resolve(value); },
        error => { signal.removeEventListener('abort', cancel); reject(error); });
    });
  }

  private async readAuthorized(trackingId: string): Promise<unknown> {
    const report = await this.untilCancelled(() => this.options.loadAuthorized(trackingId, this.abort.signal));
    if (this.closed || !report || report.trackingId !== trackingId) throw new Error(FAILURE);
    const stored = envelope(report.verification);
    const supplied = await this.untilCancelled(() => this.options.credentials(this.abort.signal));
    const credentials = { accessKeyId: supplied.accessKeyId, secretAccessKey: supplied.secretAccessKey,
      sessionToken: supplied.sessionToken, expiration: supplied.expiration };
    if (this.closed || Object.values(credentials).some(value => typeof value !== 'string' || !value.length || value.length > 8192) ||
        !Number.isFinite(Date.parse(credentials.expiration)) || Date.parse(credentials.expiration) <= Date.now()) throw new Error(FAILURE);
    const input = Buffer.from(JSON.stringify({ trackingId, envelope: stored, port: this.options.port,
      keyArn: this.options.keyArn, pcrs: this.options.pcrs, credentials }));
    if (input.length > MAX_PIPE) { input.fill(0); throw new Error(FAILURE); }
    try { return await this.exchange(input); } finally { input.fill(0); }
  }

  private exchange(input: Buffer): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.options.pythonExecutable, ['-E', '-s', '-m', 'enclave.verification.read_report_verification'], {
        // Next augments ProcessEnv with NODE_ENV; this Python child deliberately receives neither it nor application secrets.
        cwd: this.options.moduleRoot, env: { PATH: '/usr/bin:/bin' } as unknown as NodeJS.ProcessEnv, stdio: ['pipe', 'pipe', 'pipe'],
      });
      const chunks: Buffer[] = [];
      let size = 0, failed = false;
      const stop = () => { failed = true; child.stdin.destroy(); child.kill('SIGKILL'); };
      this.abort.signal.addEventListener('abort', stop, { once: true });
      child.on('error', stop);
      child.stdin.on('error', stop);
      child.stdout.on('error', stop);
      child.stderr.on('error', stop);
      child.stderr.on('data', stop); // Unexpected diagnostics never leave this bridge.
      child.stdout.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (failed || size > MAX_PIPE) { chunk.fill(0); stop(); }
        else chunks.push(chunk);
      });
      child.once('close', code => {
        this.abort.signal.removeEventListener('abort', stop);
        const output = Buffer.concat(chunks);
        try {
          if (failed || this.closed || code !== 0) throw new Error(FAILURE);
          const result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(output));
          if (!result || Object.keys(result).join(',') !== 'value') throw new Error(FAILURE);
          resolve(result.value);
        } catch { reject(new Error(FAILURE)); }
        finally { output.fill(0); chunks.forEach(chunk => chunk.fill(0)); }
      });
      child.stdin.end(input);
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    this.abort.abort();
    await this.pending?.catch(() => {});
  }
}
