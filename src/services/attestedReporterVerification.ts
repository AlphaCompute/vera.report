import { AttestedReportVerificationReader, type AttestedVerificationReaderOptions } from './attestedReportVerificationReader';
import { createAttestedEcsCredentials } from './attestedEcsCredentials';
import { REPORTER_CODE_PATTERN } from './reporterAccess';

const FAILURE = 'Report verification unavailable';
export interface ReporterVerificationStorage {
  resolveAttestedReporterTrackingId(code: string, signal: AbortSignal): Promise<string | null>;
  createReporterVerificationLoader(code: string): AttestedVerificationReaderOptions['loadAuthorized'];
}
type Reader = Pick<AttestedReportVerificationReader, 'read' | 'close'>;
type Settings = Omit<AttestedVerificationReaderOptions, 'loadAuthorized'>;
export class AttestedReporterVerification {
  private active?: Promise<{ credibilityScore: number; category: string } | null>;
  private controller?: AbortController;
  private closed = false;
  constructor(private readonly storage: ReporterVerificationStorage, private readonly settings: Settings,
    private readonly makeReader: (options: AttestedVerificationReaderOptions) => Reader = options => new AttestedReportVerificationReader(options)) {}

  read(code: string, signal: AbortSignal): Promise<{ credibilityScore: number; category: string } | null> {
    if (this.closed || this.active || signal.aborted || typeof code !== 'string' || !REPORTER_CODE_PATTERN.test(code)) return Promise.reject(new Error(FAILURE));
    const controller = new AbortController(); this.controller = controller;
    const abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 25_000);
    this.active = this.perform(code, controller.signal).catch(() => { throw new Error(FAILURE); }).finally(() => {
      clearTimeout(timer); signal.removeEventListener('abort', abort); this.controller = undefined; this.active = undefined;
    });
    return this.active;
  }

  private async perform(code: string, signal: AbortSignal) {
    const trackingId = await new Promise<string | null>((resolve, reject) => {
      const cancel = () => reject(new Error(FAILURE));
      signal.addEventListener('abort', cancel, { once: true });
      Promise.resolve().then(() => {
        signal.throwIfAborted(); return this.storage.resolveAttestedReporterTrackingId(code, signal);
      }).then(resolve, reject).finally(() => signal.removeEventListener('abort', cancel));
    });
    signal.throwIfAborted();
    if (!trackingId) return null;
    const reader = this.makeReader({ ...this.settings, loadAuthorized: this.storage.createReporterVerificationLoader(code) });
    // close() cancels AND drains the child. Keep global admission occupied until it completes.
    const abort = () => { void reader.close().catch(() => {}); };
    signal.addEventListener('abort', abort, { once: true });
    try {
      signal.throwIfAborted();
      const value = await reader.read(trackingId);
      signal.throwIfAborted();
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(FAILURE);
      const { credibilityScore, category } = value as Record<string, unknown>;
      if (typeof credibilityScore !== 'number' || !Number.isFinite(credibilityScore) || credibilityScore < 0 || credibilityScore > 100 ||
          typeof category !== 'string' || category.length > 128 || !/^[a-zA-Z0-9 _-]{1,128}$/.test(category)) throw new Error(FAILURE);
      return { credibilityScore, category };
    } finally { signal.removeEventListener('abort', abort); await reader.close(); }
  }

  async close(): Promise<void> {
    this.closed = true; this.controller?.abort(); await this.active?.catch(() => {});
  }
}

/** Only this separate read endpoint is affected. Hardware/config approval remains an operator gate. */
export function configuredAttestedReporterVerification(env: NodeJS.ProcessEnv, storage: ReporterVerificationStorage): AttestedReporterVerification | undefined {
  const enabled = env.ATTESTED_REPORTER_VERIFICATION_ENABLED;
  if (enabled === undefined || enabled === 'false') return undefined;
  if (enabled !== 'true') throw new Error(FAILURE);
  const port = env.ATTESTED_REPORTER_VERIFICATION_PORT;
  if (!port || !/^[0-9]{1,5}$/.test(port)) throw new Error(FAILURE);
  const settings: Settings = {
    pythonExecutable: '/opt/vera-attestation/venv/bin/python', moduleRoot: '/opt/vera-attestation', port: Number(port),
    keyArn: env.ATTESTED_REPORTER_VERIFICATION_KEY_ARN || '',
    pcrs: { '0': env.ATTESTED_REPORTER_VERIFICATION_PCR0 || '', '1': env.ATTESTED_REPORTER_VERIFICATION_PCR1 || '', '2': env.ATTESTED_REPORTER_VERIFICATION_PCR2 || '' },
    credentials: createAttestedEcsCredentials(env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || '', env.ATTESTED_REPORTER_VERIFICATION_TASK_ROLE_ARN || ''),
  };
  // Validate the exact packaged paths/key/pins/port eagerly, without reading data or fetching credentials.
  const validation = new AttestedReportVerificationReader({ ...settings, loadAuthorized: async () => null });
  void validation.close();
  return new AttestedReporterVerification(storage, settings);
}
