import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { EvidenceValidationError } from '../utils/evidenceValidationError';

let busy = false;

const ERROR = 'Unable to sanitize this PDF without changing unsupported document features. Signed files, attachments and active content are not accepted. No original file was accepted.';

/** Preserve the PDF page/object structure while removing document properties,
 * XMP and application-private editing metadata. Isolate untrusted parsing from
 * the API event loop with a memory limit and an enforced deadline. */
export async function stripPdfMetadata(input: Buffer): Promise<Buffer> {
  if (!input.length || input.length > 10 * 1024 * 1024) throw new EvidenceValidationError('PDF', ERROR);
  if (busy) throw new Error('PDF sanitizer busy; retry later');
  busy = true;
  try {
    return await new Promise<Buffer>((resolve, reject) => {
      const worker = new Worker(path.join(__dirname, 'pdfMetadataBootstrap.cjs'), {
        workerData: input,
        env: { NODE_ENV: process.env.NODE_ENV || 'production', PATH: process.env.PATH || '' },
      resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 8 },
        stdout: true, stderr: true,
      });
      // Parser warnings may include file-controlled content; do not forward them.
      worker.stdout?.resume(); worker.stderr?.resume();
      let settled = false;
      const finish = (data?: Uint8Array, invalidFile = false) => {
        if (settled) return;
        settled = true; clearTimeout(deadline);
        // Keep the slot until the old worker has actually released its resources.
        void worker.terminate().then(() => {
          if (data?.length) resolve(Buffer.from(data));
          else reject(invalidFile ? new EvidenceValidationError('PDF', ERROR) : new Error(ERROR));
        }, () => reject(new Error(ERROR)));
      };
      const deadline = setTimeout(() => finish(), 15_000);
      worker.once('message', message => finish(message?.ok && message.data instanceof Uint8Array ? message.data : undefined, message?.ok === false));
      worker.once('error', () => finish());
      worker.once('exit', () => finish());
    });
  } finally { busy = false; }
}
