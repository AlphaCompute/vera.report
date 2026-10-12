import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { metadataExtractorService, type ExtractedMetadata } from './metadataExtractor';

if (!isMainThread) {
  metadataExtractorService.extractMetadata(Buffer.from(workerData.buffer), workerData.name, workerData.type)
    .then(result => parentPort!.postMessage(result))
    .catch(() => { throw new Error('Metadata extraction failed'); });
}
/** CPU parsing is isolated so malformed files cannot block HTTP deadlines. */
export function extractMetadataIsolated(buffer: Buffer, name: string, type: string, signal: AbortSignal): Promise<ExtractedMetadata> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new Error('Analysis cancelled')); return; }
    const worker = new Worker(__filename, {
      workerData: { buffer, name, type },
      execArgv: __filename.endsWith('.ts') ? ['-r', 'ts-node/register/transpile-only'] : [],
      env: { NODE_ENV: process.env.NODE_ENV || 'production', PATH: process.env.PATH || '' },
      resourceLimits: { maxOldGenerationSizeMb: 128 },
    });
    let settled = false;
    const finish = (error?: Error, result?: ExtractedMetadata) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); signal.removeEventListener('abort', cancel);
      void worker.terminate().then(() => error ? reject(error) : resolve(result!));
    };
    const cancel = () => finish(new Error('Analysis cancelled'));
    const timer = setTimeout(() => finish(new Error('Analysis time limit exceeded')), 10000);
    signal.addEventListener('abort', cancel, { once: true });
    worker.once('message', result => finish(undefined, result));
    worker.once('error', error => finish(error instanceof Error ? error : new Error('Analysis failed')));
    worker.once('exit', () => { if (!settled) finish(new Error('Analysis worker exited')); });
  });
}
