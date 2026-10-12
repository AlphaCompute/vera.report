import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { mediaScratchRoot } from './mediaMetadata';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { PDFDocument, PDFName } from 'pdf-lib';

const run = promisify(execFile);
const MAX_BYTES = 10 * 1024 * 1024;
const MAX_PAGES = 10;
// Linux production containers enforce child-process CPU, address-space and
// output limits. These complement timeouts; they are not a parser sandbox.
async function renderCommand(command: string, args: string[], options: Parameters<typeof run>[2]) {
  if (process.platform === 'linux') {
    return run('prlimit', ['--as=536870912', '--cpu=15', '--fsize=20971520', '--nofile=64', '--', command, ...args], options);
  }
  return run(command, args, options);
}
let busy = false;

/** Reconstruct visible content; never copy source objects or metadata into output.
 * PDF text, links, forms, signatures and attachments are intentionally flattened.
 * Visible names, faces and document content remain identifying information.
 */
export async function sanitizeDocument(input: Buffer, type: 'application/pdf'): Promise<Buffer> {
  if (input.length === 0 || input.length > MAX_BYTES) throw new Error('Document size exceeds sanitization limit');
  if (busy) throw new Error('Document sanitizer busy; retry later');
  busy = true;
  let directory: string | undefined;
  try {
    if (!input.subarray(0, 5).equals(Buffer.from('%PDF-'))) throw new Error('Invalid PDF signature');
    directory = await mkdtemp(join(await mediaScratchRoot(), 'vera-sanitize-'));
    const source = join(directory, 'source.pdf');
    await writeFile(source, input, { mode: 0o600 });
    const deadline = Date.now() + 30_000;
    const options = { timeout: 30_000, maxBuffer: 64 * 1024, env: { PATH: process.env.PATH, LANG: 'C', HOME: directory, NODE_ENV: 'production' as const } };
    const command = (name: string, args: string[]) => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('Document processing deadline exceeded');
      return renderCommand(name, args, { ...options, timeout: remaining, killSignal: 'SIGKILL' });
    };
    const { stdout } = await command('pdfinfo', [source]);
    const pages = Number(/^Pages:\s+(\d+)$/m.exec(stdout.toString())?.[1]);
    if (!Number.isInteger(pages) || pages < 1 || pages > MAX_PAGES || /^Encrypted:\s+yes/m.test(stdout.toString())) {
      throw new Error('PDF must be unencrypted and contain 1–10 pages');
    }
    const output = await PDFDocument.create();
    for (let page = 1; page <= pages; page++) {
      // One page at a time bounds temporary storage; no shell or source filenames in arguments.
      const prefix = join(directory, 'page');
      await command('pdftoppm', ['-f', String(page), '-l', String(page), '-singlefile', '-scale-to', '2048', '-png', source, prefix]);
      const png = await readFile(`${prefix}.png`);
      if (png.length > MAX_BYTES) throw new Error('Rendered page exceeds size limit');
      const image = await output.embedPng(png);
      const target = output.addPage([image.width, image.height]);
      target.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height });
    }
    // pdf-lib otherwise adds local creation/modification timestamps and producer fields.
    output.context.trailerInfo.Info = undefined;
    output.catalog.delete(PDFName.of('Metadata'));
    const bytes = Buffer.from(await output.save());
    if (bytes.length > MAX_BYTES) throw new Error('Sanitized document exceeds size limit');
    return bytes;
  } catch {
    // Native parser diagnostics can include document content; never propagate them.
    throw new Error('Document could not be safely sanitized');
  } finally {
    try {
      if (directory) await rm(directory, { recursive: true, force: true });
    } finally { busy = false; }
  }
}
