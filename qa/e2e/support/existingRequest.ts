import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { stackState } from './state';
import type { seedExistingRequest } from './existingRequestClient';

let compiled: Promise<typeof seedExistingRequest> | undefined;

/** Compile the real client with the local stack's synthetic Nitro root, exactly
 * as browser.ts does for the browser. Signature, nonce, PCR and key binding
 * verification remain enabled. No production source or trust setting changes. */
export function existingRequestClient(): Promise<typeof seedExistingRequest> {
  return compiled ??= compileClient();
}

async function compileClient(): Promise<typeof seedExistingRequest> {
  const root = resolve(__dirname, '../../..'), work = mkdtempSync(join(tmpdir(), 'vera-existing-request-'));
  const state = stackState();
  try {
    const loader = join(work, 'loader.cjs');
    writeFileSync(loader, `const ts = require(${JSON.stringify(require.resolve('typescript'))});
module.exports = function(source) {
  if (this.resourcePath.endsWith('/confidential/attestation.ts')) {
    if (!source.includes('const ROOT = ') || !source.includes('const ROOT_SHA256 = ')) throw new Error('Synthetic root replacement no longer matches');
    source = source.replace(/const ROOT = '[^']+';/, 'const ROOT = ' + ${JSON.stringify(JSON.stringify(state.attestationRoot))} + ';')
      .replace(/const ROOT_SHA256 = '[^']+';/, 'const ROOT_SHA256 = ' + ${JSON.stringify(JSON.stringify(state.attestationRootSha256))} + ';');
  }
  return ts.transpileModule(source, { fileName: this.resourcePath, compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true
  }}).outputText;
};`);
    const { webpack } = require('next/dist/compiled/webpack/webpack');
    await new Promise<void>((done, fail) => {
      const compiler = webpack({ mode: 'development', devtool: false, target: 'node',
        entry: join(__dirname, 'existingRequestClient.ts'), output: { path: work, filename: 'client.cjs', library: { type: 'commonjs2' } },
        resolve: { extensions: ['.ts', '.js', '.json'], alias: { '@': root } },
        externals: [({ request }: { request: string }, callback: (error?: Error | null, result?: string) => void) => {
          if (request.startsWith('.') || request.startsWith('/') || request.startsWith('@/')) return callback();
          try { callback(null, `commonjs ${require.resolve(request, { paths: [root] })}`); } catch (error) { callback(error as Error); }
        }],
        module: { rules: [{ test: /\.ts$/, exclude: /node_modules/, loader }] },
      });
      compiler.run((error: Error | null, stats: any) => compiler.close((closeError: Error | null) => {
        if (error || closeError) fail(error ?? closeError);
        else if (stats.hasErrors()) fail(new Error(stats.toString({ all: false, errors: true })));
        else done();
      }));
    });
    const file = join(work, 'client.cjs');
    // All fixture keys are passed in memory after compilation, never embedded.
    if (!readFileSync(file, 'utf8').includes(state.attestationRootSha256)) throw new Error('Synthetic root was not bundled');
    return require(file).seedExistingRequest;
  } finally { rmSync(work, { recursive: true, force: true }); }
}
