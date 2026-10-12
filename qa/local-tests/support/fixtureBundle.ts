import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

/** Bundles a real component for a browser fixture.
 *
 * Imports resolve the way Next resolves them: `@/…` maps to the repository root
 * and relative imports are followed, with TypeScript transpiled on the way. So a
 * component that gains an import keeps building without anyone editing a
 * hand-maintained alias list. Only modules named in `stubs` are replaced: every
 * stub is keyed by its repository path (or a bare package name such as
 * `next/link`), must exist, and must actually be reached by the bundle.
 *
 * Guards (each fails with a message naming the fix):
 * - an import that cannot be resolved,
 * - a stub whose path no longer exists or is no longer imported (stale fixture),
 * - a module that performs network or identity I/O reached without a stub, so a
 *   fixture never silently talks to a real service. */
export const REPO_ROOT = resolve(__dirname, '../../..');
// Fixture keys and the network inventory use repository paths on every host.
const repoPath = (file: string) => relative(REPO_ROOT, file).split(sep).join('/');

/** Modules that send requests or talk to the identity provider. A fixture that
 * reaches one must stub it (or a module in front of it). */
export const NETWORK_MODULES = [
  'lib/confidential/client.ts',
  'lib/confidential/evidenceTransfer.ts',
  'lib/confidential/firmMemberDevices.ts',
  'lib/confidential/legalAuth.ts',
  'lib/confidential/identityToken.ts',
  'lib/confidential/firmOnboarding.ts',
  'lib/confidential/onboarding.ts',
  'lib/confidential/onboardingAuth.ts',
  'lib/confidential/ownerCase.ts',
  'lib/confidential/releaseWithdrawals.ts',
  'lib/auth0Management.ts',
  'lib/auditClient.ts',
  'lib/confidentialAdminListings.ts',
  'lib/legalOnboardingClient.ts',
];

export interface FixtureBundleOptions {
  /** Repository path of the module under test. */
  entry: string;
  /** CommonJS code appended after `const subject = require(<entry>)`. */
  render: string;
  /** Repository path (e.g. `lib/confidential/firmCase.ts`) or package name -> CommonJS source. */
  stubs: Record<string, string>;
  /** Module-private names of the entry to export for the fixture (e.g. an unexported page section). */
  expose?: string[];
  /** Public build settings, inlined as Next inlines NEXT_PUBLIC_* values. */
  env?: Record<string, string>;
}

const isPackage = (key: string) => !key.startsWith('.') && !key.startsWith('/') && !/\.(tsx?|jsx?)$/.test(key);

export async function bundleFixture({ entry, render, stubs, expose = [], env = { NEXT_PUBLIC_CONFIDENTIAL_CASES: '1' } }: FixtureBundleOptions): Promise<string> {
  // Real path: webpack reports resolved (symlink-free) module paths.
  const temporary = realpathSync(mkdtempSync(join(tmpdir(), 'vera-fixture-')));
  try {
    const typescript = require.resolve('typescript', { paths: [REPO_ROOT, __dirname] });
    const loader = join(temporary, 'ts-loader.js');
    writeFileSync(loader, `const ts = require(${JSON.stringify(typescript)});
const { expose } = ${JSON.stringify({ expose: { [resolve(REPO_ROOT, entry)]: expose } })};
module.exports = function (source) {
  const names = expose[this.resourcePath] || [];
  if (names.length) source += '\\nexport { ' + names.join(', ') + ' };';
  return ts.transpileModule(source, { fileName: this.resourcePath, compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX,
    esModuleInterop: true, isolatedModules: true } }).outputText;
};`);

    const stubFiles = new Map<string, string>();
    const packageStubs: Record<string, string> = {};
    const unusedStubs = new Set(Object.keys(stubs));
    Object.entries(stubs).forEach(([key, content], index) => {
      const file = join(temporary, `stub-${index}.js`);
      writeFileSync(file, `/* fixture stub for ${key} */\n${content}`);
      if (isPackage(key)) { packageStubs[`${key}$`] = file; return; }
      const source = resolve(REPO_ROOT, key);
      if (!existsSync(source)) throw new Error(`Fixture stub '${key}' does not exist in the repository. Remove it or update its path.`);
      stubFiles.set(source, file);
    });
    const stubKey = new Map<string, string>([...stubFiles].map(([source, file]) => [file, repoPath(source)]));
    Object.entries(packageStubs).forEach(([alias, file]) => stubKey.set(file, alias.slice(0, -1)));

    const entryFile = join(temporary, 'entry.js');
    writeFileSync(entryFile, `const subject = require(${JSON.stringify(resolve(REPO_ROOT, entry))});\n${render}\n`);
    // These fixtures test component behavior, not Next's CSS pipeline. Keep
    // module class names usable without suppressing any JavaScript I/O imports.
    const cssLoader = join(temporary, 'css-loader.js');
    writeFileSync(cssLoader, `module.exports = () => 'module.exports = new Proxy({}, { get: (_, name) => typeof name === "string" ? name : undefined });';`);

    const { webpack } = require('next/dist/compiled/webpack/webpack');
    const stubPlugin = {
      apply(compiler: any) {
        compiler.hooks.normalModuleFactory.tap('FixtureStubs', (factory: any) => {
          factory.hooks.afterResolve.tap('FixtureStubs', (data: any) => {
            const resource: string = data.createData.resource ?? '';
            const stub = stubFiles.get(resource.split('?')[0]);
            if (!stub) return;
            data.createData.resource = stub;
            data.createData.request = stub;
            data.createData.userRequest = stub;
            data.createData.loaders = [];
          });
        });
      },
    };
    const stats: any = await new Promise((done, reject) => {
      const compiler = webpack({
        mode: 'development', devtool: false, target: 'web', entry: entryFile,
        output: { path: temporary, filename: 'bundle.js' },
        resolve: {
          extensions: ['.tsx', '.ts', '.jsx', '.js', '.json'],
          alias: { ...packageStubs, '@': REPO_ROOT },
          modules: [join(REPO_ROOT, 'node_modules')],
        },
        module: { rules: [{ test: /\.(tsx?|jsx?)$/, exclude: /node_modules/, loader },
          { test: /\.module\.css$/, loader: cssLoader }] },
        plugins: [stubPlugin, new webpack.DefinePlugin({
          'process.env': JSON.stringify({ NODE_ENV: 'development', ...env }),
        })],
      });
      compiler.run((error: Error | null, result: any) => compiler.close((closeError: Error | null) => {
        if (error || closeError) reject(error ?? closeError); else done(result);
      }));
    });

    const errors: any[] = stats.compilation.errors;
    if (errors.length) {
      const unresolved = errors.filter(error => error.name === 'ModuleNotFoundError').map(error => {
        const from = error.module?.resource ? repoPath(error.module.resource) : 'the fixture entry';
        const request = /Can't resolve '([^']+)'/.exec(String(error.message))?.[1] ?? String(error.message);
        return `  '${request}' imported by ${from}`;
      });
      if (unresolved.length) {
        throw new Error(`Fixture bundle for ${entry} has unmapped imports:\n${unresolved.join('\n')}\n`
          + 'Fix the import path, or add a stub keyed by the repository path if the module does I/O.');
      }
      throw new Error(stats.toString({ all: false, errors: true }));
    }

    const graph = stats.compilation.moduleGraph;
    const chain = (module: any) => {
      const path: string[] = [];
      for (let at = module; at?.resource?.startsWith(REPO_ROOT) && path.length < 12; at = graph.getIssuer(at)) path.push(repoPath(at.resource));
      return path.reverse().join(' -> ');
    };
    const bundled: { path: string; via: string }[] = [];
    for (const module of stats.compilation.modules) {
      const resource: string | undefined = module.resource;
      if (!resource) continue;
      const key = stubKey.get(resource);
      if (key) { unusedStubs.delete(key); continue; }
      if (isAbsolute(resource) && !resource.includes('node_modules')) bundled.push({ path: repoPath(resource), via: chain(module) });
    }
    if (unusedStubs.size) {
      throw new Error(`Fixture bundle for ${entry} never imports these stubbed modules: ${[...unusedStubs].join(', ')}. `
        + 'Remove the stale stubs so the fixture reflects what the component really uses.');
    }
    const reached = bundled.filter(({ path }) => NETWORK_MODULES.includes(path));
    if (reached.length) {
      throw new Error(`Fixture bundle for ${entry} reaches network modules without a stub:\n${reached.map(({ via }) => `  ${via}`).join('\n')}\n`
        + 'Stub them (or the module that imports them) so the fixture stays offline.');
    }
    return readFileSync(join(temporary, 'bundle.js'), 'utf8');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export const FIXTURE_ORIGIN = 'http://localhost:9';

/** Opens an empty page with a `#root` element on a secure origin (WebCrypto and
 * other secure-context APIs behave as on the real site) without any server.
 * Every other request is refused and recorded: a fixture must never reach a
 * real service. Returns the list of refused URLs so a test can assert on it. */
export async function openFixturePage(page: import('@playwright/test').Page): Promise<string[]> {
  const refused: string[] = [];
  await page.route('**/*', route => {
    const url = route.request().url();
    if (url === `${FIXTURE_ORIGIN}/fixture`) {
      return route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body><div id="root"></div></body></html>' });
    }
    refused.push(url);
    return route.abort('blockedbyclient');
  });
  await page.goto(`${FIXTURE_ORIGIN}/fixture`);
  return refused;
}
