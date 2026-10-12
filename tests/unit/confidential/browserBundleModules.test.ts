import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { BROWSER_ENTRY_MODULES, collectBrowserModules, relativeImports } = require('../../../scripts/security/confidential-browser-modules.cjs');

const root = path.resolve(__dirname, '../../..');
const directory = path.join(root, 'enclave/src/confidential');

describe('browser/enclave interoperability bundle modules', () => {
  const modules: string[] = collectBrowserModules(directory);

  test('includes caseChunks, which ownerSubmission imports (regression: missing from a hard-coded list)', () => {
    expect(modules).toEqual(expect.arrayContaining(['ownerSubmission', 'caseChunks']));
  });

  test('is closed under relative imports after transpilation, as the browser verifier bundles it', () => {
    for (const name of modules) {
      const source = readFileSync(path.join(directory, `${name}.ts`), 'utf8');
      const output = ts.transpileModule(source, { compilerOptions: {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, rewriteRelativeImportExtensions: true,
      } }).outputText;
      for (const dependency of relativeImports(output, `${name}.js`)) expect(modules).toContain(dependency);
    }
  });

  test('entry modules come first and every module exists', () => {
    expect(modules.slice(0, BROWSER_ENTRY_MODULES.length)).toEqual([...BROWSER_ENTRY_MODULES]);
    const available = new Set(readdirSync(directory).filter(file => file.endsWith('.ts')).map(file => file.slice(0, -3)));
    for (const name of modules) expect(available.has(name)).toBe(true);
  });

  test('rejects imports that leave the confidential directory and unknown modules', () => {
    expect(() => relativeImports("import x from '../outside.ts';", 'x.ts')).toThrow('must stay in enclave/src/confidential');
    expect(() => collectBrowserModules(directory, ['doesNotExist'])).toThrow('Missing browser bundle module');
  });

  test('the browser verifier derives its module list instead of hard-coding it', () => {
    const verifier = readFileSync(path.join(root, 'scripts/security/verify-confidential-browser.cjs'), 'utf8');
    expect(verifier).toContain('collectBrowserModules(');
    expect(verifier).not.toMatch(/for \(const name of \[/);
  });
});
