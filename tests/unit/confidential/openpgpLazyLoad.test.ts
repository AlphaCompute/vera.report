import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import ts from 'typescript';

// openpgp (~395 KB minified) must load on first cryptographic use, not with the
// reporter pages. Walk the static, value (non-type) import graph from each page;
// `import()` expressions are not followed, which is the point.
const root = resolve(__dirname, '../../..');

function resolveSpecifier(from: string, specifier: string): string | null {
  if (!specifier.startsWith('@/') && !specifier.startsWith('.')) return specifier.split('/').slice(0, specifier.startsWith('@') ? 2 : 1).join('/');
  const base = (specifier.startsWith('@/') ? join(root, specifier.slice(2)) : resolve(dirname(from), specifier)).replace(/\.js$/, '');
  for (const extension of ['', '.ts', '.tsx', '.js', '/index.ts', '/index.tsx']) {
    if (existsSync(base + extension) && statSync(base + extension).isFile()) return base + extension;
  }
  return null;
}

function valueImports(file: string): string[] {
  const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true,
    file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  return source.statements.flatMap(statement => {
    if (ts.isImportDeclaration(statement)) {
      const clause = statement.importClause;
      if (clause?.isTypeOnly) return [];
      if (clause && !clause.name && clause.namedBindings && ts.isNamedImports(clause.namedBindings) &&
          clause.namedBindings.elements.length && clause.namedBindings.elements.every(element => element.isTypeOnly)) return [];
      return [(statement.moduleSpecifier as ts.StringLiteral).text];
    }
    if (ts.isExportDeclaration(statement) && statement.moduleSpecifier && !statement.isTypeOnly) return [(statement.moduleSpecifier as ts.StringLiteral).text];
    return [];
  });
}

function staticPathTo(entry: string, target: string): string[] | null {
  const start = resolve(root, entry), parent = new Map<string, string | null>([[start, null]]), queue = [start];
  while (queue.length) {
    const file = queue.shift()!;
    for (const specifier of valueImports(file)) {
      const next = resolveSpecifier(file, specifier);
      if (next === target) {
        const chain = [target];
        for (let at: string | null = file; at; at = parent.get(at) ?? null) chain.unshift(relative(root, at));
        return chain;
      }
      if (!next || !isAbsolute(next) || parent.has(next)) continue;
      parent.set(next, file); queue.push(next);
    }
  }
  return null;
}

test.each(['pages/report.tsx', 'pages/status.tsx'])('%s does not bundle openpgp statically', page => {
  expect(staticPathTo(page, 'openpgp')).toBeNull();
});

test('the walker does find a static openpgp import', () => {
  expect(staticPathTo('enclave/src/confidential/recovery.ts', 'openpgp')).not.toBeNull();
});
