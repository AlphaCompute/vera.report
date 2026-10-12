/**
 * Static legacy-isolation proof for confidential cases. Confidential data lives
 * only in `confidential_*` collections of a separate database, reached only
 * through src/services/confidentialCaseStore.ts. No legacy reader, serializer,
 * export, dissemination path, worker, script or admin UI may name those
 * collections or load the confidential store.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const ROOT = path.resolve(__dirname, '../../..');
const SCANNED = ['src', 'lib', 'pages', 'components', 'hooks', 'scripts', 'integrations', 'enclave/src', 'middleware.ts'];
const CODE = /\.(ts|tsx|js|jsx|cjs|mjs)$/;

function files(entry: string): string[] {
  const full = path.join(ROOT, entry);
  let stats;
  try { stats = statSync(full); } catch { return []; }
  if (stats.isFile()) return CODE.test(entry) ? [entry] : [];
  return readdirSync(full).filter(name => name !== 'node_modules' && !name.startsWith('.'))
    .flatMap(name => files(path.join(entry, name)));
}
const sources = SCANNED.flatMap(files).map(file => ({ file: file.split(path.sep).join('/'), text: readFileSync(path.join(ROOT, file), 'utf8') }));

/** Confidential-feature admin screens for legal organization onboarding (roster only). */
const LEGAL_ONBOARDING_SCREENS = ['components/vera/admin/LegalOrganizationsView.tsx',
  'components/vera/admin/LegalOrganizationDetail.tsx', 'components/vera/admin/LegalOnboardingParts.tsx'];

test('the scan covers the legacy readers it is meant to prove', () => {
  const names = sources.map(source => source.file);
  for (const expected of ['src/api/whistleblower.ts', 'src/api/dissemination.ts', 'src/services/reportPersistence.ts',
    'src/services/dashboardReportsMapper.ts', 'components/vera/admin/ReportDetail.tsx', 'pages/api/admin/narrative/[trackingId].ts',
    'scripts/migrate-private-records.ts']) expect(names).toContain(expected);
  expect(names.length).toBeGreaterThan(200);
});

test('only the confidential store names confidential_* collections', () => {
  const store = sources.find(source => source.file === 'src/services/confidentialCaseStore.ts')!.text;
  const names = [...store.matchAll(/collection<[^>]*>\('(confidential_[a-z_]+)'\)/g)].map(match => match[1]);
  expect(names).toEqual(expect.arrayContaining(['confidential_cases', 'confidential_case_objects', 'confidential_access_requests',
    'confidential_messages', 'confidential_staged_objects']));
  for (const source of sources) {
    if (source.file === 'src/services/confidentialCaseStore.ts') continue;
    expect({ file: source.file, names: names.filter(name => source.text.includes(name)) }).toEqual({ file: source.file, names: [] });
    // No dynamic or prefixed access to the confidential namespace either.
    expect({ file: source.file, access: /collection\s*(<[^>]*>)?\s*\(\s*[`'"]confidential/.test(source.text) })
      .toEqual({ file: source.file, access: false });
  }
});

test('only the confidential service module loads the store or storage RPC, behind the flagged gates', () => {
  const importers = (module: string) => sources
    .filter(source => new RegExp(`from ['"][^'"]*${module}['"]|require\\(['"][^'"]*${module}['"]\\)`).test(source.text))
    .map(source => source.file).sort();
  // Plus the operator's DocumentDB probe, which only touches a throwaway database it creates and drops.
  expect(importers('confidentialCaseStore')).toEqual(['scripts/security/confidentialDocumentDbProbe.ts', 'src/api/confidentialService.ts']);
  expect(importers('confidentialStorageRpc')).toEqual(['src/api/confidentialService.ts']);
  expect(importers('confidentialAdminListings')).toEqual(['components/vera/admin/ConfidentialListingsView.tsx',
    'pages/api/admin/confidential/listings.ts', 'src/api/confidentialAdminListings.ts', 'src/api/confidentialService.ts']);
  // The service is created only by the legacy API's flagged block and by the
  // confidential-only process, which loads no legacy module.
  expect(importers('confidentialService')).toEqual(['src/api/server.ts', 'src/confidentialServer.ts']);

  const server = sources.find(source => source.file === 'src/api/server.ts')!.text.replace(/\r\n/g, '\n');
  const gate = server.indexOf('if (confidentialIntakeRequired() && confidentialServiceHostedHere()) {');
  expect(gate).toBeGreaterThan(0);
  const blockEnd = server.indexOf('\n}\n', gate);
  for (const mount of ['createConfidentialService(', 'service.mount(app)']) {
    const at = server.indexOf(mount);
    expect(at).toBeGreaterThan(gate);
    expect(at).toBeLessThan(blockEnd);
    expect(server.indexOf(mount, at + 1)).toBe(-1);
  }

  const service = sources.find(source => source.file === 'src/api/confidentialService.ts')!.text.replace(/\r\n/g, '\n');
  // Frontend-only or mismatched mode mounts routes that deny, but cannot open any store.
  const enabledCheck = service.indexOf("env.CONFIDENTIAL_CASES_ENABLED !== 'true'");
  expect(enabledCheck).toBeGreaterThan(0);
  expect(enabledCheck).toBeLessThan(service.indexOf('MongoConfidentialCaseStore.connect('));
  expect(service.slice(enabledCheck, service.indexOf('MongoConfidentialCaseStore.connect('))).toContain("throw new Error('Confidential frontend/backend configuration mismatch')");
  for (const mount of ['MongoConfidentialCaseStore.connect(', 'createConfidentialAdminListingRouter(', 'createConfidentialLegalOnboardingRouter(',
    'createConfidentialObjectRouter(', 'createConfidentialChannelRouter(', 'createConfidentialStorageServer(']) {
    const at = service.indexOf(mount);
    expect(at).toBeGreaterThan(0);
    expect(service.indexOf(mount, at + 1)).toBe(-1);
  }
  // Separate database from the legacy report store, enforced at startup.
  expect(service).toMatch(/CONFIDENTIAL_MONGODB_DB_NAME \|\| 'vera_confidential'/);
  expect(service).toMatch(/must differ from the legacy MONGODB_DB_NAME/);
});

test('legacy readers only import confidential identifier and intake rejection guards, never confidential data', () => {
  const legacy = sources.filter(source =>
    /^src\/services\/(reportPersistence|dashboardReportsMapper|reportNarrative|privateRecord|rewardContact|submitterDisclosure|reporterAccess)\.ts$/.test(source.file) ||
    /^src\/services\/dissemination\//.test(source.file) ||
    // This isolated onboarding signer is part of the confidential subsystem,
    // not a legacy delivery worker. It still cannot import the case store.
    (/Worker\.ts$/.test(source.file) && source.file !== 'scripts/lib/combinedApprovalWorker.ts') ||
    /^src\/api\/(dissemination|audit|whistleblower)\.ts$/.test(source.file) ||
    /^pages\/api\/(whistleblower|dissemination)\//.test(source.file) ||
    (/^pages\/api\/admin\//.test(source.file) && !source.file.startsWith('pages/api/admin/confidential/')) ||
    (/^components\/vera\/admin\//.test(source.file) && !source.file.endsWith('ConfidentialListingsView.tsx') &&
      !LEGAL_ONBOARDING_SCREENS.includes(source.file)));
  expect(legacy.length).toBeGreaterThan(30);
  for (const source of legacy) {
    const imports = [...source.text.matchAll(/from ['"]([^'"]+)['"]/g)].map(match => match[1]);
    const confidential = imports.filter(value => /confidential|enclave\//i.test(value) &&
      !/utils\/confidentialIdentifiers$/.test(value) &&
      // The intake gate rejects plaintext before parsing; it cannot read cases.
      !(source.file === 'src/api/whistleblower.ts' && value === '../middleware/confidentialIntakeOnly'));
    expect({ file: source.file, confidential }).toEqual({ file: source.file, confidential: [] });
  }
});


test('the permitted intake rejection guard has no runtime dependencies or request reads', () => {
  const guard = sources.find(source => source.file === 'src/middleware/confidentialIntakeOnly.ts')!;
  const tree = ts.createSourceFile(guard.file, guard.text, ts.ScriptTarget.Latest, true);
  const runtimeImports: string[] = [];
  let checkedHandler = false;
  function inspect(node: ts.Node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'confidentialIntakeOnly') {
      expect(node.initializer && ts.isArrowFunction(node.initializer)).toBe(true);
      const handler = node.initializer as ts.ArrowFunction;
      const request = handler.parameters[0].name;
      expect(ts.isIdentifier(request)).toBe(true);
      const requestName = (request as ts.Identifier).text;
      const requestReads: string[] = [];
      function scanBody(child: ts.Node) {
        if (ts.isIdentifier(child) && child.text === requestName) requestReads.push(child.getText(tree));
        ts.forEachChild(child, scanBody);
      }
      scanBody(handler.body);
      expect(requestReads).toEqual([]);
      checkedHandler = true;
    }
    if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) runtimeImports.push(node.getText(tree));
    if (ts.isExportDeclaration(node) && node.moduleSpecifier && !node.isTypeOnly) runtimeImports.push(node.getText(tree));
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        ts.isIdentifier(node.expression) && node.expression.text === 'require')) runtimeImports.push(node.getText(tree));
    ts.forEachChild(node, inspect);
  }
  inspect(tree);
  expect(checkedHandler).toBe(true);
  expect(runtimeImports).toEqual([]);
});

test('legal organization onboarding surfaces never load case data, keys or the store', () => {
  const surfaces = [...LEGAL_ONBOARDING_SCREENS, 'lib/legalOnboardingClient.ts', 'src/utils/legalOnboarding.ts',
    'src/api/confidentialLegalOnboarding.ts', 'pages/api/admin/confidential/legal/[...path].ts'];
  for (const file of surfaces) {
    const source = sources.find(item => item.file === file);
    expect(source).toBeDefined();
    const imports = [...source!.text.matchAll(/(?:from\s+|import\()['"]([^'"]+)['"]/g)].map(match => match[1]);
    // Allowed confidential imports: the onboarding sign-in configuration (screens),
    // the public key-continuity verifier with its key parser (key replacement check), and
    // the public firm-key submission verifier and the private-page headers.
    // Nothing that opens a case.
    const reaching = imports.filter(value => /confidential|enclave\//i.test(value) &&
      !['@/lib/confidential/onboardingAuth', '@/enclave/src/confidential/firmKeyBinding',
        '@/lib/confidential/strictPageHeaders', '@/enclave/src/confidential/firmMembers',
        '@/enclave/src/confidential/pgp'].includes(value));
    expect({ file, reaching }).toEqual({ file, reaching: [] });
    expect({ file, names: /confidential_(cases|case_objects|access_requests|messages)/.test(source!.text) }).toEqual({ file, names: false });
  }
  // The router is mounted only by the confidential service (flagged legacy block or confidential-only process).
  expect(sources.filter(item => /from ['"][^'"]*confidentialLegalOnboarding['"]/.test(item.text)).map(item => item.file))
    .toEqual(['src/api/confidentialService.ts']);
});
