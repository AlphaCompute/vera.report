const { test } = require('node:test');
const assert = require('node:assert/strict');
// Keep the runtime suite's build-freshness gate, including this browser probe.
require('../../scripts/security/enclave-dist-freshness.cjs').assertEnclaveDistFresh();
const { readFileSync } = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const loader = require('../../scripts/loaders/openpgp-browser-debug.cjs');
const root = path.resolve(__dirname, '../..');
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;

test('development envelope search stays quiet without weakening recipient, signature or case checks', async () => {
  const originalEnvironment = process.env.NODE_ENV;
  const originalError = console.error;
  process.env.NODE_ENV = 'development';
  const errors = [];
  console.error = (...args) => { errors.push(args[0]); };
  try {
    // Exercise the installed browser build, not its separate Node export.
    const resourcePath = path.join(root, 'node_modules/openpgp/dist/openpgp.mjs');
    const source = readFileSync(resourcePath, 'utf8');
    const transpile = name => ts.transpileModule(readFileSync(path.join(root, `enclave/src/confidential/${name}.ts`), 'utf8'), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    }).outputText;
    const caseSource = transpile('caseStateKey').replace("'./base64.ts'", JSON.stringify(moduleURL(transpile('base64'))));
    const id = '1'.repeat(64);
    const minPath = path.join(root, 'node_modules/openpgp/dist/openpgp.min.mjs');
    const minSource = readFileSync(minPath, 'utf8');
    for (const [patched, input, filename] of [[false, source, resourcePath], [true, source, resourcePath], [true, minSource, minPath]]) {
      errors.length = 0;
      const pgpURL = moduleURL(patched ? loader.call({ resourcePath: filename }, input) : input);
      const pgp = await import(pgpURL);
      const state = await import(moduleURL(caseSource.replace("'./pgp.ts'", JSON.stringify(pgpURL))));
      const [owner, firm, other] = await Promise.all(['owner', 'firm', 'other'].map(async name =>
        (await pgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey));
      const key = state.generateCaseStateKey();
      const envelope = await state.wrapCaseStateKey(id, key, firm.toPublic(), owner);
      const decoy = await state.wrapCaseStateKey(id, key, other.toPublic(), owner);
      assert.deepEqual((await state.findCaseStateKey([decoy, envelope], id, firm, owner.toPublic())).key, key.key);
      await assert.rejects(state.findCaseStateKey([decoy], id, firm, owner.toPublic()));
      await assert.rejects(state.unwrapCaseStateKey(envelope, '2'.repeat(64), firm, owner.toPublic()));
      const forged = await state.wrapCaseStateKey(id, key, firm.toPublic(), other);
      await assert.rejects(state.unwrapCaseStateKey(forged, id, firm, owner.toPublic()));
      if (patched) assert.equal(errors.length, 0, 'Expected decryption misses must not be logged as browser crashes');
      else assert.ok(errors.includes('[OpenPGP.js debug]'), 'Reproduce the upstream development-only console error');
    }
    assert.throws(() => loader.call({ resourcePath }, 'changed upstream source'));
    assert.throws(() => loader.call({ resourcePath: path.join(root, 'app.js') }, source));
  } finally {
    console.error = originalError;
    if (originalEnvironment === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnvironment;
  }
});
