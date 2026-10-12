// Guards suites that load compiled enclave code. enclave/dist is gitignored and
// nothing rebuilds it before `node --test` or jest, so a checkout or edit can
// leave it older than enclave/src and a local run would pass against stale code.
// Every source module must have a compiled file at least as new as the source
// and as the compiler configuration; otherwise the suite refuses to run.
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_ENCLAVE = path.resolve(__dirname, '../../enclave');
const REBUILD = 'npm run build:enclave (or npm run test:runtime, which builds first)';

function sourceFiles(directory) {
  const out = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (/\.(ts|mts|cts)$/.test(entry.name) && !/\.d\.(ts|mts|cts)$/.test(entry.name)) out.push(full);
  }
  return out;
}

const compiledName = (file) => file.replace(/\.ts$/, '.js').replace(/\.mts$/, '.mjs').replace(/\.cts$/, '.cjs');

// Returns the relative paths of compiled modules that are missing or older than
// their source (or than tsconfig.json). An empty list means dist is current.
function staleEnclaveModules(enclaveDir = DEFAULT_ENCLAVE) {
  const src = path.join(enclaveDir, 'src');
  const dist = path.join(enclaveDir, 'dist');
  const configTime = fs.statSync(path.join(enclaveDir, 'tsconfig.json')).mtimeMs;
  const stale = [];
  for (const file of sourceFiles(src)) {
    const relative = path.relative(src, file);
    const compiled = path.join(dist, compiledName(relative));
    let compiledTime;
    try { compiledTime = fs.statSync(compiled).mtimeMs; } catch { stale.push(`${relative} (not compiled)`); continue; }
    if (compiledTime < fs.statSync(file).mtimeMs) stale.push(`${relative} (source is newer)`);
    else if (compiledTime < configTime) stale.push(`${relative} (tsconfig.json is newer)`);
  }
  return stale;
}

function assertEnclaveDistFresh(enclaveDir = DEFAULT_ENCLAVE) {
  const stale = staleEnclaveModules(enclaveDir);
  if (stale.length === 0) return;
  const shown = stale.slice(0, 10).join(', ') + (stale.length > 10 ? `, and ${stale.length - 10} more` : '');
  throw new Error(`Compiled enclave modules are out of date with enclave/src: ${shown}. Rebuild with ${REBUILD}.`);
}

module.exports = { staleEnclaveModules, assertEnclaveDistFresh };
