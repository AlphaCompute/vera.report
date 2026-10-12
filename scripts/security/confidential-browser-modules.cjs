// Module set for the synthetic browser bundle in verify-confidential-browser.cjs.
// The set is derived by following relative imports from the browser entry
// modules, so a new enclave/src/confidential dependency cannot silently drop
// out of the bundle (a hard-coded list once missed caseChunks.ts).
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');

// Modules re-exported to the synthetic browser page (see entry.js in the verifier).
const BROWSER_ENTRY_MODULES = Object.freeze(['authorization', 'caseObject', 'caseRanges', 'recovery', 'accessRequest',
  'enrollmentProof', 'attestationCbor', 'attestationEvidence', 'attestationPki', 'attestation', 'releaseManifest',
  'channelMessage', 'caseMessage', 'participantRequest', 'ownerGrant', 'firmKeyBinding', 'firmMembers',
  'caseStateKey', 'ownerSubmission', 'firmSetup', 'pgp']);

const MODULE_NAME = /^[A-Za-z][A-Za-z0-9]*$/;

function relativeImports(source, fileName) {
  const info = ts.preProcessFile(source, true, true);
  return info.importedFiles.map(item => item.fileName).filter(specifier => specifier.startsWith('.'))
    .map(specifier => {
      const match = /^\.\/([^/]+?)(?:\.ts|\.js)?$/.exec(specifier);
      if (!match || !MODULE_NAME.test(match[1])) {
        throw new Error(`${fileName} imports ${specifier}; browser bundle modules must stay in enclave/src/confidential`);
      }
      return match[1];
    });
}

// Returns every module name reachable from `entries` via relative imports, in
// a stable order (entries first, then discovery order).
function collectBrowserModules(directory, entries = BROWSER_ENTRY_MODULES) {
  const seen = new Set(), queue = [...entries];
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    if (!MODULE_NAME.test(name)) throw new Error(`Invalid module name ${name}`);
    const file = path.join(directory, `${name}.ts`);
    if (!fs.existsSync(file)) throw new Error(`Missing browser bundle module ${name}.ts`);
    seen.add(name);
    for (const dependency of relativeImports(fs.readFileSync(file, 'utf8'), `${name}.ts`)) {
      if (!seen.has(dependency)) queue.push(dependency);
    }
  }
  return [...seen];
}

module.exports = { BROWSER_ENTRY_MODULES, collectBrowserModules, relativeImports };
