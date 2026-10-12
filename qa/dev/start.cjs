// Local review only. The production build never loads this test harness.
process.env.TS_NODE_COMPILER_OPTIONS = JSON.stringify({ module: 'NodeNext', moduleResolution: 'NodeNext' });
require('ts-node').register({ transpileOnly: true, experimentalResolver: true });
const { startStack } = require('../e2e/stack/stack.ts');
const { mkdtempSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const logDir = mkdtempSync(join(tmpdir(), 'vera-dev-review-'));
startStack({ nextPort: Number(process.env.PORT || 3000), stateFile: join(logDir, 'state.json'), logDir, development: true }).then(stack => {
  console.log(`Local review ready: ${stack.state.baseURL} (simulated attestation; test data only)`);
  console.log(`Local logs: ${logDir}`);
  const stop = async () => { await stack.stop(); process.exit(0); };
  process.once('SIGINT', stop); process.once('SIGTERM', stop);
}).catch(error => { console.error(error); process.exit(1); });
