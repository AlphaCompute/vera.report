import { join } from 'node:path';
import { startStack } from './stack/stack';
import { STATE_FILE } from './support/state';

export default async function globalSetup() {
  const port = Number(process.env.VERA_E2E_PORT || 3196);
  const { stop, sweep } = await startStack({ nextPort: port, stateFile: STATE_FILE, logDir: join(__dirname, 'test-results') });
  // Teardown sweeps the host's logs and stored records for every registered
  // sentinel and device secret before the stack (and its database) goes away;
  // a hit fails the run.
  return async () => {
    try {
      const { secrets, records } = await sweep();
      process.stderr.write(`[e2e] host sweep: ${secrets} registered secret forms, ${records} host records, no leaks\n`);
    } finally { await stop(); }
  };
}
