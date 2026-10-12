const { createRelay } = require('./ipfs-loopback-relay.cjs');
const { start } = require('./start-tls.cjs');

async function main(command, args, env = process.env) {
  const flag = env.VERA_IPFS_TRANSPORT_ENABLED || '0';
  if (!['0', '1'].includes(flag)) throw new Error('Invalid IPFS transport flag');
  if (flag === '0') return start(command, args, env);
  if (env.RUN_MODE !== 'api') throw new Error('IPFS transport requires the API runtime');
  const relay = await createRelay();
  let control;
  const failed = () => {
    if (control) control.stop(1);
  };
  relay.server.on('error', failed);
  try {
    const response = await fetch('http://127.0.0.1:15002/health', { headers: { Connection: 'close' }, redirect: 'error', signal: AbortSignal.timeout(5000) });
    await response.body?.cancel();
    if (response.status !== 204) throw new Error('IPFS transport readiness failed');
    control = start(command, args, env);
    const close = () => { relay.close().catch(() => {}); };
    process.once('SIGTERM', close);
    process.once('SIGINT', close);
  } catch (error) {
    await relay.close();
    throw error;
  }
}
if (require.main === module) main(process.argv[2], process.argv.slice(3)).catch(() => {
  // Never include endpoints, process environments or upstream payloads in logs.
  console.error('IPFS transport startup failed'); process.exitCode = 1;
});
module.exports = { main };
