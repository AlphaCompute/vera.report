const net = require('node:net');

const SOCKET_PATH = '/run/vera-enclave/ipfs-vsock.sock';
const PORT = 15002;
const DEADLINE_MS = 900_000;

// Byte transport only: the measured enclave enforces HTTP verbs, sizes and CIDs.
// Keep the listener inside the API network namespace and its upstream fixed.
async function createRelay({ socketPath = SOCKET_PATH, port = PORT, deadlineMs = DEADLINE_MS } = {}) {
  const connections = new Set();
  let active;
  let waiting;
  let stopping = false;

  function promote(entry) {
    if (stopping || entry.downstream.destroyed) return;
    waiting = undefined;
    active = entry;
    const upstream = entry.upstream = net.connect({ path: socketPath, allowHalfOpen: true });
    upstream.on('error', entry.abort);
    upstream.on('close', () => {
      entry.upstreamClosed = true;
      if (!upstream.readableEnded || !upstream.writableFinished) entry.abort();
      entry.finish();
    });
    // pipe respects backpressure and propagates FIN in each direction.
    entry.downstream.pipe(upstream); upstream.pipe(entry.downstream);
  }

  const server = net.createServer({ allowHalfOpen: true }, downstream => {
    downstream.on('error', () => {});
    if (stopping || waiting) { downstream.destroy(); return; }
    // A client can observe EOF before this process receives both close events.
    // Reserve one paused admission slot so an immediate reconnect waits for
    // deterministic teardown. Never create two upstream connections at once.
    downstream.pause();
    const entry = { downstream, upstream: undefined, downstreamClosed: false, upstreamClosed: false };
    connections.add(entry);
    entry.abort = () => { downstream.destroy(); entry.upstream?.destroy(); };
    entry.finish = () => {
      if (!entry.downstreamClosed || (entry.upstream && !entry.upstreamClosed)) return;
      clearTimeout(entry.timer);
      connections.delete(entry);
      if (waiting === entry) waiting = undefined;
      if (active === entry) active = undefined;
      if (!stopping && !active && waiting) promote(waiting);
    };
    // Queue time counts toward the same absolute deadline; promotion never
    // extends it. A third connection is rejected without buffering its body.
    entry.timer = setTimeout(entry.abort, deadlineMs);
    downstream.on('error', entry.abort);
    downstream.on('close', () => {
      entry.downstreamClosed = true;
      if (!downstream.readableEnded || !downstream.writableFinished) entry.abort();
      entry.finish();
    });
    if (active) waiting = entry;
    else promote(entry);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  return {
    server,
    close: () => new Promise(resolve => {
      stopping = true;
      for (const entry of connections) entry.abort();
      server.close(resolve);
    }),
  };
}
module.exports = { createRelay, SOCKET_PATH, PORT };
