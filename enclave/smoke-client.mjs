#!/usr/bin/env node
/**
 * Minimal framed RPC client for the enclave smoke test.
 *
 * Speaks the same 4-byte big-endian length prefix plus JSON that server.ts
 * expects. Connects to the host-side end of the vsock bridge, which the smoke
 * test stands up with socat, so this stays plain TCP and needs no vsock binding
 * for Node.
 *
 * Usage: node smoke-client.mjs <port> <method> [jsonParams]
 * Exits non-zero on transport failure, RPC error, or timeout.
 */

import net from 'node:net';

const [, , portArg, method, paramsArg] = process.argv;

if (!portArg || !method) {
  process.stderr.write('usage: smoke-client.mjs <port> <method> [jsonParams]\n');
  process.exit(2);
}

const port = Number(portArg);
const params = paramsArg ? JSON.parse(paramsArg) : {};
const TIMEOUT_MS = 20000;

const frame = (obj) => {
  const payload = Buffer.from(JSON.stringify(obj), 'utf-8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
};

const socket = net.createConnection({ host: '127.0.0.1', port });
let buffer = Buffer.alloc(0);
let settled = false;

const finish = (code, message) => {
  if (settled) return;
  settled = true;
  if (message) process.stderr.write(message + '\n');
  socket.destroy();
  process.exit(code);
};

const timer = setTimeout(
  () => finish(1, `timeout: no response to "${method}" within ${TIMEOUT_MS}ms`),
  TIMEOUT_MS
);
timer.unref();

socket.on('connect', () => socket.write(frame({ id: `smoke-${method}`, method, params })));

socket.on('data', (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  if (buffer.length < 4) return;

  const declared = buffer.readUInt32BE(0);
  if (buffer.length < 4 + declared) return;

  let response;
  try {
    response = JSON.parse(buffer.subarray(4, 4 + declared).toString('utf-8'));
  } catch (err) {
    return finish(1, `malformed response frame: ${err.message}`);
  }

  if (response.error) {
    return finish(1, `rpc error ${response.error.code}: ${response.error.message}`);
  }

  process.stdout.write(JSON.stringify(response.result) + '\n');
  finish(0);
});

socket.on('error', (err) => finish(1, `connect failed on port ${port}: ${err.message}`));
socket.on('close', () => finish(1, 'connection closed before a complete response'));
