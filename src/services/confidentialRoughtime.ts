import dgram from 'node:dgram';
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

/** Host side of the enclave's optional Roughtime exchange (storage RPC method
 * `roughtimeExchange`). The host is an untrusted relay: it forwards one request
 * packet over UDP to an allowlisted server and returns the first answer. The
 * enclave authenticates the answer (pinned server key, its own nonce), so this
 * code can only delay or drop it. The allowlist (`CONFIDENTIAL_ROUGHTIME_SERVERS`,
 * comma-separated `host:port`, the same addresses as the measured configuration)
 * keeps the socket from being used as a general UDP sender. */
export type RoughtimeRelay = (address: string, packet: Buffer) => Promise<Buffer | null>;
const ADDRESS = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?:\d{1,5}$/;

export function parseRoughtimeAllowlist(value: string | undefined): string[] {
  if (!value?.trim()) return [];
  const entries = value.split(',').map(item => item.trim()).filter(Boolean);
  for (const entry of entries) {
    const port = Number(entry.slice(entry.lastIndexOf(':') + 1));
    if (!ADDRESS.test(entry) || port < 1 || port > 65535) throw new Error('Invalid CONFIDENTIAL_ROUGHTIME_SERVERS entry');
  }
  if (entries.length > 8) throw new Error('Too many CONFIDENTIAL_ROUGHTIME_SERVERS entries');
  return entries;
}

export function udpRoughtimeRelay(allowlist: readonly string[], options: { timeoutMs?: number } = {}): RoughtimeRelay {
  const allowed = new Set(allowlist), timeoutMs = options.timeoutMs ?? 3_000;
  return async (address, packet) => {
    if (!allowed.has(address) || packet.length < 1024 || packet.length > 2048) return null;
    const split = address.lastIndexOf(':');
    const host = address.slice(0, split), port = Number(address.slice(split + 1));
    const resolved = isIP(host) ? { address: host, family: isIP(host) } : await lookup(host).catch(() => null);
    if (!resolved) return null;
    const socket = dgram.createSocket(resolved.family === 6 ? 'udp6' : 'udp4');
    return new Promise<Buffer | null>(resolve => {
      const finish = (value: Buffer | null) => { clearTimeout(timer); socket.removeAllListeners(); socket.close(); resolve(value); };
      const timer = setTimeout(() => finish(null), timeoutMs);
      socket.on('error', () => finish(null));
      socket.on('message', (message, remote) => {
        if (remote.address !== resolved.address || remote.port !== port) return;
        finish(message.length <= 4096 ? Buffer.from(message) : null);
      });
      socket.send(packet, port, resolved.address, error => { if (error) finish(null); });
    });
  };
}
