import { execFile } from 'node:child_process';
import { createPrivateKey, X509Certificate, createHash } from 'node:crypto';
import * as tls from 'node:tls';
import { MessageFramer, frameMessage } from './server.js';
import { installFatalHandlers } from './fatal.js';

export type ChannelAttestor = (nonce: string, certificateHash: string) => Promise<{ document: string }>;

export async function createChannelCredentials(): Promise<{ key: Buffer; cert: string; hash: string }> {
  // OpenSSL generates both objects on stdout; no private-key file or reopened
  // stdin descriptor is needed (Node's Linux stdin transport is a socket).
  // macOS LibreSSL requires /dev/stdout; Linux OpenSSL uses '-' for stdout.
  const output = await new Promise<Buffer>((resolve, reject) => {
    execFile('/usr/bin/openssl', ['req', '-new', '-x509', '-newkey', 'ec',
      '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', process.platform === 'darwin' ? '/dev/stdout' : '-',
      '-subj', '/CN=vera-enclave', '-days', '365', '-sha256'],
    { encoding: 'buffer', timeout: 10000, maxBuffer: 16384 }, (error, stdout) => {
      if (error) { stdout.fill(0); reject(new Error('Channel certificate generation failed')); }
      else resolve(stdout);
    });
  });
  let key: Buffer | undefined;
  try {
    const boundary = output.indexOf('-----BEGIN CERTIFICATE-----');
    if (boundary < 0) throw new Error('Missing channel certificate');
    key = Buffer.from(output.subarray(0, boundary));
    const certificate = new X509Certificate(output.subarray(boundary));
    if (!certificate.checkPrivateKey(createPrivateKey(key))) throw new Error('Channel certificate key mismatch');
    return { key, cert: certificate.toString(), hash: createHash('sha256').update(certificate.raw).digest('hex') };
  } catch (error) { key?.fill(0); throw error; }
  finally { output.fill(0); }
}

/** One public challenge per TLS connection. No secret-bearing operation is enabled. */
export async function createChannelServer(attest: ChannelAttestor): Promise<tls.Server> {
  const credentials = await createChannelCredentials();
  try {
    const server = tls.createServer({ key: credentials.key, cert: credentials.cert, minVersion: 'TLSv1.3',
      handshakeTimeout: 10000 }, socket => {
      const framer = new MessageFramer();
      const deadline = setTimeout(() => socket.destroy(), 15000); deadline.unref();
      socket.once('close', () => { clearTimeout(deadline); framer.reset(); });
      socket.on('error', () => {});
      void (async () => {
        let bytes = 0;
        try {
          for await (const chunk of socket.iterator({ destroyOnReturn: false })) {
            bytes += chunk.length;
            if (bytes > 4096) throw new Error('Channel request too large');
            const messages = framer.feed(chunk as Buffer);
            if (!messages.length) continue;
            if (messages.length !== 1) throw new Error('One challenge is required');
            const request = messages[0];
            if (!request || typeof request !== 'object' || Array.isArray(request) ||
                Object.keys(request).sort().join(',') !== 'id,method,params' ||
                typeof request.id !== 'string' || !request.id.length || request.id.length > 128 ||
                request.method !== 'attestChannel' || !request.params || Array.isArray(request.params) ||
                Object.keys(request.params).length !== 1 || typeof request.params.nonce !== 'string' ||
                !/^[0-9a-f]{64}$/.test(request.params.nonce)) throw new Error('Invalid channel challenge');
            const result = await attest(request.params.nonce, credentials.hash);
            await new Promise<void>((resolve, reject) => socket.write(frameMessage({ id: request.id, result }), error => error ? reject(error) : resolve()));
            socket.end();
            return;
          }
        } catch { socket.destroy(); }
      })();
    });
    server.maxConnections = 16;
    server.on('tlsClientError', () => {});
    return server;
  } finally { credentials.key.fill(0); }
}

export async function nativeAttest(nonce: string, certificateHash: string): Promise<{ document: string }> {
  const output = await new Promise<string>((resolve, reject) => {
    const child = execFile('/app/bin/vera-nsm-channel', [], { timeout: 10000, maxBuffer: 24576 }, (error, stdout) => {
      if (error) reject(new Error('Channel attestation unavailable')); else resolve(stdout);
    });
    child.stdin!.on('error', () => {});
    child.stdin!.end(JSON.stringify({ nonce: Buffer.from(nonce, 'hex').toString('base64'), certificate_sha256: Buffer.from(certificateHash, 'hex').toString('base64') }));
  });
  const value = JSON.parse(output);
  if (!value || Object.keys(value).join(',') !== 'document' || typeof value.document !== 'string' ||
      !value.document.length || value.document.length > 21848 || Buffer.from(value.document, 'base64').toString('base64') !== value.document ||
      Buffer.from(value.document, 'base64').length > 16384) throw new Error('Invalid channel attestation');
  return value;
}

if (typeof process.argv[1] === 'string' && /(^|[\\/])channel-server\.(js|ts)$/.test(process.argv[1])) {
  // Per-connection channel keys are zeroed on every normal path; exiting releases the rest.
  installFatalHandlers('Attested channel');
  createChannelServer(nativeAttest).then(server => {
    server.on('error', () => { process.exitCode = 1; server.close(); });
    server.listen(5003, '127.0.0.1');
    for (const signal of ['SIGTERM', 'SIGINT'] as const) process.once(signal, () => server.close());
  }).catch(() => { process.stderr.write('Attested channel startup failed\n'); process.exitCode = 1; });
}
