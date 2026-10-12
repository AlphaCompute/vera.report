import * as tls from 'node:tls';
import { createChannelCredentials, type ChannelAttestor } from './channel-server.js';
import { RecipientSession } from './recipient-session.js';

const MAX_FRAME = 12 * 1024 * 1024;
function object(value: unknown, names: string[]): Record<string, any> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== names.sort().join(',')) throw new Error('Invalid channel request');
  return value as Record<string, any>;
}
function bytes(value: unknown, max: number): Buffer {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3)) throw new Error('Invalid bytes');
  const result = Buffer.from(value, 'base64');
  if (result.length > max || result.toString('base64') !== value) throw new Error('Invalid bytes');
  return result;
}
async function send(socket: tls.TLSSocket, id: unknown, result: unknown): Promise<void> {
  const body = Buffer.from(JSON.stringify({ id, result }));
  if (body.length > MAX_FRAME) throw new Error('Reply too large');
  const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
  try {
    await new Promise<void>((resolve, reject) => {
      socket.write(header);
      socket.write(body, error => error ? reject(error) : resolve());
    });
  } finally { body.fill(0); }
}

/** Experimental recipient endpoint; not started by the application entrypoint.
 * KMS authorizes key use with the supplied temporary IAM credentials. Opening
 * a session alone grants no handle. Application user/record authorization must
 * still occur before the application sends credentials or requests here.
 */
export async function createRecipientChannelServer(attest: ChannelAttestor): Promise<tls.Server> {
  const credentials = await createChannelCredentials();
  try {
    const server = tls.createServer({ key: credentials.key, cert: credentials.cert, minVersion: 'TLSv1.3', handshakeTimeout: 10000 }, socket => {
      let session: RecipientSession | undefined;
      let buffer = Buffer.alloc(0);
      let next = 0;
      const deadline = setTimeout(() => socket.destroy(), 300000); deadline.unref();
      socket.setTimeout(15000, () => socket.destroy());
      socket.on('error', () => {});
      socket.once('close', () => { clearTimeout(deadline); buffer.fill(0); session?.close(); });
      void (async () => {
        try {
          for await (const chunk of socket) {
            if (buffer.length + chunk.length > MAX_FRAME + 4) throw new Error('Buffer limit');
            const previous = buffer; buffer = Buffer.concat([previous, chunk]); previous.fill(0);
            while (buffer.length >= 4) {
              const length = buffer.readUInt32BE();
              if (!length || length > (next < 2 ? 32768 : MAX_FRAME)) throw new Error('Frame limit');
              if (buffer.length < length + 4) break;
              const request = object(JSON.parse(buffer.subarray(4, length + 4).toString('utf8')), ['id', 'method', 'params']);
              const rest = Buffer.from(buffer.subarray(length + 4)); buffer.fill(0); buffer = rest;
              // Bootstrap cannot be pipelined with a privileged request before
              // the client receives and verifies the peer attestation.
              if (next === 0 && buffer.length) throw new Error('Pipelined challenge');
              if (next >= 10000 || socket.destroyed) throw new Error('Session unavailable');
              if (next === 0) {
                const params = object(request.params, ['nonce']);
                if (request.method !== 'attestChannel' || typeof request.id !== 'string' || !request.id.length || request.id.length > 128 ||
                    typeof params.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(params.nonce)) throw new Error('Invalid challenge');
                const result = await attest(params.nonce, credentials.hash);
                if (socket.destroyed) throw new Error('Session closed');
                await send(socket, request.id, result);
              } else {
                if (request.id !== next) throw new Error('Invalid sequence');
                if (next === 1) {
                  if (request.method !== 'openRecipient') throw new Error('Session required');
                  const params = object(request.params, ['accessKeyId', 'secretAccessKey', 'sessionToken', 'expiration']);
                  if (typeof params.expiration !== 'string') throw new Error('Invalid credentials');
                  session = new RecipientSession(Buffer.from(credentials.hash, 'hex'), {
                    accessKeyId: params.accessKeyId, secretAccessKey: params.secretAccessKey,
                    sessionToken: params.sessionToken, expiration: new Date(params.expiration),
                  });
                  await send(socket, request.id, { kind: 'sessionOpened' });
                } else {
                  if (!session) throw new Error('Session required');
                  const common = ['purpose', 'record', 'keyArn', 'context'];
                  let result: unknown;
                  switch (request.method) {
                    case 'beginRead': {
                      const p = object(request.params, ['purpose', 'record', 'handle', 'iv', 'size', 'field']);
                      await session.beginRead({purpose:p.purpose, record:p.record}, p.handle,
                        {iv:bytes(p.iv, 16), size:p.size, field:p.field === null ? undefined : p.field});
                      result = {kind:'readStarted'}; break;
                    }
                    case 'appendRead': {
                      const p = object(request.params, ['ciphertext']);
                      await session.appendRead(bytes(p.ciphertext, 1024 * 1024));
                      result = {kind:'readAccepted'}; break;
                    }
                    case 'authenticateRead': {
                      const p = object(request.params, ['tag']);
                      await session.authenticateRead(bytes(p.tag, 16));
                      result = {kind:'readAuthenticated'}; break;
                    }
                    case 'readChunk': {
                      object(request.params, []);
                      const chunk = await session.readChunk();
                      try { result = {plaintext:chunk.plaintext.toString('base64'), done:chunk.done}; }
                      finally { chunk.plaintext.fill(0); }
                      break;
                    }
                    case 'cancelRead': {
                      object(request.params, []);
                      await session.cancelRead(); result = {kind:'readCancelled'}; break;
                    }
                    case 'generate': {
                      const p = object(request.params, common);
                      result = await session.generate(p as Parameters<RecipientSession['generate']>[0]); break;
                    }
                    case 'bootstrap': {
                      const p = object(request.params, [...common, 'wrappedKey']);
                      result = { handle: await session.bootstrap(p as Parameters<RecipientSession['bootstrap']>[0]) }; break;
                    }
                    case 'bootstrapLegacyEvidence': {
                      const p = object(request.params, [...common, 'wrappedKey', 'salt']);
                      result = { handle: await session.bootstrapLegacyEvidence({ purpose: p.purpose, record: p.record,
                        keyArn: p.keyArn, context: p.context, wrappedKey: p.wrappedKey, salt: bytes(p.salt, 32) }) }; break;
                    }
                    case 'bootstrapLegacyPrivate': {
                      const p = object(request.params, ['record', 'field', 'keyArn', 'wrappedKey']);
                      result = { handle: await session.bootstrapLegacyPrivate({ record: p.record, field: p.field, keyArn: p.keyArn, wrappedKey: p.wrappedKey }) }; break;
                    }
                    case 'decryptLegacyPrivate': {
                      const p = object(request.params, ['record', 'field', 'handle', 'iv', 'tag', 'ciphertext']);
                      const plaintext = await session.decryptLegacyPrivate(p.record, p.field, p.handle,
                        { iv: bytes(p.iv, 12), tag: bytes(p.tag, 16), ciphertext: bytes(p.ciphertext, 8 * 1024 * 1024) });
                      try { result = { plaintext: plaintext.toString('base64') }; } finally { plaintext.fill(0); }
                      break;
                    }
                    case 'encrypt': {
                      const p = object(request.params, ['purpose', 'record', 'handle', 'plaintext']);
                      const plaintext = bytes(p.plaintext, 8 * 1024 * 1024);
                      try {
                        const sealed = await session.encrypt({ purpose: p.purpose, record: p.record }, p.handle, plaintext);
                        result = { iv: sealed.iv.toString('base64'), tag: sealed.tag.toString('base64'), ciphertext: sealed.ciphertext.toString('base64') };
                      } finally { plaintext.fill(0); }
                      break;
                    }
                    case 'decryptLegacyEvidence':
                    case 'decrypt': {
                      const p = object(request.params, ['purpose', 'record', 'handle', 'iv', 'tag', 'ciphertext']);
                      const historical = request.method === 'decryptLegacyEvidence';
                      const decrypt = historical ? session.decryptLegacyEvidence.bind(session) : session.decrypt.bind(session);
                      const plaintext = await decrypt({ purpose: p.purpose, record: p.record }, p.handle,
                        { iv: bytes(p.iv, historical ? 16 : 12), tag: bytes(p.tag, 16), ciphertext: bytes(p.ciphertext, 8 * 1024 * 1024) });
                      try { result = { plaintext: plaintext.toString('base64') }; } finally { plaintext.fill(0); }
                      break;
                    }
                    default: throw new Error('Unsupported operation');
                  }
                  if (socket.destroyed) throw new Error('Session closed');
                  await send(socket, request.id, result);
                }
              }
              next++;
            }
          }
        } catch { socket.destroy(); }
        finally { session?.close(); buffer.fill(0); }
      })();
    });
    server.maxConnections = 16;
    server.on('tlsClientError', () => {});
    return server;
  } finally { credentials.key.fill(0); }
}
