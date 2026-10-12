import http from 'node:http';
import type { AttestedVerificationReaderOptions } from './attestedReportVerificationReader';

const FAILURE = 'Attested task credentials unavailable';
const MAX_BODY = 32768;

/** Explicit ECS v2 task metadata only. No caller-controlled host or ambient credential chain. */
export function createAttestedEcsCredentials(relativeUri: string, expectedRoleArn: string): AttestedVerificationReaderOptions['credentials'] {
  if (typeof relativeUri !== 'string' || !/^\/v2\/credentials\/[A-Za-z0-9-]{1,128}$/.test(relativeUri) ||
      typeof expectedRoleArn !== 'string' || expectedRoleArn.length > 512 ||
      !/^arn:aws:iam::000000000000:role\/[A-Za-z0-9+=,.@_/-]+$/.test(expectedRoleArn)) throw new Error(FAILURE);
  return signal => new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new Error(FAILURE)); return; }
    const chunks: Buffer[] = [];
    let size = 0, ended = false, failed = false;
    let request: http.ClientRequest;
    const stop = () => { failed = true; request?.destroy(); };
    const timer = setTimeout(stop, 3000);
    signal.addEventListener('abort', stop, { once: true });
    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', stop);
      chunks.forEach(chunk => chunk.fill(0));
    };
    try {
      request = http.get({ hostname: '169.254.170.2', port: 80, path: relativeUri, agent: false }, response => {
        response.on('error', stop);
        response.on('aborted', stop);
        if (response.statusCode !== 200 || (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity')) {
          stop(); return;
        }
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (failed || size > MAX_BODY) { chunk.fill(0); stop(); }
          else chunks.push(chunk);
        });
        response.on('end', () => { ended = true; request.destroy(); });
      });
      request.on('error', stop);
      request.once('close', () => {
        const body = Buffer.concat(chunks);
        try {
          if (failed || !ended || signal.aborted) throw new Error(FAILURE);
          const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
          if (!value || Array.isArray(value) || value.RoleArn !== expectedRoleArn ||
              ['AccessKeyId', 'SecretAccessKey', 'Token', 'Expiration'].some(key => typeof value[key] !== 'string' || !value[key].length || value[key].length > 8192) ||
              !Number.isFinite(Date.parse(value.Expiration)) || Date.parse(value.Expiration) <= Date.now() + 60000) throw new Error(FAILURE);
          resolve({ accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey,
            sessionToken: value.Token, expiration: value.Expiration });
        } catch { reject(new Error(FAILURE)); }
        finally { body.fill(0); cleanup(); }
      });
    } catch {
      cleanup();
      reject(new Error(FAILURE));
    }
  });
}
