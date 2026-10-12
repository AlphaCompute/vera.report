import { execFileSync } from 'node:child_process';
import * as https from 'node:https';
import * as tls from 'node:tls';
import { KmsRecipientClient } from '../src/kms-recipient-client';
const host = 'kms.us-east-2.amazonaws.com';
const keyArn = 'arn:aws:kms:us-east-2:000000000000:key/11111111-2222-3333-4444-555555555555';
function certificate(name: string) {
  const output = execFileSync('openssl',['req','-new','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','-','-out','-',
    '-subj',`/CN=${name}`,'-addext',`subjectAltName=DNS:${name}`,'-days','1'],{stdio:['ignore','pipe','ignore']});
  const boundary = output.indexOf('-----BEGIN CERTIFICATE-----');
  if (boundary < 0) throw new Error('Missing synthetic certificate');
  return {key:output.subarray(0,boundary),cert:output.subarray(boundary)};
}
const good = certificate(host), wrong = certificate('attacker.invalid');
afterEach(() => jest.restoreAllMocks());

it.each(['decrypt', 'generate'].flatMap(operation => ['success','untrusted','wrong-host','oversized','server-error','cancelled'].map(mode => [operation, mode])))('enclave KMS HTTPS %s: %s', async (method, mode) => {
  const cert = mode === 'wrong-host' ? wrong : good;
  let requests = 0; let body = ''; let authorization = ''; let targetHost = '';
  let received!: () => void;
  const requestReceived = new Promise<void>(resolve => { received = resolve; });
  const server = https.createServer(cert, async (request,response) => {
    requests++;
    for await (const chunk of request) body += chunk.toString();
    authorization = String(request.headers.authorization); targetHost = String(request.headers.host);
    received();
    if (mode === 'cancelled') return; // Real TLS peer withholds all response headers.
    response.setHeader('content-type','application/x-amz-json-1.1');
    if (mode === 'server-error') { response.writeHead(500); response.end(JSON.stringify({__type:'KMSInternalException',message:'synthetic failure'}));return; }
    response.end(JSON.stringify({KeyId:keyArn,CiphertextBlob:Buffer.from('persistent-wrapped').toString('base64'),EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextForRecipient:Buffer.from('synthetic-CMS').toString('base64'),
      ...(mode === 'oversized' ? {extra:'x'.repeat(100000)} : {})}));
  });
  await new Promise<void>(resolve => server.listen(0,'127.0.0.1',resolve));
  const port = (server.address() as import('node:net').AddressInfo).port;
  const original = tls.connect;
  // Test-only routing to a synthetic TLS server. Production's hostname checks
  // and rejectUnauthorized stay intact; only trusted-fixture tests add this CA.
  jest.spyOn(require('node:tls'),'connect').mockImplementation((...args: any[]) => {
    const options = args[0];
    expect(options.servername).toBe(host);expect(options.rejectUnauthorized).toBe(true);
    return original({...options,port,...(mode === 'untrusted' ? {} : {ca:cert.cert})});
  });
  const client = new KmsRecipientClient({accessKeyId:'synthetic-access',secretAccessKey:'synthetic-secret',sessionToken:'synthetic-session',expiration:new Date(Date.now()+60000)});
  try {
    const input = {keyArn,ciphertext:Buffer.from('encrypted-key'),attestation:Buffer.from('signed-fixture'),context:{purpose:'narrative',trackingId:'synthetic-record'}};
    const operation = method === 'decrypt' ? client.decrypt(input) : client.generate(input);
    if (mode === 'success') {
      const result = await operation;
      if (Buffer.isBuffer(result)) expect(result.toString()).toBe('synthetic-CMS');
      else { expect(result).toEqual({wrappedKey:Buffer.from('persistent-wrapped'),envelope:Buffer.from('synthetic-CMS')}); expect(JSON.parse(body).KeySpec).toBe('AES_256'); }
      expect(targetHost).toBe(host);
      expect(authorization).toContain('/us-east-2/kms/aws4_request');
      expect(JSON.parse(body).Recipient.KeyEncryptionAlgorithm).toBe('RSAES_OAEP_SHA_256');
      expect(body).not.toContain('synthetic-record');
    } else {
      const denied = expect(operation).rejects.toThrow('Attested KMS bootstrap failed');
      if (mode === 'cancelled') { await requestReceived; client.close(); }
      await denied;
    }
    expect(requests).toBe(mode === 'untrusted' || mode === 'wrong-host' ? 0 : 1);
  } finally {
    client.close();server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
