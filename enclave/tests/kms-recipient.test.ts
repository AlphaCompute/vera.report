import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import { createHash } from 'node:crypto';
import { KmsRecipientClient, EnclaveKmsAgent } from '../src/kms-recipient-client';
const keyArn = 'arn:aws:kms:us-east-2:000000000000:key/11111111-2222-3333-4444-555555555555';
const credentials = () => ({ accessKeyId:'synthetic-access',secretAccessKey:'synthetic-secret',sessionToken:'synthetic-session',expiration:new Date(Date.now()+60000) });
const request = () => ({ keyArn,ciphertext:Buffer.from('ciphertext'),attestation:Buffer.from('attestation'),context:{purpose:'evidence',fileKey:'synthetic-record'} });
const response = () => ({ KeyId:keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextForRecipient:Buffer.from('synthetic-CMS') });
afterEach(() => jest.restoreAllMocks());
it('binds attestation and hashed context to a single attested Decrypt command', async () => {
  const send = jest.spyOn(KMSClient.prototype,'send').mockResolvedValue(response() as never);
  const client = new KmsRecipientClient(credentials());
  try {
    expect((await client.decrypt(request())).toString()).toBe('synthetic-CMS');
    const command = send.mock.calls[0][0] as DecryptCommand;
    expect(command.input).toEqual({ KeyId:keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextBlob:Buffer.from('ciphertext'),
      EncryptionContext:{purpose:'evidence',fileKey:createHash('sha256').update(JSON.stringify(['vera-context-v2','fileKey','synthetic-record'])).digest('hex')},
      Recipient:{AttestationDocument:Buffer.from('attestation'),KeyEncryptionAlgorithm:'RSAES_OAEP_SHA_256'} });
    expect(send).toHaveBeenCalledTimes(1);
  } finally { client.close(); }
});
it.each([
  {Plaintext:Buffer.from('must-never-return')}, {KeyId:keyArn.replace('000000000000','111111111111')},
  {EncryptionAlgorithm:'RSAES_OAEP_SHA_1'}, {CiphertextForRecipient:undefined}, {CiphertextForRecipient:Buffer.alloc(16385)},
])('rejects an invalid KMS response without returning provider data: %j', async change => {
  jest.spyOn(KMSClient.prototype,'send').mockResolvedValue({...response(),...change} as never);
  const client = new KmsRecipientClient(credentials());
  try { await expect(client.decrypt(request())).rejects.toThrow('Attested KMS bootstrap failed'); }
  finally { client.close(); }
});
it.each([
  {keyArn:keyArn.replace('us-east-2','us-west-2')},{attestation:Buffer.alloc(0)}, {ciphertext:Buffer.alloc(6145)},
  {context:{purpose:'signing',fileKey:'record'}}, {context:{purpose:'evidence'}}, {context:{purpose:'evidence',fileKey:'record',unapproved:'x'}},
])('rejects invalid requests before sending: %j', async change => {
  const send = jest.spyOn(KMSClient.prototype,'send');const client = new KmsRecipientClient(credentials());
  try { await expect(client.decrypt({...request(),...change} as any)).rejects.toThrow();expect(send).not.toHaveBeenCalled(); }
  finally { client.close(); }
});
it('rejects concurrent bootstrap and discards a late result after close', async () => {
  let finish!: (value:any)=>void;
  jest.spyOn(KMSClient.prototype,'send').mockImplementation(() => new Promise(resolve => {finish=resolve;}) as any);
  const client = new KmsRecipientClient(credentials());const pending = client.decrypt(request());
  await expect(client.decrypt(request())).rejects.toThrow('unavailable');
  client.close();finish(response());
  await expect(pending).rejects.toThrow('Attested KMS bootstrap failed');
  await expect(client.decrypt(request())).rejects.toThrow('unavailable');
});
it('requires temporary credentials with a future expiration', () => {
  expect(() => new KmsRecipientClient({...credentials(),sessionToken:''})).toThrow();
  expect(() => new KmsRecipientClient({...credentials(),expiration:new Date(0)})).toThrow();
});
it('fixes the TLS destination and refuses alternate AWS hosts', () => {
  const tls = require('node:tls');
  const connect = jest.spyOn(tls,'connect').mockReturnValue({} as any);
  const agent = new EnclaveKmsAgent();
  agent.createConnection({host:'kms.us-east-2.amazonaws.com'});
  expect(connect).toHaveBeenCalledWith(expect.objectContaining({host:'127.0.0.1',port:8000,servername:'kms.us-east-2.amazonaws.com',rejectUnauthorized:true,minVersion:'TLSv1.2'}));
  expect(connect.mock.calls[0][0].ca.length).toBeGreaterThan(0);
  expect(() => agent.createConnection({host:'attacker.invalid'})).toThrow();
  agent.destroy();
});

it('accepts the documented empty Plaintext field only with a valid recipient response', async () => {
  jest.spyOn(KMSClient.prototype,'send').mockResolvedValue({...response(),Plaintext:Buffer.alloc(0)} as never);
  const client = new KmsRecipientClient(credentials());
  try { expect((await client.decrypt(request())).toString()).toBe('synthetic-CMS'); } finally { client.close(); }
});

it('generates AES-256 keys bound to the attested recipient and returns only encrypted material', async () => {
  const send = jest.spyOn(KMSClient.prototype, 'send').mockResolvedValue({ KeyId: keyArn, CiphertextBlob: Buffer.from('wrapped'), CiphertextForRecipient: Buffer.from('recipient') } as never);
  const client = new KmsRecipientClient(credentials());
  try {
    await expect(client.generate(request())).resolves.toEqual({ wrappedKey: Buffer.from('wrapped'), envelope: Buffer.from('recipient') });
    const command = send.mock.calls[0][0] as any;
    expect(command.constructor.name).toBe('GenerateDataKeyCommand');
    expect(command.input).toEqual({ KeyId: keyArn, KeySpec: 'AES_256', EncryptionContext: { purpose: 'evidence', fileKey: createHash('sha256').update(JSON.stringify(['vera-context-v2','fileKey','synthetic-record'])).digest('hex') },
      Recipient: { AttestationDocument: Buffer.from('attestation'), KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256' } });
    expect(send).toHaveBeenCalledTimes(1);
  } finally { client.close(); }
});
it.each([
  { Plaintext: Buffer.alloc(32) }, { CiphertextBlob: undefined }, { CiphertextBlob: Buffer.alloc(6145) },
  { CiphertextForRecipient: undefined }, { CiphertextForRecipient: Buffer.alloc(16385) }, { KeyId: 'different-key' },
])('rejects invalid generated key material: %j', async change => {
  jest.spyOn(KMSClient.prototype, 'send').mockResolvedValue({ KeyId: keyArn, CiphertextBlob: Buffer.from('wrapped'), CiphertextForRecipient: Buffer.from('recipient'), ...change } as never);
  const client = new KmsRecipientClient(credentials());
  try { await expect(client.generate(request())).rejects.toThrow('Attested KMS bootstrap failed'); }
  finally { client.close(); }
});
it('shares concurrency and close barriers between generation and decrypt', async () => {
  let finish!: (value: any) => void;
  jest.spyOn(KMSClient.prototype, 'send').mockImplementation(() => new Promise(resolve => { finish = resolve; }) as any);
  const client = new KmsRecipientClient(credentials());
  const pending = client.generate(request());
  await expect(client.decrypt(request())).rejects.toThrow('unavailable');
  client.close(); finish({ KeyId: keyArn, CiphertextBlob: Buffer.from('wrapped'), CiphertextForRecipient: Buffer.from('recipient') });
  await expect(pending).rejects.toThrow('Attested KMS bootstrap failed');
  await expect(client.generate(request())).rejects.toThrow('unavailable');
});
it.each(['decrypt', 'generate'] as const)('aborts pending %s work immediately when its session closes', async method => {
  let signal!: AbortSignal;
  jest.spyOn(KMSClient.prototype, 'send').mockImplementation((_command: any, options: any) => {
    signal = options.abortSignal;
    return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('synthetic cancelled request')), { once: true })) as any;
  });
  const client = new KmsRecipientClient(credentials());
  const pending = method === 'decrypt' ? client.decrypt(request()) : client.generate(request());
  expect(signal.aborted).toBe(false);
  client.close();
  expect(signal.aborted).toBe(true);
  await expect(pending).rejects.toThrow('Attested KMS bootstrap failed');
});
