import { PassThrough } from 'node:stream';
import { execFile } from 'node:child_process';
import { attestIdentity } from '../src/attestation';
import { handleRequest } from '../src/server';

jest.mock('node:child_process', () => ({ execFile: jest.fn() }));
const execute = jest.mocked(execFile);
const nonce = '42'.repeat(32);

function helperOutput(output: string, error: Error | null = null) {
  let input = '';
  execute.mockImplementation(((_file: unknown, _args: unknown, _options: unknown, callback: Function) => {
    const stdin = new PassThrough();
    stdin.on('data', chunk => { input += chunk.toString(); });
    queueMicrotask(() => callback(error, output, ''));
    return { stdin };
  }) as any);
  return () => JSON.parse(input);
}

beforeEach(() => execute.mockReset());

test.each([{}, { nonce: '' }, { nonce: 'A'.repeat(64) }, { nonce: '00'.repeat(31) },
  { nonce, public_key: 'parent-owned' }, { nonce, user_data: 'different-protocol' }])(
  'rejects malformed or caller-extended requests before launching NSM', async params => {
    await expect(attestIdentity(params)).rejects.toThrow();
    expect(execute).not.toHaveBeenCalled();
  },
);

test('passes only challenge bytes to the fixed bounded helper', async () => {
  // Opaque synthetic bytes exercise transport only, not COSE verification.
  const input = helperOutput(JSON.stringify({ document: 'AQID' }));
  expect(await attestIdentity({ nonce })).toEqual({ document: 'AQID' });
  expect(input()).toEqual({ nonce: Buffer.from(nonce, 'hex').toString('base64') });
  expect(execute).toHaveBeenCalledWith('/app/bin/vera-nsm', [], { timeout: 10_000, maxBuffer: 24576 }, expect.any(Function));
});

test.each(['{}', '[]', '{', '{"document":""}', '{"document":"AQID!"}',
  JSON.stringify({ document: 'AQID', public_key: 'parent-owned' }),
  JSON.stringify({ document: Buffer.alloc(16385).toString('base64') })])('rejects invalid helper output', async output => {
  helperOutput(output);
  await expect(attestIdentity({ nonce })).rejects.toThrow();
});

test('releases admission after helper failure and refuses overlapping work', async () => {
  let complete!: Function;
  execute.mockImplementation(((_file: unknown, _args: unknown, _options: unknown, callback: Function) => {
    complete = callback;
    return { stdin: new PassThrough() };
  }) as any);
  const first = expect(attestIdentity({ nonce })).rejects.toThrow('NSM attestation unavailable');
  try {
    await expect(attestIdentity({ nonce })).rejects.toThrow('already in progress');
    expect(execute).toHaveBeenCalledTimes(1);
  } finally { complete(new Error('synthetic NSM failure'), '', ''); await first; }
  helperOutput('{"document":"AQID"}');
  await expect(attestIdentity({ nonce })).resolves.toEqual({ document: 'AQID' });
});

test('exposes identity evidence in production without enabling secret RPC or claiming readiness', async () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  helperOutput('{"document":"AQID"}');
  try {
    expect(await handleRequest({ id: 1, method: 'attestIdentity', params: { nonce } })).toEqual({ id: 1, result: { document: 'AQID' } });
    expect((await handleRequest({ id: 2, method: 'deriveKey', params: { secret: 'parent' } })).error).toBeDefined();
    expect((await handleRequest({ id: 3, method: 'health', params: {} })).result).toMatchObject({ attested: false, status: 'unavailable' });
  } finally { process.env.NODE_ENV = previous; }
});
