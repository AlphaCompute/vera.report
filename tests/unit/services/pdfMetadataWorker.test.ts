import { EventEmitter } from 'node:events';
import { stripPdfMetadata } from '../../../src/services/pdfMetadata';
import { EvidenceValidationError } from '../../../src/utils/evidenceValidationError';

const mockWorkers: Array<EventEmitter & { terminate: jest.Mock }> = [];
jest.mock('node:worker_threads', () => ({
  Worker: jest.fn().mockImplementation(() => {
    const worker = new (require('node:events').EventEmitter)();
    worker.terminate = jest.fn().mockResolvedValue(0);
    worker.stdout = { resume: jest.fn() }; worker.stderr = { resume: jest.fn() };
    mockWorkers.push(worker); return worker;
  }),
}));

beforeEach(() => { jest.useFakeTimers(); mockWorkers.length = 0; });
afterEach(() => jest.useRealTimers());

test('distinguishes file rejection from worker failure', async () => {
  const invalid = stripPdfMetadata(Buffer.from('%PDF-invalid'));
  mockWorkers[0].emit('message', { ok: false });
  await expect(invalid).rejects.toBeInstanceOf(EvidenceValidationError);
  const crashed = stripPdfMetadata(Buffer.from('%PDF-input'));
  mockWorkers[1].emit('error', new Error('synthetic unavailable worker'));
  await expect(crashed).rejects.not.toBeInstanceOf(EvidenceValidationError);
});

test('terminates a stuck parser and ignores a late success message', async () => {
  const pending = stripPdfMetadata(Buffer.from('%PDF-1.7'));
  const rejected = expect(pending).rejects.toThrow('No original file');
  jest.advanceTimersByTime(15000); await rejected;
  mockWorkers[0].emit('message', { ok: true, data: Uint8Array.from([1, 2]) });
  expect(mockWorkers[0].terminate).toHaveBeenCalledTimes(1);
});

test('fails closed on worker crash without disclosing file-controlled error details', async () => {
  const pending = stripPdfMetadata(Buffer.from('%PDF-1.7'));
  mockWorkers[0].emit('error', new Error('identity-canary-parser-error'));
  await expect(pending).rejects.toThrow('No original file');
  expect(mockWorkers[0].terminate).toHaveBeenCalledTimes(1);
});

test('does not accept a worker exit before a successful result', async () => {
  const pending = stripPdfMetadata(Buffer.from('%PDF-1.7'));
  mockWorkers[0].emit('exit', 0);
  await expect(pending).rejects.toThrow('No original file');
});

test('rejects overlapping work and releases capacity only after worker termination', async () => {
  const first = stripPdfMetadata(Buffer.from('%PDF-1.7'));
  let terminate!: (code: number) => void;
  mockWorkers[0].terminate.mockReturnValue(new Promise<number>(resolve => { terminate = resolve; }));
  await expect(stripPdfMetadata(Buffer.from('%PDF-1.7'))).rejects.toThrow('busy');
  expect(mockWorkers).toHaveLength(1);
  mockWorkers[0].emit('message', { ok: true, data: Uint8Array.from([1, 2]) });
  await expect(stripPdfMetadata(Buffer.from('%PDF-1.7'))).rejects.toThrow('busy');
  terminate(0);
  await expect(first).resolves.toEqual(Buffer.from([1, 2]));
  const next = stripPdfMetadata(Buffer.from('%PDF-1.7'));
  mockWorkers[1].emit('message', { ok: true, data: Uint8Array.from([3, 4]) });
  await expect(next).resolves.toEqual(Buffer.from([3, 4]));
});
