import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
jest.mock('node:child_process', () => ({ ...jest.requireActual('node:child_process'), spawn: jest.fn() }));
import { stripMediaMetadata } from '../../../src/services/mediaMetadata';
import { EvidenceValidationError } from '../../../src/utils/evidenceValidationError';

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
beforeEach(() => {
    Object.defineProperty(process, 'platform', { value: 'linux' });
});
afterEach(() => {
    Object.defineProperty(process, 'platform', platform);
    jest.clearAllMocks();
});

it.each([1, 2, 126, 127])('maps media worker exit %s without disguising infrastructure failures', async (code) => {
    const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough() });
    jest.mocked(spawn).mockReturnValueOnce(child as never);
    const result = stripMediaMetadata(Buffer.from('synthetic media'), 'audio/mpeg');
    child.emit('close', code);
    if (code === 2) await expect(result).rejects.toBeInstanceOf(EvidenceValidationError);
    else await expect(result).rejects.not.toBeInstanceOf(EvidenceValidationError);
});

it('does not classify a missing worker binary as a malformed file', async () => {
    jest.mocked(spawn).mockImplementationOnce(() => {
        throw Object.assign(new Error('missing helper'), { code: 'ENOENT' });
    });
    await expect(stripMediaMetadata(Buffer.from('synthetic media'), 'audio/mpeg')).rejects.not.toBeInstanceOf(
        EvidenceValidationError,
    );
});
