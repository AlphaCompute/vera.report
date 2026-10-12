import { mediaScratchRoot } from '../../../src/services/mediaMetadata';
import * as fs from 'node:fs/promises';

jest.mock('node:fs/promises', () => ({ ...jest.requireActual('node:fs/promises'), statfs: jest.fn() }));
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const originalEnv = process.env.NODE_ENV;
afterEach(() => {
  Object.defineProperty(process, 'platform', platform);
  process.env.NODE_ENV = originalEnv;
  jest.resetAllMocks();
});
test('Linux uses only a verified memory mount, regardless of TMPDIR', async () => {
  Object.defineProperty(process, 'platform', { value: 'linux' });
  (fs.statfs as jest.Mock).mockResolvedValue({ type: 0x01021994 });
  expect(await mediaScratchRoot()).toBe('/dev/shm');
  expect(fs.statfs).toHaveBeenCalledWith('/dev/shm');
});
test('a disk-backed or missing memory mount fails closed', async () => {
  Object.defineProperty(process, 'platform', { value: 'linux' });
  (fs.statfs as jest.Mock).mockResolvedValue({ type: 0xef53 });
  await expect(mediaScratchRoot()).rejects.toThrow('tmpfs');
  (fs.statfs as jest.Mock).mockRejectedValue(new Error('missing'));
  await expect(mediaScratchRoot()).rejects.toThrow('missing');
});
test('production never falls back to a non-Linux temporary directory', async () => {
  Object.defineProperty(process, 'platform', { value: 'darwin' });
  process.env.NODE_ENV = 'production';
  await expect(mediaScratchRoot()).rejects.toThrow('Linux tmpfs');
});
