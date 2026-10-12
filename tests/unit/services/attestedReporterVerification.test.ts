import { AttestedReporterVerification, configuredAttestedReporterVerification, type ReporterVerificationStorage } from '../../../src/services/attestedReporterVerification';
import type { AttestedVerificationReaderOptions } from '../../../src/services/attestedReportVerificationReader';
const code = 'VRC-' + 'A'.repeat(64), trackingId = 'VRA-0123456789ABCDEF';
const settings = { pythonExecutable: '/explicit/python', moduleRoot: '/explicit/runtime', port: 15003,
  keyArn: 'arn:aws:kms:us-east-2:000000000000:key/12345678-1234-1234-1234-123456789012',
  pcrs: { '0': '11'.repeat(48), '1': '22'.repeat(48), '2': '33'.repeat(48) }, credentials: jest.fn() };
function setup(value: unknown = { credibilityScore: 80, category: 'fraud', narrative: 'private-sentinel', trackingId }) {
  const loader = jest.fn(async () => ({ trackingId, verification: 'encrypted' }));
  const storage: ReporterVerificationStorage = { resolveAttestedReporterTrackingId: jest.fn(async () => trackingId), createReporterVerificationLoader: jest.fn(() => loader) };
  const reader = { read: jest.fn(async () => value), close: jest.fn(async () => {}) };
  const factory = jest.fn((_options: AttestedVerificationReaderOptions) => reader);
  return { service: new AttestedReporterVerification(storage, settings, factory), storage, reader, factory };
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
afterEach(() => jest.useRealTimers());
it('projects only score/category, resolving the code before constructing the authorized reader', async () => {
  const { service, storage, reader, factory } = setup();
  expect(await service.read(code, new AbortController().signal)).toEqual({ credibilityScore: 80, category: 'fraud' });
  expect(storage.resolveAttestedReporterTrackingId).toHaveBeenCalledWith(code, expect.any(AbortSignal));
  expect(storage.createReporterVerificationLoader).toHaveBeenCalledWith(code);
  expect(reader.read).toHaveBeenCalledWith(trackingId); expect(reader.close).toHaveBeenCalledTimes(1);
  expect(factory.mock.calls[0][0].loadAuthorized).toBeDefined(); await service.close();
});
it('missing or invalid modern credentials never construct a reader', async () => {
  const { service, storage, factory } = setup();
  (storage.resolveAttestedReporterTrackingId as jest.Mock).mockResolvedValue(null);
  expect(await service.read(code, new AbortController().signal)).toBeNull();
  await expect(service.read(trackingId, new AbortController().signal)).rejects.toThrow('Report verification unavailable');
  expect(factory).not.toHaveBeenCalled(); await service.close();
});
it.each([null, [], { credibilityScore: -1, category: 'fraud' }, { credibilityScore: 101, category: 'fraud' },
  { credibilityScore: NaN, category: 'fraud' }, { credibilityScore: 80, category: '<private>' }])('fails closed for an invalid projection', async value => {
  const { service, reader } = setup(value);
  await expect(service.read(code, new AbortController().signal)).rejects.toThrow(/^Report verification unavailable$/);
  expect(reader.close).toHaveBeenCalledTimes(1); await service.close();
});
it('holds admission through child drain after a peer disconnect; then allows a fresh read', async () => {
  const { service, reader, factory } = setup(); let rejectRead!: (reason: Error) => void, release!: () => void;
  reader.read.mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectRead = reject; }));
  const drained = new Promise<void>(resolve => { release = resolve; });
  reader.close.mockImplementation(() => { rejectRead(new Error('private-error')); return drained; });
  const controller = new AbortController(); const pending = service.read(code, controller.signal).catch(e => e);
  await tick(); controller.abort(); await tick();
  await expect(service.read(code, new AbortController().signal)).rejects.toThrow('Report verification unavailable');
  expect(factory).toHaveBeenCalledTimes(1); release(); expect((await pending).message).toBe('Report verification unavailable');
  reader.close.mockResolvedValue(); expect(await service.read(code, new AbortController().signal)).toEqual({ credibilityScore: 80, category: 'fraud' });
  await service.close();
});
it('shutdown cancels slow binding lookup without later constructing a reader', async () => {
  const { service, storage, factory } = setup(); let release!: (id: string) => void;
  (storage.resolveAttestedReporterTrackingId as jest.Mock).mockImplementation(() => new Promise(resolve => { release = resolve; }));
  const pending = service.read(code, new AbortController().signal).catch(e => e); await tick(); await service.close();
  expect((await pending).message).toBe('Report verification unavailable'); release(trackingId); await tick();
  expect(factory).not.toHaveBeenCalled(); await expect(service.read(code, new AbortController().signal)).rejects.toThrow();
});
it('outer deadline aborts binding lookup and never continues late credential work', async () => {
  jest.useFakeTimers(); const { service, storage, factory } = setup();
  (storage.resolveAttestedReporterTrackingId as jest.Mock).mockImplementation(() => new Promise(() => {}));
  const pending = service.read(code, new AbortController().signal).catch(e => e);
  await jest.advanceTimersByTimeAsync(25_000); expect((await pending).message).toBe('Report verification unavailable');
  expect(factory).not.toHaveBeenCalled(); await service.close();
});
it('flag defaults off without consulting credential/config inputs, and invalid enabled settings fail closed', async () => {
  const { storage } = setup();
  expect(configuredAttestedReporterVerification({} as NodeJS.ProcessEnv, storage)).toBeUndefined();
  expect(configuredAttestedReporterVerification({ ATTESTED_REPORTER_VERIFICATION_ENABLED: 'false' } as NodeJS.ProcessEnv, storage)).toBeUndefined();
  for (const value of ['TRUE', '1', 'true']) expect(() => configuredAttestedReporterVerification({ ATTESTED_REPORTER_VERIFICATION_ENABLED: value } as NodeJS.ProcessEnv, storage)).toThrow();
});
