import { logger } from '../../../src/utils/logger';

describe('structured logger', () => {
  const env = { ...process.env };
  let log: jest.SpyInstance;
  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env.LOG_FORMAT;
    process.env.LOG_LEVEL = 'info';
    log = jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => { process.env = { ...env }; jest.restoreAllMocks(); });
  it('preserves the default argument list', () => {
    const context = { requestId: 'request-1' };
    logger.info('received', context);
    expect(log).toHaveBeenCalledWith('received', context);
  });
  it('emits a single parseable line with correlation fields and escaped newlines', () => {
    process.env.LOG_FORMAT = 'json';
    logger.info('received\nforged line', { requestId: 'request-1', endpoint: '/health' });
    const line = log.mock.calls[0][0];
    expect(line).not.toContain('\n');
    expect(JSON.parse(line)).toEqual({ timestamp: expect.any(String), level: 'info', message: 'received\nforged line', context: [{ requestId: 'request-1', endpoint: '/health' }] });
    expect(Number.isNaN(Date.parse(JSON.parse(line).timestamp))).toBe(false);
  });
  it('keeps level filtering and stderr routing', () => {
    process.env.LOG_FORMAT = 'json';
    process.env.LOG_LEVEL = 'error';
    logger.info('hidden'); logger.error('failed');
    expect(log).not.toHaveBeenCalled();
    expect(JSON.parse((console.error as jest.Mock).mock.calls[0][0]).level).toBe('error');
  });
  it('handles circular data, bigint and errors without throwing', () => {
    process.env.LOG_FORMAT = 'json';
    const obj: Record<string, unknown> = { count: BigInt(4) }; obj.self = obj;
    logger.warn('failed', obj, new Error('unavailable'));
    const event = JSON.parse((console.warn as jest.Mock).mock.calls[0][0]);
    expect(event.context[0]).toEqual({ count: '4', self: '[Circular]' });
    expect(event.context[1]).toMatchObject({ name: 'Error', message: 'unavailable' });
  });
  it('redacts sensitive structured fields and binary contents', () => {
    process.env.LOG_FORMAT = 'json';
    logger.info('event', { token: 'private', nested: { narrative: 'report' }, data: Buffer.from('secret') });
    const event = JSON.parse(log.mock.calls[0][0]);
    expect(event.context[0]).toEqual({ token: '[REDACTED]', nested: { narrative: '[REDACTED]' }, data: '[Binary data]' });
  });
  it('does not throw if context serialization fails', () => {
    process.env.LOG_FORMAT = 'json';
    logger.info('event', { toJSON() { throw new Error('bad'); } });
    expect(JSON.parse(log.mock.calls[0][0]).context).toBe('[Unserializable]');
  });
});
