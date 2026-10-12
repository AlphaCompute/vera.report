import { logger } from '../../../src/utils/logger';
it.each(['json', 'text'])('redacts nested and interpolated capabilities in %s logs', format => {
  const old = { ...process.env };
  process.env.LOG_LEVEL = 'info'; process.env.LOG_FORMAT = format;
  const log = jest.spyOn(console, 'log').mockImplementation(() => {});
  const code = 'VRC-' + 'A'.repeat(64), id = 'VRA-' + 'B'.repeat(16);
  try {
    logger.info(`Case ${id} ${code}`, { nested: [id, code, new Error(code)], description: 'PRIVATE' });
    const written = JSON.stringify(log.mock.calls);
    expect(written).toContain('REDACTED');
    for (const secret of [id, code, 'PRIVATE']) expect(written).not.toContain(secret);
  } finally { process.env = old; log.mockRestore(); }
});
