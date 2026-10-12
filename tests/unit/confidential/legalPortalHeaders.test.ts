// Response headers for the frontend, including the legal portal's report view.
test('every page is nosniff; legal portal pages send no referrer and are not cached', async () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const config = require('../../../next.config.js');
  const rules: { source: string; headers: { key: string; value: string }[] }[] = await config.headers();
  // The last matching rule wins for a repeated header key.
  const header = (source: string, key: string) => rules.filter(rule => rule.source === source)
    .map(rule => rule.headers.find(item => item.key === key)?.value).filter(Boolean).pop();
  expect(header('/:path*', 'X-Content-Type-Options')).toBe('nosniff');
  expect(header('/:path*', 'Content-Security-Policy')).toBe("frame-ancestors 'self'");
  expect(header('/legal/:path*', 'Referrer-Policy')).toBe('no-referrer');
  expect(header('/legal/:path*', 'Cache-Control')).toContain('no-store');
  expect(header('/legal', 'Referrer-Policy')).toBe('no-referrer');
});
