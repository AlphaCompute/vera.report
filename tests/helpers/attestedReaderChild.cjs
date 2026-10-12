// Explicit synthetic process fixture. It never connects to a provider.
const mode = process.argv[2];
let input = '';
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const request = JSON.parse(input);
  if (process.cwd() !== require('node:fs').realpathSync(process.argv[3]) || request.trackingId !== 'VRA-1234567890ABCDEF' || request.credentials.secretAccessKey !== 'synthetic-secret' ||
      Object.keys(process.env).some(name => !['PATH', '__CF_USER_TEXT_ENCODING'].includes(name))) process.exit(3);
  if (mode === 'stderr') { process.stderr.write('synthetic-sensitive-diagnostic'); return; }
  if (mode === 'oversized') { process.stdout.write('x'.repeat(12 * 1024 * 1024 + 1)); return; }
  if (mode === 'malformed') { process.stdout.write('{"key":"forbidden"}'); return; }
  if (mode === 'invalid-utf8') { process.stdout.write(Buffer.from([0xff])); return; }
  if (mode === 'hanging') { setInterval(() => {}, 1000); return; }
  process.stdout.write('{"value":{"credibilityScore":80,"category":"synthetic"}}');
});
