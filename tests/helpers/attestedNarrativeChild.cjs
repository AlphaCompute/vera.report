'use strict';
const mode = process.argv[2];
let input = '';
process.stdin.on('data', (b) => (input += b));
process.stdin.on('end', () => {
    const r = JSON.parse(input);
    if (mode === 'hang') return setInterval(() => {}, 1000);
    if (mode === 'stderr') {
        process.stderr.write('private-error');
        return;
    }
    if (mode === 'malformed') return process.stdout.write('not-json');
    if (mode === 'large') return process.stdout.write('x'.repeat(12 * 1024 * 1024 + 1));
    if (r.operation === 'decrypt' && mode === 'invalid-base64') return process.stdout.write(JSON.stringify({ value: 'AB==' }));
    if (r.operation === 'decrypt' && mode === 'invalid-utf8') return process.stdout.write(JSON.stringify({ value: '/w==' }));
    const value =
        r.operation === 'encrypt'
            ? {
                  format: 'recipient-narrative:v1',
                  trackingId: r.trackingId,
                  purpose: 'narrative',
                  key: 'enc:kms:recipient:v1:' + Buffer.from('test-wrapper').toString('base64'),
                  iv: Buffer.alloc(12).toString('base64'),
                  tag: Buffer.alloc(16).toString('base64'),
                  data: Buffer.from('test-ciphertext').toString('base64'),
              }
            : mode === 'control-output' ? '\u0000'.repeat(8 * 1024 * 1024) : 'offline narrative';
    process.stdout.write(JSON.stringify({ value: r.operation === 'decrypt' ? Buffer.from(value, 'utf8').toString('base64') : value }));
});
