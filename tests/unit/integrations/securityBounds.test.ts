import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

test('inbound MIME caps the scan without dropping the message and still extracts ordinary text', () => {
  execFileSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { extractTextBody, TRUNCATED_MIME_BODY } from './aws/lambda/dissemination-inbound-relay/index.mjs';
    const headers = 'Content-Type: multipart/mixed; boundary="x"\\r\\n\\r\\n';
    const text = '--x\\r\\nContent-Type: text/plain\\r\\n\\r\\nhello\\r\\n--x--';
    assert.equal(extractTextBody(headers + text), 'hello');
    assert.equal(extractTextBody(headers + '--x'.repeat(300) + text), TRUNCATED_MIME_BODY);
    assert.equal(extractTextBody(headers + text + '--x'.repeat(300)), 'hello');
  `], { cwd: resolve('.'), stdio: 'pipe' });
});
