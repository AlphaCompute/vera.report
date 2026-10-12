const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const https = require('node:https');
const tls = require('node:tls');

const image = process.env.TLS_TEST_IMAGE;
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

test('non-root TLS target carries HTTP and upgrades; fails closed on plaintext and child exit', { skip: !image, timeout: 60000 }, async () => {
  const name = `vera-tls-test-${process.pid}`;
  const app = `const http=require('http');const server=http.createServer((req,res)=>{if(req.url==='/exit'){res.end('bye');setTimeout(()=>process.exit(7),30);return;}res.writeHead(200,{'content-type':'application/octet-stream'});req.pipe(res);});server.on('upgrade',(req,socket,head)=>{socket.write('HTTP/1.1 101 Switching Protocols\\r\\nConnection: Upgrade\\r\\nUpgrade: test\\r\\n\\r\\n');if(head.length)socket.write(head);socket.pipe(socket);});server.listen(3001,'127.0.0.1');`;
  try {
    docker('run', '-d', '--name', name, '--user', 'appuser', '-e', 'TLS_PORT=3443', '-e', 'TLS_UPSTREAM_PORT=3001',
      '-p', '127.0.0.1::3443', '--entrypoint', 'node', image, '/app/start-tls.cjs', 'node', '-e', app);
    const port = Number(docker('port', name, '3443/tcp').split(':').pop());
    function request(path, body = Buffer.alloc(0)) {
      return new Promise((resolve, reject) => {
        const req = https.request({ host: '127.0.0.1', port, path, method: 'POST', rejectUnauthorized: false }, res => {
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
        });
        req.setTimeout(2000, () => req.destroy(new Error('request timed out')));
        req.on('error', reject);
        req.end(body);
      });
    }
    let ready = false;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { if ((await request('/')).status === 200) { ready = true; break; } } catch {}
      await pause(100);
    }
    assert.equal(ready, true, docker('logs', name));
    const payload = Buffer.alloc(128 * 1024, 0xa5);
    const response = await request('/upload?test=1', payload);
    assert.equal(response.status, 200);
    assert.deepEqual(response.body, payload);
    await new Promise((resolve, reject) => {
      const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false }, () => {
        socket.write('GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n');
      });
      let received = '';
      socket.setTimeout(3000, () => socket.destroy(new Error('upgrade timed out')));
      socket.on('error', reject);
      socket.on('data', chunk => {
        received += chunk.toString();
        if (received.includes('\r\n\r\n') && !received.includes('echo-payload')) socket.write('echo-payload');
        if (received.endsWith('echo-payload')) { socket.destroy(); resolve(); }
      });
    });
    await assert.rejects(new Promise((resolve, reject) => {
      const req = require('node:http').get({ host: '127.0.0.1', port }, resolve);
      req.setTimeout(2000, () => req.destroy(new Error('timeout')));
      req.on('error', reject);
    }));
    await request('/exit');
    for (let attempt = 0; attempt < 50 && docker('inspect', '-f', '{{.State.Running}}', name) === 'true'; attempt++) await pause(100);
    assert.equal(docker('inspect', '-f', '{{.State.ExitCode}}', name), '7');
  } finally {
    docker('rm', '-f', name);
  }
});
