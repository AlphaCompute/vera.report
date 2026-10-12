const { spawn, execFileSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

// stunnel transports HTTP (including streaming bodies and WebSockets) without
// parsing application data. Only the last, in-container loopback hop is cleartext.
// ALB encrypts its target connections but does not validate target certificates.
function start(command, args, env = process.env) {
  const port = Number(env.TLS_PORT);
  const upstream = Number(env.TLS_UPSTREAM_PORT);
  if (!command || ![port, upstream].every(p => Number.isInteger(p) && p > 1024 && p < 65536) || port === upstream) {
    throw new Error('TLS_PORT and TLS_UPSTREAM_PORT must be distinct unprivileged ports');
  }
  const directory = mkdtempSync(join(tmpdir(), 'vera-tls-'));
  const key = join(directory, 'key.pem');
  const cert = join(directory, 'cert.pem');
  const config = join(directory, 'stunnel.conf');
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365',
      '-subj', '/CN=vera-internal', '-keyout', key, '-out', cert], { stdio: 'ignore' });
    writeFileSync(config, `foreground = yes\npid =\ndebug = warning\n[TLS]\naccept = 0.0.0.0:${port}\nconnect = 127.0.0.1:${upstream}\ncert = ${cert}\nkey = ${key}\nsslVersionMin = TLSv1.2\n`, { mode: 0o600 });
  } catch (error) {
    rmSync(directory, { recursive: true, force: true });
    throw error;
  }
  const children = [spawn('stunnel', [config], { stdio: 'inherit' }), spawn(command, args, { stdio: 'inherit', env })];
  let stopping = false;
  let exitCode = 0;
  let remaining = children.length;
  let deadline;
  function stop(code, signal = 'SIGTERM') {
    if (stopping) return;
    stopping = true;
    exitCode = code;
    for (const child of children) child.kill(signal);
    deadline = setTimeout(() => { for (const child of children) child.kill('SIGKILL'); }, 10000);
    deadline.unref();
  }
  for (const child of children) {
    child.on('error', () => stop(1));
    child.on('close', (code) => {
      // An unexpected exit of either process must terminate the container.
      stop(code || 1);
      if (--remaining === 0) {
        clearTimeout(deadline);
        rmSync(directory, { recursive: true, force: true });
        process.exit(exitCode);
      }
    });
  }
  process.on('SIGTERM', () => stop(0));
  process.on('SIGINT', () => stop(0, 'SIGINT'));
  return { stop };
}

if (require.main === module) start(process.argv[2], process.argv.slice(3));
module.exports = { start };
