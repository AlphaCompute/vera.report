/** Run as a separate, isolated service. No HTTP signing endpoint. */
import { readFile, mkdir, readdir, open, link, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { readKey } from '../enclave/src/confidential/pgp';
import { importFirmIdentity } from '../lib/confidential/firmKey';
import { combinedApprovalWorker, failureReason } from './lib/combinedApprovalWorker';
import { legalApplicationProvisioner } from '../src/services/legalApplicationAuth0';
import { LegalApplicationSocketWorker, legalApplicationSocketSettings } from '../src/services/legalApplicationSocket';
import { projectLegalApplication } from '../src/utils/legalApplications';

let stage: 'settings' | 'authority-secret' | 'authority-key' | 'authority-pin' | 'identity' | 'journal' | 'socket' = 'settings';
async function main() {
  if (process.argv.slice(2).some(argument => argument !== '--check')) throw new Error();
  const env = process.env;
  const settings = legalApplicationSocketSettings(env);
  const endpoint = new URL(env.LEGAL_APPROVAL_BACKEND_URL || '');
  if (!settings?.botToken || !env.LEGAL_APPROVAL_BACKEND_SECRET || env.LEGAL_APPROVAL_BACKEND_SECRET.length < 32 ||
      [env.CONFIDENTIAL_ADMIN_SECRET, env.INTERNAL_API_SECRET, env.LEGAL_AUTH0_ENTRY_SECRET, env.LEGAL_AUTH0_MGMT_CLIENT_SECRET].includes(env.LEGAL_APPROVAL_BACKEND_SECRET) ||
      !env.LEGAL_APPROVAL_KEY_FILE || !env.LEGAL_APPROVAL_PUBLIC_KEY_FILE || !env.LEGAL_APPROVAL_ONBOARDING_PUBLIC_KEY_FILE ||
      Number(!!env.LEGAL_APPROVAL_PASSPHRASE_FILE) + Number(!!env.LEGAL_APPROVAL_PASSPHRASE_DPAPI_FILE) !== 1 ||
      !env.LEGAL_APPROVAL_JOURNAL || !env.LEGAL_APPROVAL_IDENTITY_FILE || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      !(endpoint.protocol === 'https:' || endpoint.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(endpoint.hostname))) throw new Error();
  // DPAPI is only a local Windows option. Capture the secret in this isolated
  // process; never write plaintext to disk, logs or the web backend environment.
  stage = 'authority-secret';
  if (env.LEGAL_APPROVAL_PASSPHRASE_DPAPI_FILE && process.platform !== 'win32') throw new Error();
  const dpapiEnv = { ...env };
  // A PowerShell 7 launcher can otherwise point Windows PowerShell 5 at
  // incompatible security modules. Let that subprocess use its own defaults.
  for (const key of Object.keys(dpapiEnv)) if (key.toLowerCase() === 'psmodulepath') delete dpapiEnv[key];
  const passphrase = env.LEGAL_APPROVAL_PASSPHRASE_FILE
    ? (await readFile(env.LEGAL_APPROVAL_PASSPHRASE_FILE, 'utf8')).trim()
    : execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '$ErrorActionPreference="Stop"; $protected=Get-Content -Raw -LiteralPath $env:LEGAL_APPROVAL_PASSPHRASE_DPAPI_FILE; $value=ConvertTo-SecureString $protected; $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($value); try { [Console]::Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }'],
      { env: dpapiEnv, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000 });
  stage = 'authority-key';
  const authority = (await importFirmIdentity(await readFile(env.LEGAL_APPROVAL_KEY_FILE, 'utf8'), passphrase)).privateKey;
  stage = 'authority-pin';
  const pinned = await readKey({ armoredKey: await readFile(env.LEGAL_APPROVAL_PUBLIC_KEY_FILE, 'utf8') });
  if (pinned.isPrivate() || pinned.getFingerprint() !== authority.getFingerprint()) throw new Error();
  if (!env.LEGAL_APPROVAL_ONBOARDING_PUBLIC_KEY_FILE) throw new Error();
  const administrator = await readKey({ armoredKey: await readFile(env.LEGAL_APPROVAL_ONBOARDING_PUBLIC_KEY_FILE, 'utf8') });
  if (administrator.isPrivate() || administrator.getFingerprint() === pinned.getFingerprint()) throw new Error();
  stage = 'identity';
  const provider = legalApplicationProvisioner(env, JSON.parse(await readFile(env.LEGAL_APPROVAL_IDENTITY_FILE, 'utf8')));
  if (!provider) throw new Error();
  if (process.argv.includes('--check')) {
    console.info('Combined approval worker configuration and authority pin verified; no connections opened');
    return;
  }
  stage = 'journal';
  const directory = resolve(env.LEGAL_APPROVAL_JOURNAL);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  async function exclusive(name: string, bytes: string) {
    const path = resolve(directory, name);
    const temporary = resolve(directory, `${randomUUID()}.tmp`);
    const handle = await open(temporary, 'wx', 0o600);
    try {
      try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
      try { await link(temporary, path); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      return await readFile(path, 'utf8');
    } finally { await unlink(temporary); }
  }
  const request = async (action: string, body: unknown) => {
    const response = await fetch(`${endpoint.href.replace(/\/$/, '')}/api/internal/legal-approval/${action}`, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'Content-Type': 'application/json', 'x-internal-secret': env.LEGAL_APPROVAL_BACKEND_SECRET! }, body: JSON.stringify(body) });
    if (response.status === 409) return { success: false, status: 409 };
    if (!response.ok) throw Object.assign(new Error(), { status: response.status });
    return response.json();
  };
  const backend = {
    get: async (id: string) => projectLegalApplication((await request('get', { id })).application),
    decide: async (decision: Parameters<ReturnType<typeof combinedApprovalWorker>['decide']>[0]) => (await request('decide', decision)).success === true,
    publish: async (id: string, digest: string, approval: string) => {
      const result = await request('combined-approval', { id, digest, approval });
      if (!result.success) throw Object.assign(new Error(), { status: result.status });
    },
  };
  const worker = combinedApprovalWorker({ authority, backend, provider, journal: {
    record: (id, wire) => exclusive(`${id}.review.json`, wire),
    entries: async () => {
      const files = new Set(await readdir(directory));
      return Promise.all([...files].filter(name => /^[a-f0-9]{64}\.review\.json$/.test(name) && !files.has(name.replace('.review.json', '.complete')))
        .map(name => readFile(resolve(directory, name), 'utf8')));
    },
    saveApproval: (id, wire) => exclusive(`${id}.approval.json`, wire),
    complete: async (id, outcome = 'published') => { await exclusive(`${id}.complete`, outcome); },
  } });
  stage = 'socket';
  const socket = new LegalApplicationSocketWorker({ settings, decide: worker.decide, getApplication: backend.get,
    onStatus: status => console.info('Approval socket', status) });
  let running: Promise<void> | null = null;
  const poll = () => { if (!running) running = worker.provision().catch((error: { failures?: string[] }) =>
    console.warn('Approval provisioning will retry', error?.failures ?? [failureReason(error)])).finally(() => { running = null; }); };
  const timer = setInterval(poll, 15000);
  socket.start(); poll();
  const stop = async () => { clearInterval(timer); await socket.stop(); await running; process.exit(0); };
  process.once('SIGINT', () => void stop()); process.once('SIGTERM', () => void stop());
}
void main().catch(() => { console.error('Combined approval worker startup failed:', stage); process.exitCode = 1; });
