import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { validateEnvironment, validateEnvironmentStrict } from '../../../src/utils/env-validation';

const api: NodeJS.ProcessEnv = {
  NODE_ENV: 'test', RUN_MODE: 'api', MONGODB_URI: 'mongodb://127.0.0.1:27017', MONGODB_DB_NAME: 'synthetic',
  INTERNAL_API_SECRET: 'synthetic-internal-secret-with-32-characters', REWARD_ENCRYPTION_KEY: 'synthetic-reward-secret-with-32-characters',
  AT_REST_LOCAL_KEY: 'synthetic-at-rest-secret-with-32-characters', IPFS_STORAGE_BACKEND: 'local-enclave',
};
let saved: NodeJS.ProcessEnv;
beforeEach(() => { saved = process.env; });
afterEach(() => { process.env = saved; });

it('defaults to the API without messaging credentials', () => {
  process.env = { ...api };
  delete process.env.RUN_MODE;
  expect(validateEnvironment().isValid).toBe(true);
  process.env.RUN_MODE = 'bot';
  expect(validateEnvironment().isValid).toBe(false);
});

it('validates API and explicitly selected local storage configurations', () => {
  process.env = { ...api };
  expect(validateEnvironment().isValid).toBe(true);
  process.env.NODE_ENV = 'production';
  expect(validateEnvironment().errors).toContain('Local IPFS in production requires the ciphertext archive');
  process.env.IPFS_CIPHERTEXT_ARCHIVE_BUCKET = 'vera-prod-ciphertext';
  expect(validateEnvironment().errors).toContain('Local IPFS in production requires an explicit ENCLAVE_IPFS_URL');
  process.env.ENCLAVE_IPFS_URL = 'http://10.0.0.5:15002';
  expect(validateEnvironment().isValid).toBe(false);
  process.env.ENCLAVE_IPFS_URL = 'http://ipfs:15002';
  expect(validateEnvironment().errors.filter(e => /IPFS/.test(e))).toEqual([]);
  process.env.IPFS_CIPHERTEXT_ARCHIVE_TEST_ENDPOINT = 'http://127.0.0.1:4566';
  expect(validateEnvironment().errors.some(e => /non-production/.test(e))).toBe(true);
});

it('requires the local-enclave storage backend and no longer accepts Pinata', () => {
  process.env = { ...api };
  delete process.env.IPFS_STORAGE_BACKEND;
  expect(validateEnvironment().missingRequired).toEqual(['IPFS_STORAGE_BACKEND']);
  for (const backend of ['pinata', 'typo']) {
    process.env.IPFS_STORAGE_BACKEND = backend;
    expect(validateEnvironment().errors).toContain('IPFS_STORAGE_BACKEND must be local-enclave');
  }
  // A leftover Pinata credential is neither required nor sufficient.
  process.env = { ...api, PINATA_JWT: 'synthetic-pinata-token' };
  delete process.env.IPFS_STORAGE_BACKEND;
  expect(validateEnvironment().isValid).toBe(false);
});

it('requires no Midnight, wallet or relay configuration and ignores leftover settings', () => {
  process.env = { ...api };
  const result = validateEnvironment();
  expect(result).toMatchObject({ isValid: true, missingRequired: [], errors: [] });
  expect(result.missingOptional.filter(name => name.startsWith('MIDNIGHT_'))).toEqual([]);
  // Leftover Midnight and relay settings from older deployments are not checked.
  Object.assign(process.env, {
    MIDNIGHT_ENABLED: 'off', RELAY_ROLE: 'invalid', MIDNIGHT_NETWORK: 'retired', MIDNIGHT_RELAY_SEED: '00'.repeat(32),
    MIDNIGHT_RELAY_MNEMONIC: 'not a mnemonic', MIDNIGHT_EVIDENCE_PROTOCOL: 'v3', NULLIFIER_SEED: 'short', WALLET_ENCRYPTION_KEY: 'short',
  });
  expect(validateEnvironment()).toMatchObject({ isValid: true, missingRequired: [], errors: [] });
});

it('accepts KMS wrapping without a local master key and rejects malformed keys and protocols', () => {
  process.env = { ...api, KMS_AT_REST_KEY_ID: 'synthetic-kms-key' };
  delete process.env.AT_REST_LOCAL_KEY;
  expect(validateEnvironment().isValid).toBe(true);
  for (const invalid of [
    { INTERNAL_API_SECRET: 'too-short' }, { REWARD_ENCRYPTION_KEY: 'too-short' },
    { RUN_MODE: 'invalid' }, { FRONTEND_TRUST_PROXY_HOPS: 'all' },
  ]) {
    process.env = { ...api, ...invalid };
    expect(validateEnvironment().isValid).toBe(false);
  }
});

it('rejects invalid webhook configuration', () => {
  process.env = { ...api };
  expect(validateEnvironment().isValid).toBe(true);
  process.env.WEBHOOK_URL = 'https://example.invalid/webhook';
  expect(validateEnvironment().isValid).toBe(false);
  process.env.WEBHOOK_SECRET = 'synthetic-webhook-key';
  expect(validateEnvironment().isValid).toBe(true);
});

it('validates direct Slack without requiring n8n credentials', () => {
  process.env = { ...api, SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T/B/synthetic' };
  expect(validateEnvironment().missingRequired).toContain('SLACK_ADMIN_URL');
  process.env.SLACK_ADMIN_URL = 'https://staging.example.invalid/admin';
  expect(validateEnvironment().isValid).toBe(true);
  process.env.SLACK_WEBHOOK_URL = 'https://attacker.invalid/hook';
  expect(validateEnvironment().isValid).toBe(false);
});

it.each([undefined, 'false'])('allows production with confidential cases disabled (%s)', flag => {
  // Production local storage needs the S3 archive and an explicit Kubo origin.
  process.env = { ...api, NODE_ENV: 'production', IPFS_CIPHERTEXT_ARCHIVE_BUCKET: 'vera-prod-ciphertext', ENCLAVE_IPFS_URL: 'http://127.0.0.1:15002' };
  if (flag !== undefined) process.env.CONFIDENTIAL_CASES_ENABLED = flag;
  expect(validateEnvironment().isValid).toBe(true);
});

it('refuses confidential cases under NODE_ENV=production without a known DEPLOY_ENV, even when the old enclave flag is off', () => {
  process.env = { ...api, NODE_ENV: 'production', ENCLAVE_ENABLED: 'false', CONFIDENTIAL_CASES_ENABLED: 'true' };
  expect(validateEnvironment().errors).toContain('CONFIDENTIAL_CASES_ENABLED under NODE_ENV=production requires DEPLOY_ENV to be prod, staging or rehearsal');
  expect(() => validateEnvironmentStrict()).toThrow('CONFIDENTIAL_CASES_ENABLED');
});

it.each(['prod', 'staging', 'rehearsal'])('permits confidential cases on the %s stack under NODE_ENV=production', deployEnv => {
  process.env = { ...api, NODE_ENV: 'production', DEPLOY_ENV: deployEnv, CONFIDENTIAL_CASES_ENABLED: 'true' };
  expect(validateEnvironment().errors).not.toContain('CONFIDENTIAL_CASES_ENABLED under NODE_ENV=production requires DEPLOY_ENV to be prod, staging or rehearsal');
});

it.each(['development', 'test'])('permits isolated confidential tests in %s', environment => {
  process.env = { ...api, NODE_ENV: environment, CONFIDENTIAL_CASES_ENABLED: 'true' };
  expect(validateEnvironment().isValid).toBe(true);
});

it.each(['1', 'TRUE', '', ' true '])('rejects ambiguous confidential flags (%s)', flag => {
  process.env = { ...api, CONFIDENTIAL_CASES_ENABLED: flag };
  expect(validateEnvironment().errors).toContain('CONFIDENTIAL_CASES_ENABLED must be true or false');
});

it('the CLI loads local/fallback files with shell precedence and returns a failing exit status', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'vera-env-regression-'));
  const script = path.resolve('scripts/validate-env.ts');
  const args = [require.resolve('ts-node/dist/bin.js'), '--project', path.resolve('tsconfig.json'), script];
  try {
    const empty = spawnSync(process.execPath, args, { cwd: directory, env: { PATH: saved.PATH, NODE_ENV: 'test' }, encoding: 'utf8' });
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain('MONGODB_URI');
    writeFileSync(path.join(directory, '.env'), Object.entries(api).map(([key, value]) => `${key}=${value}`).join('\n'));
    writeFileSync(path.join(directory, '.env.local'), 'REWARD_ENCRYPTION_KEY=invalid-local-key\n');
    const invalidFile = spawnSync(process.execPath, args, { cwd: directory, env: { PATH: saved.PATH }, encoding: 'utf8' });
    expect(invalidFile.status).toBe(1);
    expect(invalidFile.stderr).toContain('REWARD_ENCRYPTION_KEY');
    const valid = spawnSync(process.execPath, args, { cwd: directory, env: { PATH: saved.PATH, REWARD_ENCRYPTION_KEY: api.REWARD_ENCRYPTION_KEY }, encoding: 'utf8' });
    expect(valid.status).toBe(0);
    expect(valid.stdout + valid.stderr).not.toContain(api.REWARD_ENCRYPTION_KEY);
    expect(valid.stdout + valid.stderr).not.toContain(api.INTERNAL_API_SECRET);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}, 30_000);
