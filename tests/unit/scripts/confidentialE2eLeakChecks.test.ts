import { generateFirmIdentity, exportFirmIdentity, generateFirmRecoveryCode } from '../../../lib/confidential/firmKey';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { encodeRecoveryCodeV2, formatRecoveryCode } from '../../../enclave/src/confidential/recoveryCode';
import { recoveryFileText } from '../../../lib/confidential/recoveryFile';
import { leakedSecrets, recordTraffic, recoveryCodeForms, recoveryFileSecrets, organizationKeyFileSecrets } from '../../../qa/e2e/support/leaks';

// The click-through suite's "the host saw only ciphertext" checks are only as
// good as what they record and what they look for. These guard both.

type FakeRequest = { url: string; headers?: Record<string, string>; body?: string };
function request(input: FakeRequest) {
  return {
    url: () => input.url,
    headers: () => input.headers ?? {},
    postDataBuffer: () => (input.body === undefined ? null : Buffer.from(input.body, 'utf8')),
  };
}

async function sampleReport() {
  const secret = new Uint8Array(randomBytes(32));
  const recoveryCode = formatRecoveryCode(await encodeRecoveryCodeV2(secret));
  const recoveryFile = recoveryFileText({ recoveryCode, recoveryPackage: '{"format":"vera-owner-recovery/v2","ciphertext":"AAAA"}' });
  return { recoveryCode, recoveryFile, secret: Buffer.from(secret) };
}

describe('recordTraffic', () => {
  it('records URLs, headers and bodies', () => {
    const page = new EventEmitter();
    const seen = recordTraffic(page as never);
    page.emit('request', request({ url: 'https://vera.test/a?x=1', headers: { 'x-reporter-credential': 'HEADER-SECRET-VALUE' }, body: 'BODY-SECRET-VALUE' }));
    expect(leakedSecrets(seen, ['https://vera.test/a?x=1', 'HEADER-SECRET-VALUE', 'BODY-SECRET-VALUE'])).toHaveLength(3);
  });

  it('records a whole browser context into a shared log, pages opened later included', () => {
    const host: string[] = [];
    const reporter = new EventEmitter(), steward = new EventEmitter();
    recordTraffic(reporter as never, host);
    recordTraffic(steward as never, host);
    // Requests from any page of a context surface on the context.
    steward.emit('request', request({ url: 'https://vera.test/legal', body: 'SENTINEL-FIRM-MESSAGE in the clear' }));
    reporter.emit('request', request({ url: 'https://vera.test/status' }));
    expect(leakedSecrets(host, ['SENTINEL-FIRM-MESSAGE'])).toEqual(['SENTINEL-FIRM-MESSAGE']);
  });
});

describe('recovery code leak checks', () => {
  it('finds the code in any case, with or without separators, in a header', async () => {
    const { recoveryCode, recoveryFile } = await sampleReport();
    const secrets = recoveryFileSecrets(recoveryFile, recoveryCode);
    const bare = recoveryCode.replace(/-/g, '');
    for (const sent of [recoveryCode, recoveryCode.toLowerCase(), bare, bare.toLowerCase(), recoveryCode.replace(/-/g, ' ')]) {
      const page = new EventEmitter();
      const traffic = recordTraffic(page as never);
      page.emit('request', request({ url: 'https://vera.test/api/whistleblower/status/x', headers: { 'X-Reporter-Credential': sent } }));
      expect(leakedSecrets(traffic, secrets).length).toBeGreaterThan(0);
    }
  });

  it('finds the decoded secret as hex, base64 and base64url, and the file itself', async () => {
    const { recoveryCode, recoveryFile, secret } = await sampleReport();
    const secrets = recoveryFileSecrets(recoveryFile, recoveryCode);
    for (const sent of [secret.toString('hex'), secret.toString('hex').toUpperCase(), secret.toString('base64'), secret.toString('base64url'), recoveryFile]) {
      expect(leakedSecrets([`{"value":"${sent}"}`], secrets).length).toBeGreaterThan(0);
    }
    // Raw secret bytes in a binary body (bodies are recorded as latin1).
    const page = new EventEmitter();
    const traffic = recordTraffic(page as never);
    page.emit('request', { url: () => 'https://vera.test/upload', headers: () => ({}), postDataBuffer: () => Buffer.concat([Buffer.from([1, 2]), secret]) });
    expect(leakedSecrets(traffic, secrets).length).toBeGreaterThan(0);
  });

  it('does not flag the encrypted backup line the host already stores', async () => {
    const { recoveryCode, recoveryFile } = await sampleReport();
    const backup = recoveryFile.split('\n').find(line => line.startsWith('{"format"'))!;
    expect(leakedSecrets([backup], recoveryFileSecrets(recoveryFile, recoveryCode))).toEqual([]);
  });

  it('covers other codes too (organization key recovery code, passphrases)', () => {
    const forms = recoveryCodeForms('VERA-FIRM-1.abcdefghijklmnop-qrst');
    expect(leakedSecrets(['vera-firm-1.abcdefghijklmnop-qrst'], forms)).toHaveLength(1);
    expect(leakedSecrets(['VERAFIRM1.ABCDEFGHIJKLMNOPQRST'], forms)).toHaveLength(1);
  });
});

test('an unencrypted organization key file is not accepted as a key file', async () => {
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const file = 'PRIVATE\n' + JSON.stringify({ format: 'vera-firm-private-key/v1', privateKey: firm.privateKey.armor(), domain: 'counsel.example' });
  await expect(organizationKeyFileSecrets(file, '')).rejects.toThrow();
  await expect(organizationKeyFileSecrets(file, generateFirmRecoveryCode())).rejects.toThrow();
});

test('encrypted organization backups still guard the decrypted key and recovery code', async () => {
  const firm = await generateFirmIdentity({ organizationId: 'a'.repeat(64), domain: 'counsel.example' });
  const code = generateFirmRecoveryCode();
  const file = await exportFirmIdentity(firm, code);
  const privateKey = firm.privateKey.armor();
  const secrets = await organizationKeyFileSecrets(file, code);
  for (const sent of [file, privateKey, JSON.stringify({ key: privateKey }), encodeURIComponent(privateKey), code, code.toLowerCase()]) {
    expect(leakedSecrets([sent], secrets).length).toBeGreaterThan(0);
  }
  expect(leakedSecrets(['counsel.example'], secrets)).toEqual([]);
  await expect(organizationKeyFileSecrets(file, 'incorrect-passphrase')).rejects.toThrow();
});

describe('the confidential journey sweeps every participant', () => {
  const spec = readFileSync('qa/e2e/specs/confidential-journey.spec.ts', 'utf8');

  it('records the firm side (steward, lawyer, onboarding operator) and the reporter into the host log', () => {
    for (const context of ['steward', 'associate', 'context', 'ownerDevice']) {
      expect(spec).toMatch(new RegExp(`recordTraffic\\(${context}, hostTraffic\\)`));
    }
    // The reporter's submission is checked and then added to the same log.
    expect(spec).toMatch(/hostTraffic\.push\(\.\.\.traffic\)/);
  });

  it('forbids the recovery file, organization key files and codes, and device codes', () => {
    expect(spec).toMatch(/recoveryFileSecrets\(journey\.report\.recoveryFile, journey\.report\.recoveryCode\)/);
    expect(spec).toMatch(/keepPrivate\(\.\.\.await organizationKeyFileSecrets\(journey\.firmKeyFile, journey\.firmCode\)\)/);
    expect(spec).toMatch(/keepPrivate\(\.\.\.await organizationKeyFileSecrets\(keyFile, code\)\)/);
    expect(spec).toMatch(/deviceSecrets\.push\(code\)/);
    expect(spec).toMatch(/leakedSecrets\(hostTraffic, sweptFromHost\(\[\.\.\.SENTINELS, \.\.\.deviceSecrets\]\)\)/);
  });

  it('checks recovery secrets in the submit, restore and phone flows', () => {
    for (const name of ['smoke', 'owner-mobile', 'release-update']) {
      expect(readFileSync(`qa/e2e/specs/${name}.spec.ts`, 'utf8')).toMatch(/recoveryFileSecrets\(report\.recoveryFile, report\.recoveryCode\)/);
    }
  });
});

describe('the two-organization spec sweeps every participant', () => {
  const spec = readFileSync('qa/e2e/specs/confidential-two-firms.spec.ts', 'utf8');
  const firm = readFileSync('qa/e2e/support/firm.ts', 'utf8');

  it('records both organizations, the operator, the submitting reporter and both owner devices', () => {
    // Stewards and the onboarding operator are recorded by the shared firm helper.
    expect(firm.match(/recordTraffic\(context, watch\.traffic\)/g)).toHaveLength(2);
    expect(spec).toMatch(/recordTraffic\(ownerDevice, hostTraffic\)/);
    expect(spec).toMatch(/recordTraffic\(context, hostTraffic\)/);
    expect(spec).toMatch(/hostTraffic\.push\(\.\.\.traffic\)/);
  });

  it('forbids the recovery file and every organization key file and code', () => {
    expect(spec).toMatch(/recoveryFileSecrets\(report\.recoveryFile, report\.recoveryCode\)/);
    expect(firm).toMatch(/keepPrivate\(watch, \.\.\.await organizationKeyFileSecrets\(keyFile, code\)\)/);
    expect(spec).toMatch(/leakedSecrets\(hostTraffic, sweptFromHost\(\[\.\.\.SENTINELS, \.\.\.watch\.deviceSecrets\]\)\)/);
  });
});
