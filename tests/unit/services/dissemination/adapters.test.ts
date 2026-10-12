jest.mock('../../../../src/services/dissemination/packetEvidence', () => ({ exportPacketArchive: jest.fn().mockResolvedValue(Buffer.from('ZIP-with-evidence')) }));
/**
 * Adapter tests: dryrun mode routing, MIME rendering, receipt parsing,
 * and the Psst Stage-1 deep-link handoff.
 */

import { EmailAdapter, disseminationMode } from '../../../../src/services/dissemination/adapters/emailAdapter';
import { cisaAdapter } from '../../../../src/services/dissemination/adapters/cisa';
import { gaoFraudnetAdapter } from '../../../../src/services/dissemination/adapters/gaoFraudnet';
import { epaOigAdapter } from '../../../../src/services/dissemination/adapters/epaOig';
import { psstSafeAdapter } from '../../../../src/services/dissemination/adapters/psstSafe';
import { securedropAdapter } from '../../../../src/services/dissemination/adapters/securedrop';
import { getAdapter, hasAdapter } from '../../../../src/services/dissemination/adapters/registry';
import type { DisseminationView, Packet } from '../../../../src/services/dissemination/types';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';

function makeView(): DisseminationView {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    categories: ['cyber-security'],
    rawCategories: ['cyber-security'],
    narrative: 'Narrative summary of the incident.',
    urgency: 'high',
    evidence: {
      evidenceHash: 'e'.repeat(64),
      files: [{ name: 'evidence.pdf', cid: 'QmFileCid' }],
    },
    zkProof: {
      proofHash: '0xproofhash',
      txHash: '0xtxhash',
      verified: true,
    },
  };
}

function makePacket(entityId: string): Packet {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    entityId,
    packetVersion: 1,
    pdf: Buffer.from('%PDF-1.7 fake pdf body'),
    sidecar: {
      schema: 'vera-packet/1.0',
      trackingId: 'VRA-ABCDEF0123456789',
      entityId,
      packetVersion: 1,
      generatedAt: new Date().toISOString(),
      categories: [{ slug: 'cyber-security', label: 'Cyber security' }],
      narrative: 'Narrative summary of the incident.',
      evidenceManifest: { files: [], escrowStatement: 'escrowed' },
      transmittalStatement: 'transmitted with consent',
    },
    packetHash: 'f'.repeat(64),
    generatedAt: new Date(),
  };
}

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe('dissemination mode (safety switch)', () => {
  it('defaults to dryrun', () => {
    delete process.env.DISSEMINATION_MODE;
    expect(disseminationMode()).toBe('dryrun');
  });

  it('only goes live on the explicit value', () => {
    process.env.DISSEMINATION_MODE = 'live';
    expect(disseminationMode()).toBe('live');
    process.env.DISSEMINATION_MODE = 'anything-else';
    expect(disseminationMode()).toBe('dryrun');
  });
});

describe('email adapter (Tier A base)', () => {
  it('routes to the internal inbox with a [DRYRUN] marker in dryrun mode', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    process.env.DISSEMINATION_DRYRUN_INBOX = 'internal@vera.test';

    const prep = await cisaAdapter.prepare(makeView(), makePacket('cisa'));
    expect(prep.email?.to).toBe('internal@vera.test');
    expect(prep.email?.subject).toContain('[DRYRUN]');
  });

  it('targets the real agency intake only in live mode', async () => {
    process.env.DISSEMINATION_MODE = 'live';
    const prep = await cisaAdapter.prepare(makeView(), makePacket('cisa'));
    expect(prep.email?.to).toBe('contact@mail.cisa.dhs.gov');
    expect(prep.email?.subject).not.toContain('[DRYRUN]');
  });

  it('refuses to dispatch in dryrun without an inbox configured', async () => {
    process.env.DISSEMINATION_MODE = 'dryrun';
    delete process.env.DISSEMINATION_DRYRUN_INBOX;

    const prep = await cisaAdapter.prepare(makeView(), makePacket('cisa'));
    await expect(cisaAdapter.dispatch(prep)).rejects.toThrow(/DISSEMINATION_DRYRUN_INBOX/);
  });

  it('attaches the report ZIP and JSON sidecar', async () => {
    process.env.DISSEMINATION_MODE = 'live';

    const prep = await gaoFraudnetAdapter.prepare(makeView(), makePacket('gao-fraudnet'));
    const filenames = prep.email!.attachments.map((a) => a.filename);
    expect(filenames).toEqual([
      'vera-report-VRA-ABCDEF0123456789.zip',
      'vera-packet-VRA-ABCDEF0123456789.json',
    ]);
    expect(prep.email!.coverLetter).toContain('VRA-ABCDEF0123456789');
    expect(prep.email!.coverLetter).toContain('decryption keys are not included');
    expect(prep.email!.coverLetter).toContain('0xproofhash');
  });

  it('renders valid multipart MIME with base64 attachments', async () => {
    // Live route with an audited plaintext exception: the only cleartext path.
    process.env.DISSEMINATION_MODE = 'live';
    process.env.DISSEMINATION_EMAIL_POLICIES = JSON.stringify({
      'contact@mail.cisa.dhs.gov': { allowUnencrypted: true, reason: 'Synthetic test exception' },
    });
    const audit = jest.spyOn(disseminationPersistence, 'appendAudit').mockResolvedValue(undefined);

    const adapter = cisaAdapter as EmailAdapter;
    const prep = await adapter.prepare(makeView(), makePacket('cisa'));
    const mime = Buffer.from(await adapter.buildMime('sender@vera.test', prep.email!, 'VRA-ABCDEF0123456789')).toString('utf8');
    audit.mockRestore();

    expect(mime).toContain('From: sender@vera.test');
    expect(mime).toContain('To: contact@mail.cisa.dhs.gov');
    expect(mime).toContain('Content-Type: multipart/mixed; boundary=');
    expect(mime).toContain('Content-Transfer-Encoding: quoted-printable');
    expect(mime).toContain('Content-Disposition: attachment; filename="vera-report-VRA-ABCDEF0123456789.zip"');

    // The ZIP payload round-trips through the base64 section.
    const b64Section = mime.split('Content-Transfer-Encoding: base64')[1];
    expect(b64Section.replace(/[\r\n-]/g, '')).toContain(
      Buffer.from('ZIP-with-evidence').toString('base64'),
    );

    // Closing boundary present
    const boundary = mime.match(/boundary="([^"]+)"/)![1];
    expect(mime).toContain(`--${boundary}--`);
  });

  it('parses entity-native receipts from inbound acks', () => {
    expect(cisaAdapter.parseReceipt('Your incident ID: CISA-2026-04821 has been recorded')).toMatchObject({
      type: 'incident-id',
      value: 'CISA-2026-04821',
    });
    expect(gaoFraudnetAdapter.parseReceipt('FraudNet control number: FN-99123')).toMatchObject({
      type: 'control-number',
      value: 'FN-99123',
    });
    expect(epaOigAdapter.parseReceipt('Case Number: EPA-555-X')).toMatchObject({
      type: 'control-number',
      value: 'EPA-555-X',
    });
    expect(cisaAdapter.parseReceipt('thanks, we got it')).toBeNull();
    expect(cisaAdapter.parseReceipt(42)).toBeNull();
  });
});

describe('psst safe adapter (Stage-1 deep-link)', () => {
  it('prepares a deep-link handoff with a paste-ready deposit body', async () => {
    const prep = await psstSafeAdapter.prepare(makeView(), makePacket('psst-safe'));

    expect(prep.mode).toBe('deep-link');
    expect(prep.deepLink?.url).toBe('https://safe.psst.org/to/safe');
    expect(prep.deepLink?.depositBody).toContain('VRA-ABCDEF0123456789');
    expect(prep.deepLink?.depositBody).toContain('QmFileCid');
    expect(prep.deepLink?.depositBody).toContain('0xproofhash');
    expect(prep.deepLink?.depositBody).not.toContain('nullifier');
  });

  it('dispatch is a handoff, never an automated send', async () => {
    const prep = await psstSafeAdapter.prepare(makeView(), makePacket('psst-safe'));
    const result = await psstSafeAdapter.dispatch(prep);
    expect(result.outcome).toBe('handoff');
    expect(result.provisionalReceipt).toBeUndefined();
  });

  it('treats confirmation text as a manual receipt', () => {
    const receipt = psstSafeAdapter.parseReceipt('Deposited on 2026-07-01, confirmation shown');
    expect(receipt).toMatchObject({ type: 'manual' });
    expect(psstSafeAdapter.parseReceipt('')).toBeNull();
  });
});

describe('securedrop adapter (Stage-1 deep-link, press/media)', () => {
  it('prepares a deep-link handoff to the FPF directory with a paste-ready deposit body', async () => {
    const prep = await securedropAdapter.prepare(makeView(), makePacket('securedrop'));

    expect(prep.mode).toBe('deep-link');
    expect(prep.deepLink?.url).toBe('https://securedrop.org/directory');
    expect(prep.deepLink?.depositBody).toContain('VRA-ABCDEF0123456789');
    expect(prep.deepLink?.depositBody).toContain('QmFileCid');
    expect(prep.deepLink?.depositBody).toContain('0xproofhash');
    // Identity firewall: keys/nullifier never reach the deposit body.
    expect(prep.deepLink?.depositBody).not.toContain('nullifier');
  });

  it('dispatch is a handoff, never an automated send', async () => {
    const prep = await securedropAdapter.prepare(makeView(), makePacket('securedrop'));
    const result = await securedropAdapter.dispatch(prep);
    expect(result.outcome).toBe('handoff');
    expect(result.provisionalReceipt).toBeUndefined();
  });

  it('treats the source codename as a manual receipt', () => {
    const receipt = securedropAdapter.parseReceipt('Codename: anonymous-otter-42');
    expect(receipt).toMatchObject({ type: 'manual' });
    expect(securedropAdapter.parseReceipt('')).toBeNull();
  });
});

describe('adapter registry', () => {
  it('exposes the Tier A shipped adapters and rejects not-yet-implemented entities', () => {
    // Tier A automated email + Psst Stage-1 deep-link (this slice)
    expect(hasAdapter('cisa')).toBe(true);
    expect(hasAdapter('gao-fraudnet')).toBe(true);
    expect(hasAdapter('epa-oig')).toBe(true);
    expect(hasAdapter('psst-safe')).toBe(true);
    expect(hasAdapter('securedrop')).toBe(true);
    // Tier B portal companions (this slice) — now dispatchable.
    expect(hasAdapter('sec-tcr')).toBe(true);
    expect(hasAdapter('fincen')).toBe(true);
    expect(hasAdapter('irs-211')).toBe(true);
    // Tier C counsel adapters (this slice) — now dispatchable.
    expect(hasAdapter('eeoc')).toBe(true);
    // Entities with no adapter (implemented:false in the taxonomy) stay
    // non-dispatchable.
    expect(hasAdapter('irs-ci')).toBe(false);
    expect(hasAdapter('state-ag')).toBe(false);
    expect(getAdapter('unknown')).toBeNull();
  });
});
