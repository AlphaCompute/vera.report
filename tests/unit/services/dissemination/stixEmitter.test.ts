jest.mock('../../../../src/services/dissemination/packetEvidence', () => ({ exportPacketArchive: jest.fn().mockResolvedValue(Buffer.from('ZIP-with-evidence')) }));
/**
 * STIX 2.1 emitter tests (Phase 2b): bundle shape, IOC extraction,
 * identity exclusion, determinism, and the CISA attachment wiring.
 */

import { stixEmitter, extractIocs, STIX_SPEC_VERSION } from '../../../../src/services/dissemination/stixEmitter';
import { cisaAdapter } from '../../../../src/services/dissemination/adapters/cisa';
import type { DisseminationView, Packet } from '../../../../src/services/dissemination/types';

function makeView(overrides: Partial<DisseminationView> = {}): DisseminationView {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    categories: ['cyber-security'],
    rawCategories: ['cyber-security'],
    narrative:
      'Attackers exfiltrated data to evil-c2.example.net (203.0.113.7) using malware ' +
      'with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. ' +
      'Staging server: https://drop.badhost.io/payload.',
    urgency: 'high',
    evidence: { evidenceHash: 'a'.repeat(64), files: [] },
    zkProof: { proofHash: '0xproof', txHash: '0xtx', verified: true },
    submittedAt: new Date('2026-07-01T00:00:00Z'),
    ...overrides,
  };
}

function makePacket(): Packet {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    entityId: 'cisa',
    packetVersion: 1,
    pdf: Buffer.from('%PDF- test'),
    sidecar: {
      schema: 'vera-packet/1.0',
      trackingId: 'VRA-ABCDEF0123456789',
      entityId: 'cisa',
      packetVersion: 1,
      generatedAt: new Date().toISOString(),
      categories: [{ slug: 'cyber-security', label: 'Cyber security' }],
      narrative: '',
      evidenceManifest: { files: [], escrowStatement: '' },
      transmittalStatement: '',
    },
    packetHash: 'f'.repeat(64),
    generatedAt: new Date(),
  };
}

describe('extractIocs', () => {
  it('finds hashes, IPs, domains, and URLs', () => {
    const iocs = extractIocs(makeView().narrative);
    const kinds = iocs.map((i) => i.kind);
    expect(kinds).toContain('sha256');
    expect(kinds).toContain('ipv4');
    expect(kinds).toContain('url');
    expect(kinds).toContain('domain');

    const domain = iocs.find((i) => i.kind === 'domain');
    expect(domain?.value).toBe('evil-c2.example.net');
    const url = iocs.find((i) => i.kind === 'url');
    expect(url?.pattern).toContain("url:value = 'https://drop.badhost.io/payload'");
  });

  it('skips Vera boilerplate domains and deduplicates', () => {
    const iocs = extractIocs('See https://vera.report and vera.report and psst.org for info.');
    expect(iocs.filter((i) => i.kind === 'domain')).toHaveLength(0);
  });

  it('returns nothing for clean prose', () => {
    expect(extractIocs('My manager falsified safety inspection records last March.')).toEqual([]);
  });

  it('drops reporter-PII observables: private IPs and email-embedded domains (H2)', () => {
    const iocs = extractIocs(
      'Reach me at whistleblower.jane@proton.me from my home network 192.168.1.50; ' +
        'the C2 was evil-c2.example.net at 203.0.113.7.',
    );
    const values = iocs.map((i) => i.value.toLowerCase());
    // Reporter callback contact + home network are excluded...
    expect(values).not.toContain('192.168.1.50');
    expect(values).not.toContain('proton.me');
    expect(values).not.toContain('whistleblower.jane');
    // ...but genuine threat observables still come through.
    expect(values).toContain('203.0.113.7');
    expect(values).toContain('evil-c2.example.net');
  });
});

describe('stixEmitter.emit', () => {
  it('produces a valid bundle: identity, indicators, and a report referencing them', () => {
    const bundle = stixEmitter.emit(makeView());

    expect(bundle.type).toBe('bundle');
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);

    const identity = bundle.objects.find((o) => o.type === 'identity')!;
    expect(identity.name).toBe('Vera.Report');

    const indicators = bundle.objects.filter((o) => o.type === 'indicator');
    expect(indicators.length).toBeGreaterThanOrEqual(3);
    for (const ind of indicators) {
      expect(ind.spec_version).toBe(STIX_SPEC_VERSION);
      expect(ind.pattern_type).toBe('stix');
      expect(ind.created_by_ref).toBe(identity.id);
    }

    const report = bundle.objects.find((o) => o.type === 'report')!;
    expect(report.report_types).toEqual(['threat-report']);
    expect(report.labels).toEqual(['Cyber security']);
    expect(report.object_refs).toEqual([identity.id, ...indicators.map((i) => i.id)]);
    expect(report.x_vera_existence_proof).toEqual({
      network: 'midnight',
      proof_hash: '0xproof',
      tx_hash: '0xtx',
      verified: true,
    });
    expect(report.x_vera_evidence_sha256).toBe('a'.repeat(64));
  });

  it('is deterministic: same view yields identical object ids', () => {
    const a = stixEmitter.emit(makeView());
    const b = stixEmitter.emit(makeView());
    expect(a.id).toBe(b.id);
    expect(a.objects.map((o) => o.id)).toEqual(b.objects.map((o) => o.id));
  });

  it('never contains identity or decryption material', () => {
    const json = JSON.stringify(stixEmitter.emit(makeView()));
    for (const banned of ['nullifier', 'contactValue', 'contactMethod', 'wantsReward', 'encryptionKey']) {
      expect(json).not.toContain(banned);
    }
  });

  it('omits the existence proof extension when there is no proof', () => {
    const bundle = stixEmitter.emit(makeView({ zkProof: undefined }));
    const report = bundle.objects.find((o) => o.type === 'report')!;
    expect(report.x_vera_existence_proof).toBeUndefined();
  });
});

describe('stixEmitter.applicable', () => {
  it('applies only to CISA and only for cyber-security reports', () => {
    expect(stixEmitter.applicable(makeView(), 'cisa')).toBe(true);
    expect(stixEmitter.applicable(makeView(), 'gao-fraudnet')).toBe(false);
    expect(stixEmitter.applicable(makeView({ categories: ['financial-fraud'] }), 'cisa')).toBe(false);
  });
});

describe('CISA adapter STIX attachment', () => {
  const ORIGINAL_ENV = { ...process.env };
  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('attaches the STIX bundle for cyber-category reports', async () => {
    // Live shape; dryrun withholds attachments unless the inbox has a pinned key.
    process.env.DISSEMINATION_MODE = 'live';

    const prep = await cisaAdapter.prepare(makeView(), makePacket());
    const filenames = prep.email!.attachments.map((a) => a.filename);
    expect(filenames).toContain('vera-stix-VRA-ABCDEF0123456789.json');

    const stix = prep.email!.attachments.find((a) => a.filename.startsWith('vera-stix-'))!;
    const bundle = JSON.parse(stix.content.toString('utf8'));
    expect(bundle.type).toBe('bundle');
    expect(bundle.objects.some((o: { type: string }) => o.type === 'report')).toBe(true);
  });

  it('omits the bundle for non-cyber reports', async () => {
    // Live shape; dryrun withholds attachments unless the inbox has a pinned key.
    process.env.DISSEMINATION_MODE = 'live';

    const prep = await cisaAdapter.prepare(
      makeView({ categories: ['government-accountability'] }),
      makePacket(),
    );
    expect(prep.email!.attachments.map((a) => a.filename)).toEqual([
      'vera-report-VRA-ABCDEF0123456789.zip',
      'vera-packet-VRA-ABCDEF0123456789.json',
    ]);
  });
});
