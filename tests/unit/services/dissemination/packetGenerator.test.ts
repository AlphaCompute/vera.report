/**
 * Packet generator tests: manifest/digest correctness and identity
 * exclusion (no reward/contact/nullifier/decryption material in packets).
 */

import crypto from 'node:crypto';
import { PDFPage } from 'pdf-lib';
import { packetGenerator, TRANSMITTAL_STATEMENT } from '../../../../src/services/dissemination/packetGenerator';
import type { DisseminationView } from '../../../../src/services/dissemination/types';
import { buildDisseminationView } from '../../../../src/services/dissemination/disseminationView';
import type { ReportRecord } from '../../../../src/services/reportPersistence';

// Pinning is exercised separately; keep unit tests offline.
jest.mock('../../../../src/services/evidenceStorage', () => ({
  evidenceStorageService: {
    uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'QmPacketCid' }),
  },
}));

beforeEach(() => { process.env.DISSEMINATION_WEBHOOK_SECRET = 'packet-case-ref-test'; });

function makeView(): DisseminationView {
  return {
    trackingId: 'VRA-ABCDEF0123456789',
    categories: ['cyber-security', 'financial-fraud'],
    rawCategories: ['cyber-security'],
    narrative: 'A detailed narrative of the wrongdoing observed.',
    urgency: 'high',
    location: 'Test City',
    dateOfIncident: '2026-06-01',
    verification: { credibilityScore: 82, category: 'cyber-security' },
    evidence: {
      evidenceHash: 'e'.repeat(64),
      ipfsHash: 'QmMetadataCid',
      files: [
        { name: 'evidence1.pdf', cid: 'QmFileCid1', mimetype: 'application/pdf', size: 12345 },
        { name: 'photo.png', cid: 'QmFileCid2', mimetype: 'image/png', size: 6789 },
      ],
    },
    zkProof: {
      proofHash: '0xproofhash',
      proofType: 'compact_circuit',
      contractAddress: '0xcontract',
      txHash: '0xtxhash',
      verified: true,
    },
    submittedAt: new Date('2026-06-02T00:00:00Z'),
    jurisdiction: 'us',
  };
}

describe('packetGenerator', () => {
  it.each([undefined, 'sha256-framed-v2'] as const)('retains commitment version %s through projection and packet export', async evidenceHashVersion => {
    const view = buildDisseminationView({
      trackingId: 'VRA-ABCDEF0123456789', evidenceHash: 'e'.repeat(64), evidenceHashVersion,
    } as ReportRecord, 'Synthetic narrative');
    const packet = await packetGenerator.generate(view, 'cisa');
    expect(packet.sidecar.evidenceManifest.evidenceHashVersion).toBe(evidenceHashVersion ?? 'sha256-concat-v1');
  });
  it('produces a valid PDF with a matching SHA-256 digest', async () => {
    const packet = await packetGenerator.generate(makeView(), 'cisa');

    expect(packet.pdf.subarray(0, 5).toString()).toBe('%PDF-');
    const digest = crypto.createHash('sha256').update(packet.pdf).digest('hex');
    expect(packet.packetHash).toBe(digest);
    expect(packet.packetCid).toBe('QmPacketCid');
  });

  it('builds a complete JSON sidecar with the evidence manifest', async () => {
    const packet = await packetGenerator.generate(makeView(), 'gao-fraudnet');
    const sidecar = packet.sidecar;

    expect(sidecar.schema).toBe('vera-packet/1.0');
    expect(sidecar.trackingId).toMatch(/^CASE-/);
    expect(JSON.stringify(sidecar)).not.toContain('VRA-ABCDEF0123456789');
    expect(sidecar.entityId).toBe('gao-fraudnet');
    expect(sidecar.categories.map((c) => c.slug)).toEqual(['cyber-security', 'financial-fraud']);
    expect(sidecar.evidenceManifest.evidenceHash).toBe('e'.repeat(64));
    expect(sidecar.evidenceManifest.files).toHaveLength(2);
    expect(sidecar.evidenceManifest.files[0].cid).toBe('QmFileCid1');
    expect(sidecar.existenceProof?.txHash).toBe('0xtxhash');
    expect(sidecar.existenceProof?.network).toBe('midnight');
    expect(sidecar.jurisdiction).toBe('us');
    expect(sidecar.submittedAt).toBe('2026-06-02T00:00:00.000Z');
    expect(sidecar.transmittalStatement).toBe(TRANSMITTAL_STATEMENT);
  });

  it('never contains identity or decryption material (identity firewall)', async () => {
    const packet = await packetGenerator.generate(makeView(), 'cisa');

    const sidecarJson = JSON.stringify(packet.sidecar);
    const pdfText = packet.pdf.toString('latin1');

    for (const banned of [
      'nullifier',
      'encryptedContactValue',
      'contactMethod',
      'contactValue',
      'wantsReward',
      'reward',
      'encryptionKey',
      'authTag',
      'evidence_decryption_params',
    ]) {
      expect(sidecarJson).not.toContain(banned);
      expect(pdfText).not.toContain(banned);
    }
  });

  it('is deterministic in structure across a report with no evidence or proof', async () => {
    const bare: DisseminationView = {
      ...makeView(),
      evidence: { files: [] },
      zkProof: undefined,
      narrative: '',
    };
    const packet = await packetGenerator.generate(bare, 'epa-oig');
    expect(packet.pdf.length).toBeGreaterThan(500);
    expect(packet.sidecar.existenceProof).toBeUndefined();
    expect(packet.sidecar.evidenceManifest.files).toEqual([]);
  });

  it('survives a pinning failure and ships without a CID', async () => {
    const { evidenceStorageService } = jest.requireMock('../../../../src/services/evidenceStorage') as {
      evidenceStorageService: { uploadEncryptedFile: jest.Mock };
    };
    evidenceStorageService.uploadEncryptedFile.mockRejectedValueOnce(new Error('storage down'));

    const packet = await packetGenerator.generate(makeView(), 'cisa');
    expect(packet.packetCid).toBeUndefined();
    expect(packet.packetHash).toHaveLength(64);
  });
});

it.each(['missing', 'unverified', 'fallback', 'verified'])('states truthful blockchain availability for %s proofs', async state => {
  const view = makeView();
  if (state === 'missing') delete view.zkProof;
  if (state === 'unverified') view.zkProof!.verified = false;
  if (state === 'fallback') view.zkProof!.proofType = 'hash_commitment';
  const draw = jest.spyOn(PDFPage.prototype, 'drawText');
  try {
    const packet = await packetGenerator.generate(view, 'cisa');
    const text = draw.mock.calls.map(call => call[0]).join(' ');
    expect(text).not.toContain('unaltered, at its stated time');
    expect(text).not.toContain('is bound to the blockchain proof reference');
    expect(text.includes('A verified Midnight transaction reference')).toBe(state === 'verified');
    if (state === 'missing') expect(text).toContain('No blockchain proof reference');
    if (state === 'fallback' || state === 'unverified') expect(text).toContain('does not establish a verified blockchain submission');
    expect(packet.sidecar.transmittalStatement).not.toContain('establishes that this report existed');
  } finally { draw.mockRestore(); }
});
