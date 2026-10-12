import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import type { ConfidentialReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';

// Fixed vector shared with tests/confidential-runtime/release-manifest-generator.test.cjs
// (compiled enclave + CI generator) and tests/deploy/test_eif_release.py (Python).
// This side checks the TypeScript source directly.
const vector = JSON.parse(readFileSync(join(__dirname, '../../fixtures/confidential-release-manifest-vector.json'), 'utf8'));
const sha256 = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

describe('confidential release manifest fixed vector', () => {
  const manifest: ConfidentialReleaseManifest = {
    format: 'vera-confidential-release/v1',
    sourceRepository: vector.repository,
    sourceCommit: vector.commit,
    eifSha256: sha256(vector.eif),
    imageSha256: vector.measurements.docker_image_id.replace(/^sha256:/, ''),
    configurationSha256: sha256(vector.configuration),
    provenanceSha256: sha256(vector.provenance),
    protocolVersion: 'vera-confidential-channel/v1',
    dataFormatVersion: 'vera-confidential-case/v1',
    measurements: { pcr0: vector.measurements.PCR0, pcr1: vector.measurements.PCR1, pcr2: vector.measurements.PCR2 },
  };

  it('produces the expected canonical bytes and digest from the TypeScript source', async () => {
    expect(vector.measurements.eif_sha256).toBe(manifest.eifSha256);
    const canonical = canonicalReleaseManifest(manifest);
    expect(canonical).toBe(vector.expected.canonical);
    await expect(readReleaseManifest(canonical)).resolves.toEqual({ manifest, digest: vector.expected.sha256 });
  });

  it('canonical form does not depend on input key order', () => {
    const reordered = Object.fromEntries(Object.entries(manifest).reverse()) as ConfidentialReleaseManifest;
    expect(canonicalReleaseManifest(reordered)).toBe(vector.expected.canonical);
  });

  it('rejects non-canonical encodings of the same manifest', async () => {
    await expect(readReleaseManifest(JSON.stringify(manifest, null, 2))).rejects.toThrow();
    await expect(readReleaseManifest(`${vector.expected.canonical}\n`)).rejects.toThrow();
  });
});
