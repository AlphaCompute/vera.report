import { canonicalReleaseManifest, readReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { releaseIdentity } from '../../../lib/confidential/releaseIdentity';

const manifest = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: '2'.repeat(64), imageSha256: '3'.repeat(64), configurationSha256: '4'.repeat(64), provenanceSha256: '5'.repeat(64),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '6'.repeat(96), pcr1: '7'.repeat(96), pcr2: '8'.repeat(96) } });

test('release consent identifies exactly the canonical release and its declared commit', async () => {
  expect(await releaseIdentity(manifest)).toEqual({ sourceCommit: '1'.repeat(40),
    sourceUrl: `https://github.com/example/vera/commit/${'1'.repeat(40)}`, digest: (await readReleaseManifest(manifest)).digest });
});
test('malformed or substituted source identity is never rendered as verified release metadata', async () => {
  await expect(releaseIdentity(manifest + '\n')).rejects.toThrow();
  await expect(releaseIdentity(manifest.replace('https://github.com/example/vera', 'javascript:alert(1)'))).rejects.toThrow();
});
