import { readReleaseManifest } from '../../enclave/src/confidential/releaseManifest';

export type ReleaseIdentity = { sourceCommit: string; sourceUrl: string; digest: string };
/** Display only canonical manifest fields; a source link is not provenance proof. */
export async function releaseIdentity(wire: string): Promise<ReleaseIdentity> {
  const { manifest, digest } = await readReleaseManifest(wire);
  return { sourceCommit: manifest.sourceCommit, sourceUrl: `${manifest.sourceRepository}/commit/${manifest.sourceCommit}`, digest };
}
