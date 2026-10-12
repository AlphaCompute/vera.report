import { readReleaseManifest } from '../../enclave/src/confidential/releaseManifest';
import type { ApprovedRelease } from './ownerCase';

/** Optional operator description of one backend release, bundled with the site
 * build (`NEXT_PUBLIC_CONFIDENTIAL_RELEASE_NOTES`). It is VERA's claim, not part of
 * the measured release: the UI labels it as such and shows it only when it names
 * exactly the release being approved, so notes from an older build never describe
 * a newer release. */
export type ReleaseNotes = { releaseDigest: string; summary: string; publishedAt: string | null };
export type ReleaseUpdate = {
  releaseDigest: string; sourceCommit: string; sourceUrl: string;
  measurements: { pcr0: string; pcr1: string; pcr2: string };
  notes: ReleaseNotes | null;
  /** The newest release this report already approved, if this device can verify one. */
  previous: ApprovedRelease | null;
};

const SUMMARY_LIMIT = 280;

export function readReleaseNotes(wire: string | undefined, releaseDigest: string): ReleaseNotes | null {
  if (!wire || wire.length > 2048) return null;
  let value: unknown;
  try { value = JSON.parse(wire); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>, keys = Object.keys(record).sort().join(',');
  if (keys !== 'publishedAt,releaseDigest,summary' && keys !== 'releaseDigest,summary') return null;
  if (record.releaseDigest !== releaseDigest || typeof record.summary !== 'string') return null;
  const summary = record.summary.trim();
  if (!summary || summary.length > SUMMARY_LIMIT || /[\u0000-\u001f\u007f]/.test(summary)) return null;
  let publishedAt: string | null = null;
  if (record.publishedAt !== undefined && record.publishedAt !== null) {
    if (typeof record.publishedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(record.publishedAt)) return null;
    const parsed = new Date(`${record.publishedAt}T00:00:00Z`);
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== record.publishedAt) return null;
    publishedAt = record.publishedAt;
  }
  return { releaseDigest, summary, publishedAt };
}

/** Everything the "Approve update" card shows, from the canonical manifest this
 * build verifies the secure service against. */
export async function describeReleaseUpdate(manifestWire: string, notesWire: string | undefined,
  approvals: readonly ApprovedRelease[]): Promise<ReleaseUpdate> {
  const { manifest, digest } = await readReleaseManifest(manifestWire);
  const earlier = approvals.filter(item => item.releaseDigest !== digest);
  return {
    releaseDigest: digest, sourceCommit: manifest.sourceCommit,
    sourceUrl: `${manifest.sourceRepository}/commit/${manifest.sourceCommit}`,
    measurements: { ...manifest.measurements },
    notes: readReleaseNotes(notesWire, digest),
    previous: earlier.length ? earlier[earlier.length - 1] : null,
  };
}

/** One sentence on what changed. Without notes for this exact release, say only
 * what the device can establish. */
export { releaseChangeSentence } from './releaseUpdateCopy';
