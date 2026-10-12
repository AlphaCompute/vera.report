import { verifyOwnerStatement } from './authorization.ts';
import { issuedNotAfter } from './clockSkew.ts';
import type { OwnerTrust } from './authorization.ts';
import type { ApplicationAttestationPolicy } from './attestationEvidence.ts';

/** Backend identity only. Cosmetic frontend builds do not change case approval.
 * These digests bind claims; source/build provenance must authenticate the claims
 * before an owner is asked to approve them. No URLs are fetched by this module. */
export type ConfidentialReleaseManifest = {
  format: 'vera-confidential-release/v1';
  sourceRepository: string;
  sourceCommit: string;
  eifSha256: string;
  imageSha256: string;
  configurationSha256: string;
  provenanceSha256: string;
  protocolVersion: 'vera-confidential-channel/v1';
  dataFormatVersion: 'vera-confidential-case/v1';
  measurements: { pcr0: string; pcr1: string; pcr2: string };
};

function invalid(): never { throw new Error('Invalid or unapproved confidential release'); }
function record(value: unknown, fields: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) invalid();
  return value as Record<string, unknown>;
}
function hex(value: unknown, length: number): string {
  if (typeof value !== 'string' || value.length !== length || !/^[0-9a-f]+$/.test(value) || /^0+$/.test(value)) invalid();
  return value;
}
function parse(value: unknown): ConfidentialReleaseManifest {
  const manifest = record(value, ['format', 'sourceRepository', 'sourceCommit', 'eifSha256',
    'imageSha256', 'configurationSha256', 'provenanceSha256', 'protocolVersion', 'dataFormatVersion', 'measurements']);
  const measurements = record(manifest.measurements, ['pcr0', 'pcr1', 'pcr2']);
  if (manifest.format !== 'vera-confidential-release/v1' || manifest.protocolVersion !== 'vera-confidential-channel/v1' ||
      manifest.dataFormatVersion !== 'vera-confidential-case/v1' || typeof manifest.sourceRepository !== 'string' ||
      manifest.sourceRepository.length > 200 ||
      !/^https:\/\/github\.com\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(manifest.sourceRepository)) invalid();
  return { format: 'vera-confidential-release/v1', sourceRepository: manifest.sourceRepository,
    sourceCommit: hex(manifest.sourceCommit, 40), eifSha256: hex(manifest.eifSha256, 64),
    imageSha256: hex(manifest.imageSha256, 64), configurationSha256: hex(manifest.configurationSha256, 64),
    provenanceSha256: hex(manifest.provenanceSha256, 64), protocolVersion: 'vera-confidential-channel/v1',
    dataFormatVersion: 'vera-confidential-case/v1', measurements: {
      pcr0: hex(measurements.pcr0, 96), pcr1: hex(measurements.pcr1, 96), pcr2: hex(measurements.pcr2, 96),
    } };
}

export function canonicalReleaseManifest(manifest: ConfidentialReleaseManifest): string {
  return JSON.stringify(parse(manifest));
}

export async function readReleaseManifest(wire: string): Promise<{ manifest: ConfidentialReleaseManifest; digest: string }> {
  try {
    if (typeof wire !== 'string' || !wire.length || wire.length > 8192) invalid();
    const manifest = parse(JSON.parse(wire));
    // Require canonical bytes: duplicate keys, reordered fields and whitespace
    // must not acquire the same approval ID via silent JSON normalization.
    if (JSON.stringify(manifest) !== wire) invalid();
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(wire)));
    return { manifest, digest: Array.from(digest, value => value.toString(16).padStart(2, '0')).join('') };
  } catch { return invalid(); }
}

export type ApprovedReleaseInput = {
  manifest: string;
  release: string;
  checkpoint: string;
  /** Independently authenticated CURRENT checkpoint, not read from this response. */
  checkpointDigest: string;
  trust: OwnerTrust;
  nonce: Uint8Array;
  now: number;
};

/** Resolves the owner's exact currently-active approval to attestation pins.
 * It does not verify build provenance, current-state freshness or an AWS quote. */
export async function approvedReleasePolicy(input: ApprovedReleaseInput): Promise<{
  releaseDigest: string; policy: ApplicationAttestationPolicy;
}> {
  try {
    const snapshot = { ...input, trust: { ...input.trust } };
    if (!(snapshot.nonce instanceof Uint8Array) || snapshot.nonce.length !== 32 ||
        !Number.isSafeInteger(snapshot.now) || snapshot.now <= 0 || snapshot.now > 8640000000000000) invalid();
    const nonce = new Uint8Array(snapshot.nonce), checkpointDigest = hex(snapshot.checkpointDigest, 64);
    const [release, checkpoint, parsed] = await Promise.all([
      verifyOwnerStatement(snapshot.release, snapshot.trust),
      verifyOwnerStatement(snapshot.checkpoint, snapshot.trust), readReleaseManifest(snapshot.manifest),
    ]);
    if (release.statement.kind !== 'release' || checkpoint.statement.kind !== 'checkpoint' ||
        checkpoint.digest !== checkpointDigest || !checkpoint.statement.releaseDigests.includes(release.digest) ||
        release.statement.releaseDigest !== parsed.digest || release.statement.revision > checkpoint.statement.revision ||
        !issuedNotAfter(release.statement.issuedAt, snapshot.now) || !issuedNotAfter(checkpoint.statement.issuedAt, snapshot.now)) invalid();
    const pcrs = parsed.manifest.measurements;
    const decode = (value: string) => Uint8Array.from(value.match(/../g)!, item => parseInt(item, 16));
    return { releaseDigest: parsed.digest, policy: { nonce, now: snapshot.now,
      expectedPcrs: new Map([[0, decode(pcrs.pcr0)], [1, decode(pcrs.pcr1)], [2, decode(pcrs.pcr2)]]) } };
  } catch { return invalid(); }
}
