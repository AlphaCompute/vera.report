/**
 * Identity firewall (VERA-PDR-001 §10).
 *
 * Builds the dissemination view of a report: the ONLY projection the
 * dissemination layer is allowed to read. Reporter identifiers are
 * excluded structurally — reward contact data, nullifiers, decryption
 * keys, and session metadata are never copied into the view, so no
 * downstream component (routing, packets, adapters) can leak them.
 */

import type { ReportRecord } from '../reportPersistence';
import { normalizeCategory, type CategorySlug } from './taxonomy';
import type { DisseminationView, EvidenceManifestEntry } from './types';

export interface EvidenceFileInfo {
  name: string;
  cid?: string;
  mimetype?: string;
  size?: number;
}

/**
 * Build the identity-free dissemination view from a persisted report.
 *
 * @param report     The MongoDB report record.
 * @param narrative  Report narrative — the decrypted `encryptedDescription`
 *                   from MongoDB, or the admin-approved redaction override
 *                   when one has been frozen onto the disposition.
 * @param files      Evidence manifest entries (names + CIDs, no keys).
 */
export function buildDisseminationView(
  report: ReportRecord,
  narrative: string,
  files: EvidenceFileInfo[] = [],
): DisseminationView {
  const rawCategories: string[] = [];
  // Older records may predate intake validation. Never pass structured values
  // into category normalization or recipient-facing packet text.
  if (Array.isArray(report.categories)) rawCategories.push(...report.categories.filter(c => typeof c === 'string'));
  if (typeof report.category === 'string' && report.category) rawCategories.push(report.category);
  if (typeof report.verification?.category === 'string') rawCategories.push(report.verification.category);

  const categories: CategorySlug[] = [];
  for (const raw of rawCategories) {
    const slug = normalizeCategory(raw);
    if (slug && !categories.includes(slug)) categories.push(slug);
  }

  // Neutralize reporter-chosen filenames before they leave the platform. A raw
  // name like "JaneDoe_paystub.pdf" or "badge_10432.jpg" de-anonymizes the
  // reporter, and it is NOT covered by the narrative redaction pass. Keep only
  // the file-type extension (a non-identifying hint); the file itself is
  // retrieved by `cid`, never by this display name.
  const manifest: EvidenceManifestEntry[] = files.map((f, i) => {
    const ext = f.name.match(/\.[A-Za-z0-9]{1,8}$/)?.[0].toLowerCase() ?? '';
    return {
      name: `evidence-${i + 1}${ext}`,
      cid: f.cid,
      mimetype: f.mimetype,
      size: f.size,
    };
  });

  return {
    trackingId: report.trackingId,
    categories,
    rawCategories,
    narrative,
    urgency: report.urgency,
    location: report.location,
    dateOfIncident: report.dateOfIncident,
    verification: report.verification
      ? {
          credibilityScore: report.verification.credibilityScore,
          category: report.verification.category,
        }
      : undefined,
    evidence: {
      evidenceHash: report.evidenceHash,
      evidenceHashVersion: report.evidenceHashVersion ?? 'sha256-concat-v1',
      ipfsHash: report.ipfsHash,
      files: manifest,
    },
    zkProof: report.zkProof
      ? {
          // Deliberately excludes the nullifier: it can correlate repeat
          // submissions from the same reporter (identity-adjacent).
          proofHash: report.zkProof.proofHash,
          proofType: report.zkProof.proofType,
          contractAddress: report.zkProof.contractAddress,
          txHash: report.zkProof.txHash,
          verified: report.zkProof.verified,
        }
      : undefined,
    submittedAt: report.createdAt,
    psstTreatment: report.consent?.psst.treatment,
    jurisdiction: report.jurisdiction,
    orgType: report.verification?.organizationType,
    subjectOrganization: report.verification?.namedOrganization,
  };
}
