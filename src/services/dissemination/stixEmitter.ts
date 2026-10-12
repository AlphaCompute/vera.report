/**
 * STIX 2.1 emitter for cyber-category reports (Phase 2b, VERA-PDR-001).
 *
 * CISA's intake guidelines explicitly accept STIX submissions — the only
 * structured machine format in the U.S. whistleblower landscape. This
 * module maps the identity-free dissemination view to a STIX 2.1 bundle:
 *
 *   narrative            → report SDO
 *   IOCs in the text     → indicator SDOs (hashes, IPs, domains, URLs)
 *   Vera.Report          → identity SDO (the transmitting party)
 *   Midnight proof ref   → x_vera_existence_proof extension on the report
 *
 * The bundle is hand-rolled JSON — the subset of the STIX schema needed
 * here is small and dependency-free. It is built from the dissemination
 * view only, so the identity firewall holds by construction.
 */

import crypto from 'node:crypto';
import { categoryLabel } from './taxonomy';
import type { DisseminationView } from './types';

export const STIX_SPEC_VERSION = '2.1';

/** Deterministic STIX id: same input always yields the same identifier. */
function stixId(type: string, seed: string): string {
  const hash = crypto.createHash('sha256').update(seed).digest('hex');
  // Format the first 16 bytes of the digest as a UUID (version nibble 4,
  // variant bits 10) so consumers see a syntactically valid UUIDv4.
  const uuid = [
    hash.slice(0, 8),
    hash.slice(8, 12),
    `4${hash.slice(13, 16)}`,
    `${((parseInt(hash[16], 16) & 0x3) | 0x8).toString(16)}${hash.slice(17, 20)}`,
    hash.slice(20, 32),
  ].join('-');
  return `${type}--${uuid}`;
}

export interface StixObject {
  type: string;
  spec_version: string;
  id: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

export interface ExtractedIoc {
  kind: 'sha256' | 'md5' | 'ipv4' | 'domain' | 'url';
  value: string;
  /** STIX pattern expression for this observable. */
  pattern: string;
}

const IOC_PATTERNS: { kind: ExtractedIoc['kind']; re: RegExp; pattern: (v: string) => string }[] = [
  {
    kind: 'sha256',
    re: /\b[a-f0-9]{64}\b/gi,
    pattern: (v) => `[file:hashes.'SHA-256' = '${v.toLowerCase()}']`,
  },
  {
    kind: 'md5',
    re: /\b[a-f0-9]{32}\b/gi,
    pattern: (v) => `[file:hashes.MD5 = '${v.toLowerCase()}']`,
  },
  {
    kind: 'ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    pattern: (v) => `[ipv4-addr:value = '${v}']`,
  },
  {
    kind: 'url',
    re: /\bhttps?:\/\/[^\s"'<>)\]]+/gi,
    pattern: (v) => `[url:value = '${v.replace(/'/g, "\\'")}']`,
  },
  {
    kind: 'domain',
    // Requires at least one dot and a plausible TLD; matched after URLs so
    // hosts inside URLs are deduplicated by value below.
    re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
    pattern: (v) => `[domain-name:value = '${v.toLowerCase()}']`,
  },
];

/** Domains that appear in Vera's own boilerplate — never IOCs. */
const DOMAIN_ALLOWLIST = new Set(['vera.report', 'safe.psst.org', 'psst.org']);

/**
 * Extract indicators of compromise from free text. Deliberately
 * conservative: an over-extracted domain is noise for a CISA analyst, a
 * missed one is still in the attached narrative.
 *
 * Reporter-PII guard (review finding H2): because this text leaves the
 * platform, it drops the observables most likely to be the REPORTER rather
 * than the threat — private/reserved IPv4 ranges (home/VPN networks) and
 * domains embedded in an email address (callback contact info). Narrative
 * redaction before packet freeze is the primary control; this is defence
 * in depth.
 */
export function extractIocs(text: string): ExtractedIoc[] {
  const seen = new Set<string>();
  const results: ExtractedIoc[] = [];

  for (const { kind, re, pattern } of IOC_PATTERNS) {
    for (const match of text.matchAll(re)) {
      // Trailing sentence punctuation is prose, not part of the observable.
      const value = kind === 'url' ? match[0].replace(/[.,;:!?]+$/, '') : match[0];
      const key = value.toLowerCase();
      if (seen.has(key)) continue;

      // Drop private/reserved IPs — far more likely the reporter's own
      // network than a threat indicator (H2).
      if (kind === 'ipv4' && !isPublicRoutableIpv4(value)) continue;

      if (kind === 'domain') {
        if (DOMAIN_ALLOWLIST.has(key)) continue;
        // Skip domains that are part of an already-captured URL.
        if ([...seen].some((s) => s.includes(key))) continue;
        // Skip pure-numeric "domains" (they're version strings or IPs).
        if (/^[\d.]+$/.test(key)) continue;
        // Skip domains embedded in an email address (reporter callback
        // contact, not a threat IOC) — on either side of an '@' (H2).
        const idx = match.index ?? 0;
        const before = idx > 0 ? text[idx - 1] : '';
        const after = text[idx + value.length] ?? '';
        if (before === '@' || after === '@') continue;
      }

      seen.add(key);
      results.push({ kind, value, pattern: pattern(value) });
    }
  }
  return results;
}

/**
 * True only for public, routable IPv4 — excludes private/reserved ranges
 * (RFC1918, loopback, link-local, CGNAT, TEST-NET, multicast) that are far
 * more likely to be the reporter's own network than a threat indicator.
 */
function isPublicRoutableIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return false;         // this-net / RFC1918 / loopback
  if (a === 172 && b >= 16 && b <= 31) return false;          // 172.16.0.0/12
  if (a === 192 && b === 168) return false;                   // 192.168.0.0/16
  if (a === 169 && b === 254) return false;                   // link-local
  if (a === 100 && b >= 64 && b <= 127) return false;         // CGNAT 100.64.0.0/10
  if (a === 192 && b === 0) return false;                     // 192.0.0.0/24, TEST-NET-1
  if (a >= 224) return false;                                 // multicast + reserved
  return true;
}

class StixEmitter {
  /** Entities whose intake accepts STIX; currently CISA only. */
  applicable(view: DisseminationView, entityId: string): boolean {
    return entityId === 'cisa' && view.categories.includes('cyber-security');
  }

  /** Build the STIX 2.1 bundle for a report. */
  emit(view: DisseminationView): StixBundle {
    const now = (view.submittedAt ?? new Date()).toISOString();
    const objects: StixObject[] = [];

    const veraIdentity: StixObject = {
      type: 'identity',
      spec_version: STIX_SPEC_VERSION,
      id: stixId('identity', 'vera.report'),
      created: now,
      modified: now,
      name: 'Vera.Report',
      identity_class: 'system',
      description:
        'Anonymous whistleblowing infrastructure. This bundle was transmitted on behalf of ' +
        'an anonymous reporter with their explicit consent; Vera.Report does not ' +
        'independently verify the allegations.',
    };
    objects.push(veraIdentity);

    const iocs = extractIocs(view.narrative);
    const indicatorIds: string[] = [];
    for (const ioc of iocs) {
      const indicator: StixObject = {
        type: 'indicator',
        spec_version: STIX_SPEC_VERSION,
        id: stixId('indicator', `${view.trackingId}:${ioc.pattern}`),
        created: now,
        modified: now,
        created_by_ref: veraIdentity.id,
        name: `${ioc.kind} observed in whistleblower report ${view.trackingId}`,
        pattern: ioc.pattern,
        pattern_type: 'stix',
        valid_from: now,
        indicator_types: ['unknown'],
      };
      indicatorIds.push(indicator.id);
      objects.push(indicator);
    }

    const report: StixObject = {
      type: 'report',
      spec_version: STIX_SPEC_VERSION,
      id: stixId('report', view.trackingId),
      created: now,
      modified: now,
      created_by_ref: veraIdentity.id,
      name: `Whistleblower report ${view.trackingId}`,
      description: view.narrative || '(narrative withheld)',
      report_types: ['threat-report'],
      published: now,
      labels: view.categories.map((c) => categoryLabel(c)),
      object_refs: [veraIdentity.id, ...indicatorIds],
      // Custom extension (STIX 2.1 §7.3 custom properties): the Midnight
      // existence proof lets the receiving analyst verify the report
      // existed, unaltered, at its stated time.
      ...(view.zkProof
        ? {
            x_vera_existence_proof: {
              network: 'midnight',
              proof_hash: view.zkProof.proofHash,
              tx_hash: view.zkProof.txHash,
              verified: view.zkProof.verified,
            },
          }
        : {}),
      ...(view.evidence.evidenceHash
        ? { x_vera_evidence_sha256: view.evidence.evidenceHash }
        : {}),
    };
    objects.push(report);

    return {
      type: 'bundle',
      id: stixId('bundle', `${view.trackingId}:bundle`),
      objects,
    };
  }
}

export const stixEmitter = new StixEmitter();
