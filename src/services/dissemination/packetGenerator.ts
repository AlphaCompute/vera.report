import { logger } from '../../utils/logger';
import { recipientCaseReference } from './recipientCapability';
/**
 * Submission packet generator (VERA-PDR-001 FR-5, §7.1).
 *
 * Renders per-entity submission packets from the identity-free
 * dissemination view: a PDF dossier (narrative, category mapping,
 * evidence manifest with IPFS CIDs and digests, chain-of-custody
 * statement, Midnight ZK existence proof reference) plus a JSON sidecar
 * for machine intake. Packets are treated like evidence: encrypted and
 * pinned to IPFS, referenced by CID from the submission record.
 *
 * Evidence decryption keys are NEVER included in packets (PDR §10):
 * agencies receive CIDs and digests; decryption is a separate,
 * consent-gated escrow release.
 */

import crypto from 'node:crypto';
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from 'pdf-lib';
import { categoryLabel, getEntity, JURISDICTIONS } from './taxonomy';
import type { DisseminationView, Packet, PacketSidecar } from './types';
import { SECURE_LINK_ENTITY_ID } from './secureLink';
import { checkPacketCompleteness } from './packetCompleteness';
import type { PacketSubmitter } from '../submitterDisclosure';

/**
 * Standard transmittal statement (PDR §12): Vera transmits
 * reporter-authored content on the reporter's instruction; it does not
 * verify truth. Wording is subject to outside-counsel review (§16).
 */
export const TRANSMITTAL_STATEMENT =
  'Prepared by Vera.Report for an anonymous reporter. Generating this packet does not ' +
  'mean it has been sent or accepted by a recipient. Disclosure requires reporter consent ' +
  'and authorization. Vera.Report does not independently verify the allegations. ' +
  'See the blockchain section for the available proof reference.';

export const ESCROW_STATEMENT =
  'This manifest lists encrypted evidence references and SHA-256 digests, not decryption keys. ' +
  'Ask an authorized Vera.Report reviewer about evidence access. Reporter consent and ' +
  'access checks apply; the case reference alone does not grant access.';

const PAGE_WIDTH = 612; // US Letter
const PAGE_HEIGHT = 792;
const MARGIN = 56;
const BODY_SIZE = 10;
const LINE_HEIGHT = 14;

class PacketGenerator {
  /** Current packet schema/layout version; part of the idempotency key. */
  readonly packetVersion = 3;

  /**
   * Generate the packet for one (report, entity) pair. Pinning to IPFS is
   * best-effort: a storage outage must not block Tier A dispatch (NFR-3),
   * so the packet ships with hash only when pinning fails.
   */
  async generate(view: DisseminationView, entityId: string, submitter: PacketSubmitter = { mode: 'anonymous' }): Promise<Packet> {
    const recipientView = { ...view, trackingId: recipientCaseReference(view.trackingId, entityId) };
    const sidecar = this.buildSidecar(recipientView, entityId, submitter);
    const pdf = await this.renderPdf(recipientView, entityId, sidecar);
    const packetHash = crypto.createHash('sha256').update(pdf).digest('hex');

    const packet: Packet = {
      trackingId: view.trackingId,
      entityId,
      packetVersion: this.packetVersion,
      pdf,
      sidecar,
      packetHash,
      generatedAt: new Date(),
      completeness: checkPacketCompleteness(view, entityId),
    };

    const pinned = await this.pinEncryptedPacket(packet);
    packet.packetCid = pinned.cid;
    packet.packetKey = pinned.key;
    return packet;
  }

  private buildSidecar(view: DisseminationView, entityId: string, submitter: PacketSubmitter): PacketSidecar {
    return {
      schema: 'vera-packet/1.0',
      submitter,
      trackingId: view.trackingId,
      entityId,
      packetVersion: this.packetVersion,
      generatedAt: new Date().toISOString(),
      categories: view.categories.map((slug) => ({ slug, label: categoryLabel(slug) })),
      subjectOrganization: view.subjectOrganization,
      orgType: view.orgType,
      narrative: view.narrative,
      urgency: view.urgency,
      location: view.location,
      dateOfIncident: view.dateOfIncident,
      jurisdiction: view.jurisdiction,
      submittedAt: view.submittedAt ? new Date(view.submittedAt).toISOString() : undefined,
      verification: view.verification,
      evidenceManifest: {
        evidenceHash: view.evidence.evidenceHash,
        evidenceHashVersion: view.evidence.evidenceHashVersion ?? 'sha256-concat-v1',
        ipfsHash: view.evidence.ipfsHash,
        files: view.evidence.files,
        escrowStatement: ESCROW_STATEMENT,
      },
      existenceProof: view.zkProof
        ? { ...view.zkProof, network: 'midnight' }
        : undefined,
      transmittalStatement: submitter.mode === 'identified'
        ? TRANSMITTAL_STATEMENT.replace('an anonymous reporter', 'the identified submitter')
        : TRANSMITTAL_STATEMENT,
    };
  }

  /**
   * Encrypt the packet (PDF + sidecar) with a random key and pin to IPFS.
   * The key is RETAINED — returned alongside the CID and persisted on the
   * submission — so the pinned copy stays recoverable for audit: the
   * encrypted blob is tamper-evident custody of exactly what was sent, and
   * the submission also keeps the plaintext hash. Best-effort: a storage
   * outage must not block Tier A dispatch (NFR-3), so on failure it returns
   * an empty result and the packet ships with hash only.
   */
  private async pinEncryptedPacket(packet: Packet): Promise<{ cid?: string; key?: string }> {
    try {
      const { evidenceStorageService } = await import('../evidenceStorage');
      const encryptionKey = crypto.randomBytes(32).toString('hex');
      const bundle = Buffer.from(
        JSON.stringify({ sidecar: packet.sidecar, pdfBase64: packet.pdf.toString('base64') }),
      );
      const result = await evidenceStorageService.uploadEncryptedFile(
        bundle,
        `packet_${packet.trackingId}_${packet.entityId}_v${packet.packetVersion}.json`,
        packet.trackingId,
        encryptionKey,
      );
      return { cid: result.originalCID, key: encryptionKey };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`[DISSEMINATION] Packet pinning failed (continuing without CID): ${msg}`);
      return {};
    }
  }

  // ── PDF rendering ─────────────────────────────────────────────────

  private async renderPdf(view: DisseminationView, entityId: string, sidecar: PacketSidecar): Promise<Buffer> {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const bold = await doc.embedFont(StandardFonts.HelveticaBold);
    const mono = await doc.embedFont(StandardFonts.Courier);

    const writer = new PdfWriter(doc, font, bold, mono);
    // Synthetic dissemination ids (e.g. the one-time secure-packet link) have
    // no taxonomy entry; render a human label instead of the raw slug.
    const entityName =
      getEntity(entityId)?.name ??
      (entityId === SECURE_LINK_ENTITY_ID ? 'Authorized recipient' : entityId);

    writer.title('Vera.Report Submission Packet');
    writer.subtitle(`Prepared for: ${entityName}`);
    writer.spacer(6);

    writer.kv('Case reference', view.trackingId);
    writer.kv('Packet version', String(this.packetVersion));
    writer.kv('Generated', sidecar.generatedAt);
    if (view.submittedAt) writer.kv('Report submitted', view.submittedAt.toISOString());
    writer.kv('Categories', sidecar.categories.map((c) => c.label).join('; ') || 'Uncategorized');
    if (view.subjectOrganization) {
      writer.kv(
        'Subject organization',
        view.subjectOrganization + (view.orgType && view.orgType !== 'unknown' ? ` (${view.orgType})` : ''),
      );
    }
    if (view.urgency) writer.kv('Urgency', view.urgency);
    if (view.location) writer.kv('Location', view.location);
    if (view.dateOfIncident) writer.kv('Date of incident', view.dateOfIncident);
    if (view.jurisdiction) {
      writer.kv('Jurisdiction', JURISDICTIONS.find((j) => j.value === view.jurisdiction)?.label ?? view.jurisdiction);
    }

    writer.heading('1. Submitter and Contact');
    const submitter = sidecar.submitter;
    if (submitter?.mode === 'identified') {
      // Standard PDF fonts cannot encode all valid names. Keep exact Unicode
      // in the JSON sidecar and explicitly escape unsupported PDF glyphs.
      const supported = new Set(font.getCharacterSet());
      const requiresEscapes = [submitter.name, submitter.contact.value].some(value => [...value].some(char => !supported.has(char.codePointAt(0)!)));
      const displayIdentity = (value: string) => requiresEscapes ? [...value].map(char => {
        const code = char.codePointAt(0)!;
        return code === 92 || !supported.has(code) ? `\\u{${code.toString(16).toUpperCase()}}` : char;
      }).join('') : value;
      if (requiresEscapes) writer.paragraph('Some identity characters are shown as Unicode escapes (\\u{HEX}); the JSON sidecar preserves the exact text. Literal backslashes are escaped too.');
      writer.kv('Submitter', displayIdentity(submitter.name));
      writer.kv('Preferred contact', { email: 'Email', phone: 'Phone', encrypted: 'Secure contact', multiple: 'Supplied contact methods' }[submitter.contact.method]);
      writer.kv('Contact details', displayIdentity(submitter.contact.value));
      writer.paragraph('The submitter consented to share these details with authorized recipients for direct follow-up.');
      writer.kv('Consent recorded', submitter.consent.capturedAt);
    } else {
      writer.kv('Submitter', 'Anonymous');
      writer.paragraph('The submitter has not consented to include their name or direct contact details in this packet.');
    }

    writer.heading('2. Narrative');
    writer.paragraph(view.narrative || '(No narrative provided.)');

    writer.heading('3. Evidence Manifest');
    if (view.evidence.evidenceHash) {
      writer.kv('Evidence digest (SHA-256)', view.evidence.evidenceHash, true);
      writer.kv('Evidence commitment format', view.evidence.evidenceHashVersion ?? 'sha256-concat-v1');
    }
    if (view.evidence.ipfsHash) {
      writer.kv('Encrypted evidence CID', view.evidence.ipfsHash, true);
    }
    if (view.evidence.files.length === 0) {
      writer.paragraph('No evidence files attached.');
    } else {
      for (const [i, f] of view.evidence.files.entries()) {
        writer.paragraph(
          `${i + 1}. ${f.name}` +
            (f.mimetype ? ` (${f.mimetype}${f.size ? `, ${Math.round(f.size / 1024)} KB` : ''})` : ''),
        );
        if (f.cid) writer.mono(`   CID: ${f.cid}`);
      }
    }
    writer.paragraph(ESCROW_STATEMENT, true);

    writer.heading('4. Existence Proof (Midnight Blockchain)');
    if (view.zkProof) {
      writer.kv('Proof hash', view.zkProof.proofHash, true);
      if (view.zkProof.proofType) writer.kv('Proof type', view.zkProof.proofType);
      if (view.zkProof.contractAddress) writer.kv('Contract', view.zkProof.contractAddress, true);
      if (view.zkProof.txHash) writer.kv('Transaction hash', view.zkProof.txHash, true);
      writer.kv('Verified', view.zkProof.verified ? 'yes' : 'no');
      writer.paragraph(
        view.zkProof.verified && view.zkProof.proofType === 'compact_circuit' && view.zkProof.txHash && view.zkProof.contractAddress
          ? 'A verified Midnight transaction reference is recorded above. It does not verify the truth of the allegations or independently establish the reported incident time.'
          : 'This reference does not establish a verified blockchain submission. Proof processing may be pending, failed, or unavailable.',
        true,
      );
    } else {
      writer.paragraph('No blockchain proof reference is available for this report.');
    }

    writer.heading('5. Chain of Custody');
    writer.paragraph(
      'VERA processes supported metadata on its servers before encrypting evidence for storage. ' +
        'File contents may still identify the reporter. The evidence digest binds the submitted ' +
        'narrative and original file bytes; it does not establish who created them or whether ' +
        'the allegations are true. See the manifest and blockchain section for recorded references.',
    );

    writer.heading('6. Transmittal Statement');
    writer.paragraph(sidecar.transmittalStatement);

    writer.footerAllPages(`Vera.Report packet ${view.trackingId} — ${entityName}`);

    const bytes = await doc.save();
    return Buffer.from(bytes);
  }
}

/** Minimal top-down text layout over pdf-lib with automatic page breaks. */
export class PdfWriter {
  private page: PDFPage;
  private y: number;

  constructor(
    private doc: PDFDocument,
    private font: PDFFont,
    private bold: PDFFont,
    private monoFont: PDFFont,
  ) {
    this.page = doc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
    this.y = PAGE_HEIGHT - MARGIN;
  }

  private ensureRoom(lines = 1): void {
    if (this.y - lines * LINE_HEIGHT < MARGIN) {
      this.page = this.doc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
      this.y = PAGE_HEIGHT - MARGIN;
    }
  }

  private drawLine(text: string, font: PDFFont, size: number, color = rgb(0.1, 0.1, 0.1)): void {
    this.ensureRoom();
    this.page.drawText(text, { x: MARGIN, y: this.y, size, font, color });
    this.y -= LINE_HEIGHT;
  }

  private wrap(text: string, font: PDFFont, size: number): string[] {
    const maxWidth = PAGE_WIDTH - MARGIN * 2;
    const lines: string[] = [];
    for (const rawLine of text.split('\n')) {
      const words = rawLine.split(/\s+/).filter(Boolean);
      if (words.length === 0) {
        lines.push('');
        continue;
      }
      let current = '';
      for (const word of words) {
        const candidate = current ? `${current} ${word}` : word;
        if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
          current = candidate;
        } else {
          if (current) lines.push(current);
          // Hard-break tokens wider than the line (hashes, CIDs).
          let chunk = word;
          while (font.widthOfTextAtSize(chunk, size) > maxWidth) {
            let cut = chunk.length;
            while (cut > 1 && font.widthOfTextAtSize(chunk.slice(0, cut), size) > maxWidth) cut--;
            lines.push(chunk.slice(0, cut));
            chunk = chunk.slice(cut);
          }
          current = chunk;
        }
      }
      if (current) lines.push(current);
    }
    return lines;
  }

  title(text: string): void {
    this.drawLine(text, this.bold, 18);
    this.y -= 4;
  }

  subtitle(text: string): void {
    this.drawLine(text, this.font, 12, rgb(0.3, 0.3, 0.3));
  }

  heading(text: string): void {
    this.y -= 10;
    this.ensureRoom(2);
    this.drawLine(text, this.bold, 12);
    this.y -= 2;
  }

  paragraph(text: string, muted = false): void {
    const color = muted ? rgb(0.35, 0.35, 0.35) : rgb(0.1, 0.1, 0.1);
    for (const line of this.wrap(text, this.font, BODY_SIZE)) {
      this.drawLine(line, this.font, BODY_SIZE, color);
    }
    this.y -= 4;
  }

  mono(text: string): void {
    for (const line of this.wrap(text, this.monoFont, 8.5)) {
      this.drawLine(line, this.monoFont, 8.5, rgb(0.2, 0.2, 0.2));
    }
  }

  kv(key: string, value: string, monoValue = false): void {
    this.ensureRoom();
    this.page.drawText(`${key}:`, { x: MARGIN, y: this.y, size: BODY_SIZE, font: this.bold });
    const keyWidth = this.bold.widthOfTextAtSize(`${key}:`, BODY_SIZE) + 6;
    const valueFont = monoValue ? this.monoFont : this.font;
    const valueSize = monoValue ? 8.5 : BODY_SIZE;
    const maxWidth = PAGE_WIDTH - MARGIN * 2 - keyWidth;

    if (valueFont.widthOfTextAtSize(value, valueSize) <= maxWidth) {
      this.page.drawText(value, { x: MARGIN + keyWidth, y: this.y, size: valueSize, font: valueFont });
      this.y -= LINE_HEIGHT;
    } else {
      this.y -= LINE_HEIGHT;
      if (monoValue) this.mono(value);
      else this.paragraph(value);
    }
  }

  spacer(px: number): void {
    this.y -= px;
  }

  footerAllPages(text: string): void {
    const pages = this.doc.getPages();
    pages.forEach((page, i) => {
      page.drawText(`${text} — page ${i + 1} of ${pages.length}`, {
        x: MARGIN,
        y: MARGIN / 2,
        size: 8,
        font: this.font,
        color: rgb(0.5, 0.5, 0.5),
      });
    });
  }
}

export const packetGenerator = new PacketGenerator();
