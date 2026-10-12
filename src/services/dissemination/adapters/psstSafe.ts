/**
 * Psst Safe adapter — Stage 1 deep-link handoff (VERA-PDR-001 §7.2).
 *
 * Stage 1 requires zero coordination with Psst engineering: Vera prepares
 * a prefilled handoff into their existing Hush Line form at
 * safe.psst.org/to/safe — the unencrypted metadata fields (org type,
 * categories) plus a ready-to-paste deposit body containing the narrative
 * summary, evidence CIDs + digests (never decryption keys), and the
 * Midnight proof reference. The reporter's own contact method goes in the
 * encrypted field on Psst's side, keeping Vera out of the identity path.
 *
 * Non-blocking guarantees (FR-9): dispatch is a 'handoff' — it marks the
 * channel awaiting human action and never gates any other channel. The
 * receipt is manual confirmation entered by the admin.
 *
 * (Stage 2 — programmatic, partnership-gated Hush Line deposits — arrives
 * in a later slice; the Stage-1 handoff remains the fallback.)
 */

import { CircuitBreaker } from '../../../utils/circuitBreaker';
import { categoryLabel } from '../taxonomy';
import type {
  DisseminationView,
  DispatchResult,
  Packet,
  PreparedSubmission,
  Receipt,
  SubmissionAdapter,
  Tier,
} from '../types';

const PSST_SAFE_URL = 'https://safe.psst.org/to/safe';

class PsstSafeAdapter implements SubmissionAdapter {
  readonly entityId = 'psst-safe';
  readonly tier: Tier = 'A';

  // Own breaker per FR-9 — the invariant (no other channel depends on Psst
  // state) is wired from day one, ahead of Stage-2 programmatic deposits.
  private readonly breaker = new CircuitBreaker({
    name: 'dissemination-psst-safe',
    failureThreshold: 5,
    cooldownMs: 30 * 60 * 1000,
  });

  allowsDispatch(): boolean {
    return this.breaker.allowsRequest();
  }

  async prepare(view: DisseminationView, packet: Packet): Promise<PreparedSubmission> {
    const fields: Record<string, string> = {
      url: PSST_SAFE_URL,
      categories: view.categories.map((c) => categoryLabel(c)).join('; '),
    };
    if (view.location) fields.location = view.location;

    return {
      entityId: this.entityId,
      trackingId: view.trackingId,
      mode: 'deep-link',
      deepLink: {
        url: PSST_SAFE_URL,
        fields,
        depositBody: this.renderDepositBody(view, packet),
      },
    };
  }

  /**
   * Stage-1 dispatch is a handoff: the prepared deep link and deposit body
   * are stored on the submission and surfaced in the admin panel (and
   * optionally relayed to the reporter). Nothing leaves Vera automatically,
   * and this channel's state never gates any other (FR-9).
   */
  async dispatch(_prep: PreparedSubmission): Promise<DispatchResult> {
    return {
      outcome: 'handoff',
      detail: 'Psst Stage-1 deep-link handoff prepared; awaiting human deposit + manual receipt',
    };
  }

  parseReceipt(raw: unknown): Receipt | null {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    // Stage 1 has no machine receipt; treat any confirmation text as manual.
    return { type: 'manual', value: raw.trim(), receivedAt: new Date() };
  }

  private renderDepositBody(view: DisseminationView, packet: Packet): string {
    const files = view.evidence.files;
    const manifestLines =
      files.length === 0
        ? ['(no evidence files)']
        : files.map((f, i) => `${i + 1}. ${f.name}${f.cid ? ` — IPFS CID ${f.cid}` : ''}`);

    return [
      `Vera.Report handoff — tracking ID ${view.trackingId}`,
      '',
      `Categories: ${view.categories.map((c) => categoryLabel(c)).join('; ') || 'Uncategorized'}`,
      view.urgency ? `Urgency: ${view.urgency}` : null,
      view.dateOfIncident ? `Date of incident: ${view.dateOfIncident}` : null,
      '',
      'Narrative summary:',
      view.narrative,
      '',
      'Evidence manifest (encrypted originals pinned to IPFS — no decryption keys included):',
      ...manifestLines,
      view.evidence.evidenceHash ? `Evidence digest (SHA-256): ${view.evidence.evidenceHash}` : null,
      `Packet digest (SHA-256): ${packet.packetHash}`,
      '',
      view.zkProof
        ? `Midnight existence proof: ${view.zkProof.proofHash}` +
          (view.zkProof.txHash ? ` (tx ${view.zkProof.txHash})` : '')
        : null,
      '',
      'This deposit was prepared by Vera.Report with the reporter\'s consent.',
      'Decryption of evidence is escrowed and consent-gated; reference the tracking ID.',
    ]
      .filter((line): line is string => line !== null)
      .join('\n');
  }
}

export const psstSafeAdapter = new PsstSafeAdapter();
