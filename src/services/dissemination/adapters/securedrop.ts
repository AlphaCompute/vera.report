/**
 * SecureDrop adapter — Stage-1 deep-link handoff (VERA-PDR-001 addendum A2).
 *
 * SecureDrop (Freedom of the Press Foundation) is a per-newsroom Tor onion
 * drop-box with no public API, so — exactly like the Psst Stage-1 channel —
 * Vera only PREPARES the disclosure: a ready-to-paste deposit body (narrative
 * summary, evidence CIDs + digests, Midnight proof reference — never decryption
 * keys) plus the FPF directory link where the reporter selects their newsroom
 * and submits anonymously over Tor. Nothing leaves Vera automatically.
 *
 * MVP: a single deep-link to securedrop.org/directory (reporter picks the
 * newsroom). Per-newsroom entity seeding from the directory is deferred.
 *
 * Consent: dispatch is gated on consent.press (reporter-elected, opt-in) in
 * disseminationService.approve — press disclosure is never dispatched without
 * an explicit press election. Non-blocking behind its own breaker (FR-9); the
 * receipt is the SecureDrop source codename, entered manually by the admin.
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

const SECUREDROP_DIRECTORY_URL = 'https://securedrop.org/directory';

class SecureDropAdapter implements SubmissionAdapter {
  readonly entityId = 'securedrop';
  readonly tier: Tier = 'B';

  // Own breaker per FR-9 — press-channel state never gates any other channel.
  private readonly breaker = new CircuitBreaker({
    name: 'dissemination-securedrop',
    failureThreshold: 5,
    cooldownMs: 30 * 60 * 1000,
  });

  allowsDispatch(): boolean {
    return this.breaker.allowsRequest();
  }

  async prepare(view: DisseminationView, packet: Packet): Promise<PreparedSubmission> {
    const fields: Record<string, string> = {
      url: SECUREDROP_DIRECTORY_URL,
      categories: view.categories.map((c) => categoryLabel(c)).join('; '),
    };
    if (view.location) fields.location = view.location;

    return {
      entityId: this.entityId,
      trackingId: view.trackingId,
      mode: 'deep-link',
      deepLink: {
        url: SECUREDROP_DIRECTORY_URL,
        fields,
        depositBody: this.renderDepositBody(view, packet),
      },
    };
  }

  /**
   * Stage-1 dispatch is a handoff: the prepared deep link + deposit body are
   * stored on the submission and surfaced in the admin panel (optionally
   * relayed to the reporter). Nothing leaves Vera automatically; this channel's
   * state never gates any other (FR-9).
   */
  async dispatch(_prep: PreparedSubmission): Promise<DispatchResult> {
    return {
      outcome: 'handoff',
      detail:
        'SecureDrop deep-link handoff prepared; reporter submits via a newsroom over Tor, then the codename is recorded as a manual receipt',
    };
  }

  parseReceipt(raw: unknown): Receipt | null {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    // SecureDrop issues a source codename, not a machine confirmation — manual.
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
      "Prepared by Vera.Report with the reporter's consent for press/media disclosure.",
      'Submit via a newsroom listed at securedrop.org/directory using Tor Browser.',
      'Decryption of evidence is escrowed and consent-gated; reference the tracking ID.',
    ]
      .filter((line): line is string => line !== null)
      .join('\n');
  }
}

export const securedropAdapter = new SecureDropAdapter();
