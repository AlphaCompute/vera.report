/**
 * Tier C counsel-mediated adapter (Phase 3, VERA-PDR-001).
 *
 * Channels like EEOC, OSHA, and OSC require claimant identity, so Vera
 * cannot file them directly without breaking the identity firewall. The
 * adapter dispatches a handoff whose next step is counsel assignment
 * (matter code + scoped workspace link); counsel handles the identity leg
 * with the reporter entirely off-platform and the filing confirmation
 * returns as an attestation receipt.
 */

import { getEntity } from '../taxonomy';
import type {
  DisseminationView,
  DispatchResult,
  Packet,
  PreparedSubmission,
  Receipt,
  SubmissionAdapter,
  Tier,
} from '../types';

export class CounselAdapter implements SubmissionAdapter {
  readonly tier: Tier = 'C';

  constructor(readonly entityId: string) {}

  allowsDispatch(): boolean {
    return true; // no external call — the "dispatch" is a workflow handoff
  }

  async prepare(view: DisseminationView, _packet: Packet): Promise<PreparedSubmission> {
    const entity = getEntity(this.entityId);
    const name = entity?.name ?? this.entityId;
    return {
      entityId: this.entityId,
      trackingId: view.trackingId,
      mode: 'deep-link',
      deepLink: {
        url: '', // no portal — the workspace link is minted at assignment
        fields: { workflow: 'counsel-mediated' },
        depositBody: [
          `${name} — counsel-mediated filing for ${view.trackingId}`,
          '',
          `${name} requires claimant identity, which Vera.Report does not hold.`,
          'Next steps:',
          '1. Assign counsel to this channel (below) — this generates a matter code',
          '   and notifies the reporter to contact counsel directly, off-platform.',
          '2. Share the scoped workspace link with counsel (redacted packet + filing form).',
          '3. When counsel confirms filing, record their attestation with the',
          '   confirmation/charge number — that is this channel\'s receipt.',
        ].join('\n'),
      },
    };
  }

  async dispatch(_prep: PreparedSubmission): Promise<DispatchResult> {
    return {
      outcome: 'handoff',
      detail: `${this.entityId} awaiting counsel assignment and off-platform filing`,
    };
  }

  parseReceipt(raw: unknown): Receipt | null {
    if (typeof raw !== 'string' || !raw.trim()) return null;
    // Attestations are counsel-supplied confirmation artifacts — free-form.
    return { type: 'manual', value: raw.trim(), receivedAt: new Date() };
  }
}

export const eeocAdapter = new CounselAdapter('eeoc');
export const oshaAdapter = new CounselAdapter('osha');
export const oscAdapter = new CounselAdapter('osc');
export const agencyOigAdapter = new CounselAdapter('agency-oig');
