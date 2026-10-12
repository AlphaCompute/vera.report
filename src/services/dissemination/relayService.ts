/**
 * Relay service (Phase 3c, VERA-PDR-001 FR-11 upgrade).
 *
 * Two-way anonymous follow-up between agencies/counsel and the reporter.
 * Agency questions are entered by admins (or arrive via the receipt
 * mailboxes) and relayed to the reporter through the  * public status page; replies flow back the same path.
 *
 * The identity firewall is structural: RelayMessageDoc has no sender
 * field beyond the direction enum and no free-form metadata, so a message
 * physically cannot carry "who". Reporter access is authenticated by
 * knowledge of the tracking ID — the same trust model as the status page.
 * Admin identities appear only in the dissemination audit log.
 */

import crypto from 'node:crypto';
import { disseminationPersistence } from './disseminationPersistence';
import { getEntity } from './taxonomy';
import type { RelayMessageDoc } from './types';

const MAX_BODY_CHARS = 4000;

export interface RelayThreadMessage {
  messageId: string;
  entityId?: string;
  entityName?: string;
  direction: 'to-reporter' | 'from-reporter';
  body: string;
  createdAt: Date;
}

class RelayService {
  /**
   * Admin-entered follow-up (an agency or counsel question) relayed to
   * the reporter. The actor is audited, never stored on the message.
   */
  async postToReporter(
    trackingId: string,
    body: string,
    actor: string,
    entityId?: string,
  ): Promise<{ ok: boolean; error?: string }> {
    const trimmed = body?.trim();
    if (!trimmed) return { ok: false, error: 'empty_message' };
    if (entityId && !getEntity(entityId)) return { ok: false, error: 'unknown_entity' };

    await disseminationPersistence.insertRelayMessage({
      messageId: crypto.randomUUID(),
      trackingId,
      entityId,
      direction: 'to-reporter',
      body: trimmed.slice(0, MAX_BODY_CHARS),
      createdAt: new Date(),
    });
    await disseminationPersistence.appendAudit({
      trackingId,
      entityId,
      event: 'relay_message_to_reporter',
      actor,
      detail: { chars: Math.min(trimmed.length, MAX_BODY_CHARS) },
    });
    return { ok: true };
  }

  /**
   * Reporter reply from the status page. Authenticated upstream by
   * tracking-ID knowledge; recorded with no actor at all.
   */
  async postFromReporter(trackingId: string, body: string): Promise<{ ok: boolean; error?: string }> {
    const trimmed = body?.trim();
    if (!trimmed) return { ok: false, error: 'empty_message' };

    if (!await disseminationPersistence.hasRelayQuestion(trackingId)) {
      // Reply-auth strengthening (review): a reply is only accepted once an
      // agency/counsel question has actually been relayed to the reporter —
      // knowing the tracking ID is not sufficient to inject messages. (A
      // per-report reply token issued at intake is the recommended stronger
      // control and is tracked as a follow-up.)
      return { ok: false, error: 'no_open_thread' };
    }

    await disseminationPersistence.insertRelayMessage({
      messageId: crypto.randomUUID(),
      trackingId,
      direction: 'from-reporter',
      body: trimmed.slice(0, MAX_BODY_CHARS),
      createdAt: new Date(),
    });
    await disseminationPersistence.appendAudit({
      trackingId,
      event: 'relay_message_from_reporter',
      actor: 'reporter',
      detail: { chars: Math.min(trimmed.length, MAX_BODY_CHARS) },
    });
    return { ok: true };
  }

  /** Latest 200 messages, oldest first, with entity names resolved for display. */
  async getThread(trackingId: string): Promise<RelayThreadMessage[]> {
    const messages = await disseminationPersistence.getRelayThread(trackingId);
    return messages.map((m: RelayMessageDoc) => ({
      messageId: m.messageId,
      entityId: m.entityId,
      entityName: m.entityId ? getEntity(m.entityId)?.name ?? m.entityId : undefined,
      direction: m.direction,
      body: m.body,
      createdAt: m.createdAt,
    }));
  }
}

export const relayService = new RelayService();
