/**
 * Relay service tests (Phase 3c): two-way anonymous follow-up. The core
 * property under test is the structural identity firewall — messages
 * carry a direction and text, nothing else.
 */

import { relayService } from '../../../../src/services/dissemination/relayService';
import { disseminationPersistence } from '../../../../src/services/dissemination/disseminationPersistence';

const T1 = 'VRA-00000000000000AA';
const T2 = 'VRA-00000000000000BB';
const T3 = 'VRA-00000000000000CC';

describe('relay threads', () => {
  it('shows recent memory-backed messages without forgetting an old agency question', async () => {
    const trackingId = 'VRA-ABCDEFABCDEFABCD';
    for (let i = 0; i < 201; i++) {
      await disseminationPersistence.insertRelayMessage({ trackingId, messageId: `memory-${i}`, body: `message ${i}`, direction: i === 0 ? 'to-reporter' : 'from-reporter', createdAt: new Date(i) });
    }
    const thread = await relayService.getThread(trackingId);
    expect(thread).toHaveLength(200);
    expect(thread[0].body).toBe('message 1');
    expect(thread[199].body).toBe('message 200');
    expect(await relayService.postFromReporter(trackingId, 'still open')).toEqual({ ok: true });
  });
  it('relays admin-entered questions and reporter replies on one thread', async () => {
    const q = await relayService.postToReporter(
      T1,
      'CISA asks: what timeframe did the exfiltration cover?',
      'admin@test',
      'cisa',
    );
    expect(q).toEqual({ ok: true });

    const a = await relayService.postFromReporter(T1, 'Between March and May 2026.');
    expect(a).toEqual({ ok: true });

    const thread = await relayService.getThread(T1);
    expect(thread).toHaveLength(2);
    expect(thread[0]).toMatchObject({
      direction: 'to-reporter',
      entityId: 'cisa',
      entityName: 'CISA Incident Reporting',
    });
    expect(thread[1]).toMatchObject({ direction: 'from-reporter' });
    // Ordered oldest → newest.
    expect(thread[0].createdAt.getTime()).toBeLessThanOrEqual(thread[1].createdAt.getTime());
  });

  it('keeps threads isolated by tracking ID', async () => {
    await relayService.postToReporter(T2, 'Different report question', 'admin@test');
    const thread1 = await relayService.getThread(T1);
    const thread2 = await relayService.getThread(T2);
    expect(thread1.every((m) => !m.body.includes('Different report'))).toBe(true);
    expect(thread2).toHaveLength(1);
  });

  it('the message schema structurally cannot carry identity', async () => {
    const raw = await disseminationPersistence.getRelayThread(T1);
    const allowed = new Set(['body', 'createdAt', 'direction', 'entityId', 'messageId', 'trackingId', '_id']);
    for (const msg of raw) {
      // Only schema fields — no sender, email, chat id, or metadata.
      for (const key of Object.keys(msg)) {
        expect(allowed.has(key)).toBe(true);
      }
    }
    // The admin who relayed the question appears in the audit log only.
    const audit = await disseminationPersistence.getAuditForReport(T1);
    const relayEvents = audit.filter((e) => e.event.startsWith('relay_message'));
    expect(relayEvents.length).toBeGreaterThanOrEqual(2);
    expect(relayEvents.some((e) => e.actor === 'admin@test')).toBe(true);
    // Reporter messages are audited with the generic 'reporter' actor.
    expect(relayEvents.some((e) => e.actor === 'reporter')).toBe(true);
  });

  it('rejects a reporter reply until an agency/counsel question has been relayed', async () => {
    // Reply-auth strengthening (review): knowing the tracking ID is not
    // enough to seed a thread — a to-reporter message must exist first.
    expect(await relayService.postFromReporter(T3, 'Unsolicited reply')).toEqual({
      ok: false,
      error: 'no_open_thread',
    });
    // Nothing was persisted for the guessed tracking ID.
    expect(await relayService.getThread(T3)).toHaveLength(0);

    // Once a question is relayed, the reply is accepted.
    expect(await relayService.postToReporter(T3, 'Please clarify the dates.', 'admin@test', 'cisa')).toEqual({
      ok: true,
    });
    expect(await relayService.postFromReporter(T3, 'April 2026.')).toEqual({ ok: true });

    const thread = await relayService.getThread(T3);
    expect(thread.map((m) => m.direction)).toEqual(['to-reporter', 'from-reporter']);

    // The reply still carries no identity — only direction + body.
    const raw = await disseminationPersistence.getRelayThread(T3);
    const reply = raw.find((m) => m.direction === 'from-reporter');
    expect(reply).toBeDefined();
    const allowed = new Set(['body', 'createdAt', 'direction', 'entityId', 'messageId', 'trackingId', '_id']);
    for (const key of Object.keys(reply!)) {
      expect(allowed.has(key)).toBe(true);
    }
    // No sender field of any kind is stored on the reply.
    expect('sender' in reply!).toBe(false);
    expect(reply!.entityId).toBeUndefined();
  });

  it('rejects empty messages and unknown entities, and caps length', async () => {
    expect(await relayService.postToReporter(T1, '   ', 'admin@test')).toEqual({
      ok: false,
      error: 'empty_message',
    });
    expect(await relayService.postToReporter(T1, 'hi', 'admin@test', 'not-an-entity')).toEqual({
      ok: false,
      error: 'unknown_entity',
    });
    expect(await relayService.postFromReporter(T1, '')).toEqual({ ok: false, error: 'empty_message' });

    await relayService.postFromReporter(T1, 'x'.repeat(10_000));
    const thread = await relayService.getThread(T1);
    const longest = Math.max(...thread.map((m) => m.body.length));
    expect(longest).toBeLessThanOrEqual(4000);
  });
});
