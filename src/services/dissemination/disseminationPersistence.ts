import { protectFields } from '../privateRecord';
import { logger } from '../../utils/logger';
/**
 * MongoDB persistence for the Dissemination Service (VERA-PDR-001 §9).
 *
 * Collections (none stores reporter identity):
 * - dispositions            — approved dissemination plan per report
 * - submissions             — one per (report, entity); doubles as the dispatch queue
 * - dissemination_receipts  — entity-native receipt records
 * - routing_rules           — versioned, data-driven routing rules
 * - dissemination_audit_log — append-only transition events
 *
 * Runtime requires MongoDB. Memory stores are test doubles used only when
 * NODE_ENV=test and no MongoDB URI is configured.
 */

import crypto from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { MongoClient, Db, Collection, Filter } from 'mongodb';
import type {
  AuditAnchorDoc,
  AuditHistoryEntry,
  AuditBatchState,
  AuditEventDoc,
  ChannelState,
  ConsentSnapshot,
  CounselPartnerDoc,
  CounselAssignment,
  DispositionDoc,
  InboundMailDoc,
  ReceiptDoc,
  RelayMessageDoc,
  RoutingRuleDoc,
  SecureLinkRevealDoc,
  SubmissionDoc,
} from './types';
import { DEFAULT_ROUTING_MATRIX, CATEGORY_SLUGS, EU_ROUTING_RULES } from './taxonomy';

export class DisseminationPersistenceService {
  private memReceiptKeys = new Set<string>();
  private memRecipientCases = new Map<string, string>();
  private client: MongoClient | null = null;
  private db: Db | null = null;
  private dispositions: Collection<DispositionDoc> | null = null;
  private submissions: Collection<SubmissionDoc> | null = null;
  private receipts: Collection<ReceiptDoc> | null = null;
  private routingRules: Collection<RoutingRuleDoc> | null = null;
  private auditLog: Collection<AuditEventDoc> | null = null;
  private inboundMail: Collection<InboundMailDoc> | null = null;
  private counselPartners: Collection<CounselPartnerDoc> | null = null;
  private relayThreads: Collection<RelayMessageDoc> | null = null;
  private auditAnchors: Collection<AuditAnchorDoc> | null = null;
  private auditBatchState: Collection<AuditBatchState> | null = null;
  private memAuditBatchState: AuditBatchState = { _id: 'audit-anchor', revision: 0 };
  private locks: Collection<{ _id: string; lockedUntil: Date }> | null = null;
  private secureLinkReveals: Collection<SecureLinkRevealDoc> | null = null;
  private recipientGrants: Collection<{ tokenHash: string; expiresAt: Date; revoked: boolean }> | null = null;
  private memGrants = new Map<string, { expiresAt: Date; revoked: boolean }>();
  private isConnected = false;
  private seeded = false;
  private connecting: Promise<void> | null = null;

  /** Test-only storage when no MongoDB is configured. */
  private memDispositions = new Map<string, DispositionDoc>();
  private memSubmissions = new Map<string, SubmissionDoc>();
  private memReceipts: ReceiptDoc[] = [];
  private memRules: RoutingRuleDoc[] = [];
  private memAudit: AuditEventDoc[] = [];
  private memInbound = new Map<string, InboundMailDoc>();
  private memCounsel = new Map<string, CounselPartnerDoc>();
  private memRelay: RelayMessageDoc[] = [];
  private memAnchors: AuditAnchorDoc[] = [];

  private async connect(): Promise<void> {
    if (this.isConnected) return;
    if (!this.connecting) this.connecting = this.open();
    try { await this.connecting; } finally { this.connecting = null; }
  }

  private async open(): Promise<void> {
    const mongoUri = process.env.MONGODB_URI?.trim();
    if (!mongoUri) {
      if (process.env.NODE_ENV === 'test') return;
      throw new Error('Dissemination storage unavailable: MONGODB_URI is required');
    }

    const dbName = process.env.MONGODB_DB_NAME || 'vera';

    try {
      const tlsCAFile = process.env.MONGODB_TLS_CA_FILE;
      this.client = new MongoClient(mongoUri, {
        readPreference: 'primary',
        ...(tlsCAFile ? { tlsCAFile } : {}),
        serverSelectionTimeoutMS: 10000,
        writeConcern: { w: 'majority', j: true },
      });
      await this.client.connect();
      this.db = this.client.db(dbName);

      this.dispositions = this.db.collection<DispositionDoc>('dispositions');
      await this.dispositions.createIndex({ trackingId: 1 }, { unique: true });

      this.submissions = this.db.collection<SubmissionDoc>('submissions');
      await this.submissions.createIndex({ idempotencyKey: 1 }, { unique: true });
      await this.submissions.createIndex({ submissionId: 1 }, { unique: true });
      await this.submissions.createIndex({ trackingId: 1 });
      await this.submissions.createIndex({ state: 1, nextAttemptAt: 1 });

      this.receipts = this.db.collection<ReceiptDoc>('dissemination_receipts');
      await this.receipts.createIndex({ submissionId: 1 });
      await this.receipts.createIndex({ trackingId: 1 });

      this.routingRules = this.db.collection<RoutingRuleDoc>('routing_rules');
      await this.routingRules.createIndex({ ruleId: 1 }, { unique: true });
      await this.routingRules.createIndex({ active: 1, version: -1 });

      this.auditLog = this.db.collection<AuditEventDoc>('dissemination_audit_log');
      await this.auditLog.createIndex({ trackingId: 1, at: -1 });
      await this.auditLog.createIndex({ at: 1, _id: 1 });

      this.inboundMail = this.db.collection<InboundMailDoc>('dissemination_inbound');
      await this.inboundMail.createIndex({ inboundId: 1 }, { unique: true });
      await this.inboundMail.createIndex({ status: 1, receivedAt: -1 });

      this.counselPartners = this.db.collection<CounselPartnerDoc>('counsel_partners');
      await this.counselPartners.createIndex({ counselId: 1 }, { unique: true });
      await this.counselPartners.createIndex({ active: 1, channels: 1 });

      this.relayThreads = this.db.collection<RelayMessageDoc>('relay_threads');
      await this.relayThreads.createIndex({ messageId: 1 }, { unique: true });
      await this.relayThreads.createIndex({ trackingId: 1, createdAt: 1 });

      this.auditAnchors = this.db.collection<AuditAnchorDoc>('audit_anchors');
      await this.auditAnchors.createIndex({ anchorId: 1 }, { unique: true });
      await this.auditAnchors.createIndex({ anchoredAt: -1 });
      await this.auditAnchors.createIndex({ root: 1 });
      await this.auditAnchors.createIndex({ 'leaves.eventId': 1 });

      this.auditBatchState = this.db.collection<AuditBatchState>('audit_batch_state');
      this.locks = this.db.collection('dissemination_locks');

      this.secureLinkReveals = this.db.collection<SecureLinkRevealDoc>('secure_link_reveals');
      await this.secureLinkReveals.createIndex({ jti: 1 }, { unique: true });
      await this.secureLinkReveals.createIndex({ trackingId: 1 });

      this.recipientGrants = this.db.collection('recipient_grants');
      await this.recipientGrants.createIndex({ tokenHash: 1 }, { unique: true });
      await this.recipientGrants.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      this.isConnected = true;
      logger.info('[DISSEMINATION] Connected to MongoDB');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`[DISSEMINATION] MongoDB connection failed: ${msg}`);
      await this.client?.close().catch(() => {});
      this.clearHandles();
      throw err;
    }
  }

  /**
   * Close the MongoDB connection and drop cached handles (graceful shutdown /
   * test teardown). A subsequent operation reconnects lazily.
   */
  async disconnect(): Promise<void> {
    await this.connecting?.catch(() => {});
    try { await this.client?.close(); } finally { this.clearHandles(); }
  }

  private clearHandles(): void {
    this.seeded = false;
    this.client = null;
    this.db = null;
    this.isConnected = false;
    this.dispositions = null;
    this.submissions = null;
    this.receipts = null;
    this.routingRules = null;
    this.auditLog = null;
    this.inboundMail = null;
    this.counselPartners = null;
    this.relayThreads = null;
    this.auditAnchors = null;
    this.auditBatchState = null;
    this.locks = null;
    this.secureLinkReveals = null;
    this.recipientGrants = null;
  }

  async issueRecipientGrant(tokenHash: string, expiresAt: Date): Promise<void> {
    await this.connect();
    if (this.recipientGrants) {
      assertAcknowledged(await this.recipientGrants.updateOne({ tokenHash }, { $setOnInsert: { tokenHash, expiresAt, revoked: false } }, { upsert: true }));
    } else if (!this.memGrants.has(tokenHash)) this.memGrants.set(tokenHash, { expiresAt, revoked: false });
  }
  async recipientGrantActive(tokenHash: string): Promise<boolean> {
    await this.connect();
    const grant = this.recipientGrants ? await this.recipientGrants.findOne({ tokenHash }) : this.memGrants.get(tokenHash);
    return !!grant && !grant.revoked && grant.expiresAt.getTime() > Date.now();
  }
  async revokeRecipientGrant(tokenHash: string): Promise<void> {
    await this.connect();
    if (this.recipientGrants) assertAcknowledged(await this.recipientGrants.updateOne({ tokenHash }, { $set: { revoked: true } }));
    else { const grant = this.memGrants.get(tokenHash); if (grant) grant.revoked = true; }
  }

  // ── Dispositions ──────────────────────────────────────────────────

  async upsertDisposition(doc: DispositionDoc): Promise<void> {
    await this.connect();
    doc = await protectFields(doc, `disposition:${doc.trackingId}`, ['narrativeOverride'], 'seal');
    if (this.dispositions) {
      try {
        // Channel approval must not erase a review written independently.
        const { createdAt, ...fields } = doc;
        assertAcknowledged(await this.dispositions.updateOne({ trackingId: doc.trackingId }, {
          $set: fields, $setOnInsert: { createdAt },
        }, { upsert: true }));
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to upsert disposition: ${errMsg(err)}`);
        throw err;
      }
    }
    this.memDispositions.set(doc.trackingId, { ...this.memDispositions.get(doc.trackingId), ...doc });
  }

  /** Review is independent of routing: it never approves channels or queues delivery. */
  async saveNarrativeReview(
    trackingId: string,
    consentSnapshot: ConsentSnapshot,
    review: Pick<DispositionDoc, 'narrativeOverride' | 'narrativeReviewedAt' | 'narrativeReviewedBy'>,
  ): Promise<void> {
    await this.connect();
    const now = new Date();
    const fields = await protectFields({ ...review, updatedAt: now }, `disposition:${trackingId}`, ['narrativeOverride'], 'seal');
    const initial = { trackingId, channels: [], consentSnapshot, approvedBy: '', createdAt: now };
    if (this.dispositions) {
      assertAcknowledged(await this.dispositions.updateOne({ trackingId }, {
        $set: fields, $setOnInsert: initial,
      }, { upsert: true }));
    } else {
      this.memDispositions.set(trackingId, { ...(this.memDispositions.get(trackingId) ?? initial), ...fields });
    }
  }

  /** Reverting to the original requires a fresh review of that original. */
  async clearNarrativeReview(trackingId: string): Promise<void> {
    await this.connect();
    if (this.dispositions) {
      assertAcknowledged(await this.dispositions.updateOne({ trackingId }, {
        $unset: { narrativeOverride: '', narrativeReviewedAt: '', narrativeReviewedBy: '' },
        $set: { updatedAt: new Date() },
      }));
    } else {
      const doc = this.memDispositions.get(trackingId);
      if (doc) {
        delete doc.narrativeOverride;
        delete doc.narrativeReviewedAt;
        delete doc.narrativeReviewedBy;
        doc.updatedAt = new Date();
      }
    }
  }

  async getDisposition(trackingId: string): Promise<DispositionDoc | null> {
    await this.connect();
    if (this.dispositions) {
      try {
        return protectFields((await this.dispositions.findOne({ trackingId })) ?? null, `disposition:${trackingId}`, ['narrativeOverride'], 'open');
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get disposition: ${errMsg(err)}`);
        throw err;
      }
    }
    return protectFields(this.memDispositions.get(trackingId) ?? null, `disposition:${trackingId}`, ['narrativeOverride'], 'open');
  }

  /** Receipt progress is monotonic; terminal access revocations never match. */
  async advanceReceiptSubmission(submissionId: string, state: 'receipted' | 'acknowledged' | 'feedback_received', at: Date): Promise<void> {
    await this.connect();
    const allowed = receiptPredecessors(state);
    if (this.submissions) {
      // Plain updates work on DocumentDB as well as MongoDB. Every write
      // checks current state; timestamp stamps never overwrite an earlier receipt.
      const timestamps = state === 'receipted' ? [] : [
        'ackReceivedAt', ...(state === 'feedback_received' ? ['feedbackReceivedAt'] : []),
      ];
      for (const field of timestamps) {
        assertAcknowledged(await this.submissions.updateOne(
          { submissionId, state: { $in: allowed }, sla: { $type: 'object' }, [`sla.${field}`]: null },
          { $set: { [`sla.${field}`]: at } },
        ));
      }
      assertAcknowledged(await this.submissions.updateOne(
        { submissionId, state: { $in: allowed } },
        { $set: { state, updatedAt: at } },
      ));
      return;
    }
    const sub = [...this.memSubmissions.values()].find(s => s.submissionId === submissionId);
    if (!sub || !allowed.includes(sub.state)) return;
    sub.state = state; sub.updatedAt = at;
    if (sub.sla && state !== 'receipted') {
      sub.sla.ackReceivedAt ??= at;
      if (state === 'feedback_received') sub.sla.feedbackReceivedAt ??= at;
    }
  }

  async advanceReceiptChannel(trackingId: string, entityId: string, state: 'receipted' | 'acknowledged' | 'feedback_received'): Promise<void> {
    await this.connect();
    const allowed = receiptPredecessors(state);
    if (this.dispositions) {
      assertAcknowledged(await this.dispositions.updateOne(
        { trackingId, channels: { $elemMatch: { entityId, state: { $in: allowed } } } },
        { $set: { 'channels.$.state': state, updatedAt: new Date() } },
      ));
      return;
    }
    const channel = this.memDispositions.get(trackingId)?.channels.find(c => c.entityId === entityId);
    if (channel && allowed.includes(channel.state)) channel.state = state;
  }

  async setDispositionChannelState(trackingId: string, entityId: string, state: ChannelState, allowedFrom?: ChannelState[]): Promise<void> {
    await this.connect();
    if (this.dispositions) {
      try {
        assertAcknowledged(await this.dispositions.updateOne(
          { trackingId, ...(allowedFrom ? { channels: { $elemMatch: { entityId, state: { $in: allowedFrom } } } } : { 'channels.entityId': entityId }) },
          { $set: { 'channels.$.state': state, updatedAt: new Date() } },
        ));
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to set channel state: ${errMsg(err)}`);
        throw err;
      }
    }
    const disp = this.memDispositions.get(trackingId);
    if (disp) {
      const channel = disp.channels.find((c) => c.entityId === entityId);
      if (channel && (!allowedFrom || allowedFrom.includes(channel.state))) {
        channel.state = state;
        disp.updatedAt = new Date();
      }
    }
  }

  // ── One-time secure-packet links (single-use guard) ───────────────

  /**
   * Burn a one-time secure-packet link's `jti`. Returns true when this call
   * consumed it (first use), false when it was already consumed.
   *
   * FAIL-CLOSED — as with other runtime operations, there is NO
   * memory fallback. A single-use guarantee cannot be honored in-process (it
   * would reset on restart and not hold across instances), so if MongoDB is
   * unavailable this THROWS and the caller must refuse the reveal rather than
   * serve an unguarded packet.
   */
  async consumeSecureLink(args: {
    jti: string;
    trackingId: string;
    entityId: string;
    detail?: Record<string, unknown>;
  }): Promise<boolean> {
    await this.connect();
    if (!this.secureLinkReveals) {
      throw new Error('secure-link store unavailable — refusing reveal (fail-closed)');
    }
    try {
      assertAcknowledged(await this.secureLinkReveals.insertOne({ ...args, revealedAt: new Date() }));
      return true;
    } catch (err: unknown) {
      if (isDuplicateKeyError(err)) return false; // already revealed — replay rejected
      throw err; // unknown DB error — fail closed, do not serve
    }
  }

  /**
   * Whether a one-time link's `jti` is already consumed. Used by the
   * landing GET only (which never consumes). Database errors propagate; only
   * the test-only store may report no reveal without a MongoDB connection.
   */
  async isSecureLinkConsumed(jti: string): Promise<boolean> {
    await this.connect();
    if (!this.secureLinkReveals) return false;
    return (await this.secureLinkReveals.countDocuments({ jti })) > 0;
  }

  // ── Submissions (dispatch queue) ──────────────────────────────────

  /** Insert a submission; returns false when the idempotency key already exists. */
  async insertSubmission(doc: SubmissionDoc): Promise<boolean> {
    await this.connect();
    if (this.submissions) {
      try {
        assertAcknowledged(await this.submissions.insertOne(doc));
        return true;
      } catch (err: unknown) {
        if (isDuplicateKeyError(err)) return false;
        logger.error(`[DISSEMINATION] Failed to insert submission: ${errMsg(err)}`);
        throw err;
      }
    }
    if (this.memSubmissions.has(doc.idempotencyKey)) return false;
    this.memSubmissions.set(doc.idempotencyKey, doc);
    return true;
  }

  async getSubmission(submissionId: string): Promise<SubmissionDoc | null> {
    await this.connect();
    if (this.submissions) {
      try {
        return (await this.submissions.findOne({ submissionId })) ?? null;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get submission: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memSubmissions.values()].find((s) => s.submissionId === submissionId) ?? null;
  }

  async getSubmissionsForReport(trackingId: string): Promise<SubmissionDoc[]> {
    await this.connect();
    if (this.submissions) {
      try {
        return await this.submissions.find({ trackingId }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list submissions: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memSubmissions.values()].filter((s) => s.trackingId === trackingId);
  }

  /** First writer wins; retries use the persisted matter rather than replacing it. */
  async ensureCounselAssignment(submissionId: string, assignment: CounselAssignment): Promise<CounselAssignment> {
    await this.connect();
    if (this.submissions) {
      assertAcknowledged(await this.submissions.updateOne(
        { submissionId, counsel: { $exists: false }, state: { $nin: ['withdrawn', 'failed', 'closed', 'suppressed'] } },
        { $set: { counsel: assignment, updatedAt: new Date() } },
      ));
      const sub = await this.submissions.findOne({ submissionId });
      if (!sub?.counsel || ['withdrawn', 'failed', 'closed', 'suppressed'].includes(sub.state)) throw new Error('Assignment unavailable');
      return sub.counsel;
    }
    const sub = [...this.memSubmissions.values()].find(s => s.submissionId === submissionId);
    if (!sub || ['withdrawn', 'failed', 'closed', 'suppressed'].includes(sub.state)) throw new Error('Assignment unavailable');
    if (!sub.counsel) sub.counsel = assignment;
    return sub.counsel;
  }

  /** Persist correlation before external send; CASE references grant no reporter access. */
  async registerRecipientCase(caseReference: string, entityId: string, trackingId: string): Promise<void> {
    await this.connect();
    const id = JSON.stringify([caseReference, entityId]);
    if (this.db) {
      const cases = this.db.collection<{ _id: string; trackingId: string }>('dissemination_recipient_cases');
      assertAcknowledged(await cases.updateOne({ _id: id, trackingId }, { $setOnInsert: { trackingId } }, { upsert: true }));
      return;
    }
    const existing = this.memRecipientCases.get(id);
    if (existing && existing !== trackingId) throw new Error('Recipient case reference collision');
    this.memRecipientCases.set(id, trackingId);
  }

  async resolveRecipientCase(caseReference: string, entityId: string): Promise<string | undefined> {
    await this.connect();
    const id = JSON.stringify([caseReference, entityId]);
    if (this.db) {
      const mapped = await this.db.collection<{ _id: string; trackingId: string }>('dissemination_recipient_cases').findOne({ _id: id });
      return mapped?.trackingId ?? (await this.submissions!.findOne({ caseReference, entityId }))?.trackingId;
    }
    return this.memRecipientCases.get(id) ?? [...this.memSubmissions.values()].find(s => s.caseReference === caseReference && s.entityId === entityId)?.trackingId;
  }

  /** Dispatch and withdrawal compete atomically for the same unsent row. */
  async updateUnsentSubmission(submissionId: string, updates: Partial<SubmissionDoc>, allowFailed = false, claimToken?: string): Promise<boolean> {
    await this.connect();
    const allowed = ['approved', 'deferred', 'packet_ready', ...(allowFailed ? ['failed'] : [])];
    if (this.submissions) {
      const set: Record<string, unknown> = { updatedAt: new Date() };
      const unset: Record<string, ''> = {};
      for (const [key, value] of Object.entries(updates)) {
        if (value === undefined) unset[key] = ''; else set[key] = value;
      }
      const result = await this.submissions.updateOne(
        { submissionId, ...(claimToken ? { claimToken } : {}), state: { $in: allowed as ChannelState[] }, dispatchInFlightAt: { $exists: false } },
        { $set: set, ...(Object.keys(unset).length ? { $unset: unset } : {}) },
      );
      assertAcknowledged(result);
      return result.matchedCount === 1;
    }
    const sub = [...this.memSubmissions.values()].find(s => s.submissionId === submissionId);
    if (!sub || (claimToken && sub.claimToken !== claimToken) || !allowed.includes(sub.state) || sub.dispatchInFlightAt) return false;
    Object.assign(sub, updates, { updatedAt: new Date() });
    return true;
  }

  async claimDispatch(submissionId: string, claimToken?: string): Promise<boolean> {
    await this.connect();
    if (this.submissions) {
      const result = await this.submissions.updateOne(
        { submissionId, ...(claimToken ? { claimToken } : {}), state: 'packet_ready', dispatchInFlightAt: { $exists: false } },
        { $set: { dispatchInFlightAt: new Date() } },
      );
      assertAcknowledged(result); return result.matchedCount === 1;
    }
    const sub = [...this.memSubmissions.values()].find(s => s.submissionId === submissionId);
    if (!sub || (claimToken && sub.claimToken !== claimToken) || sub.state !== 'packet_ready' || sub.dispatchInFlightAt) return false;
    sub.dispatchInFlightAt = new Date(); return true;
  }

  async patchSubmission(
    submissionId: string,
    updates: Partial<Omit<SubmissionDoc, 'submissionId' | 'idempotencyKey' | 'createdAt'>>,
    claimToken?: string,
  ): Promise<boolean> {
    await this.connect();
    const now = new Date();
    // Split defined vs undefined: a bare `$set` of undefined is dropped by the
    // driver (ignoreUndefined), so an explicit `undefined` must $unset to truly
    // clear the field (e.g. nextAttemptAt/lastError/dispatchInFlightAt).
    const setOps: Record<string, unknown> = { updatedAt: now };
    const unsetOps: Record<string, ''> = {};
    for (const [k, v] of Object.entries(updates)) {
      if (v === undefined) unsetOps[k] = '';
      else setOps[k] = v;
    }
    if (this.submissions) {
      try {
        const update: Record<string, unknown> = { $set: setOps };
        if (Object.keys(unsetOps).length > 0) update.$unset = unsetOps;
        const result = await this.submissions.updateOne({ submissionId, ...(claimToken ? { claimToken } : {}) }, update);
        assertAcknowledged(result);
        return result.matchedCount === 1;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to patch submission: ${errMsg(err)}`);
        throw err;
      }
    }
    for (const [key, sub] of this.memSubmissions) {
      if (sub.submissionId === submissionId && (!claimToken || sub.claimToken === claimToken)) {
        const merged: SubmissionDoc = { ...sub, updatedAt: now };
        for (const [k, v] of Object.entries(updates)) {
          if (v === undefined) delete (merged as unknown as Record<string, unknown>)[k];
          else (merged as unknown as Record<string, unknown>)[k] = v;
        }
        this.memSubmissions.set(key, merged);
        return true;
      }
    }
    return false;
  }

  /**
   * Atomically claim one due submission for dispatch: state in the claimable
   * set and nextAttemptAt due. Moves it to the transient 'packet_ready' state
   * with a fresh token fencing writes from an expired worker. The unique
   * idempotencyKey deduplicates queue rows, not external sends. Stale 'packet_ready'
   * rows (a worker died mid-processing) become claimable again after 10
   * minutes.
   */
  async claimNextDueSubmission(now: Date): Promise<SubmissionDoc | null> {
    await this.connect();
    const staleBefore = new Date(now.getTime() - 10 * 60 * 1000);
    const claimToken = crypto.randomUUID();
    const filter: Filter<SubmissionDoc> = {
      $or: [
        {
          state: { $in: ['approved', 'deferred'] as ChannelState[] },
          $or: [{ nextAttemptAt: { $exists: false } }, { nextAttemptAt: { $lte: now } }],
        },
        { state: 'packet_ready' as ChannelState, updatedAt: { $lte: staleBefore } },
      ],
    };
    if (this.submissions) {
      try {
        const result = await this.submissions.findOneAndUpdate(
          filter,
          { $set: { state: 'packet_ready' as ChannelState, updatedAt: now, claimToken } },
          { returnDocument: 'after' },
        );
        return result ?? null;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to claim submission: ${errMsg(err)}`);
        throw err;
      }
    }
    for (const sub of this.memSubmissions.values()) {
      const due = !sub.nextAttemptAt || sub.nextAttemptAt <= now;
      const claimable =
        ((sub.state === 'approved' || sub.state === 'deferred') && due) ||
        (sub.state === 'packet_ready' && sub.updatedAt <= staleBefore);
      if (claimable) {
        sub.state = 'packet_ready';
        sub.updatedAt = now;
        sub.claimToken = claimToken;
        return { ...sub };
      }
    }
    return null;
  }

  /** Submissions with running SLA clocks (dispatched or receipted). */
  async getSubmissionsWithOpenSla(): Promise<SubmissionDoc[]> {
    await this.connect();
    const states: ChannelState[] = ['dispatched', 'receipted', 'acknowledged'];
    if (this.submissions) {
      try {
        return await this.submissions.find({ state: { $in: states }, sla: { $exists: true } }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list SLA submissions: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memSubmissions.values()].filter((s) => states.includes(s.state) && s.sla);
  }

  /**
   * Compare-and-set one SLA clock to breached (#1043). Returns true only for
   * the caller that made the transition, so with several API tasks sweeping
   * the same submission exactly one appends the audit event and alerts. The
   * filter repeats every breach condition so a receipt recorded since the
   * sweep read the row also wins over the breach.
   */
  async markSlaBreached(submissionId: string, clock: 'ack' | 'feedback', now: Date): Promise<boolean> {
    await this.connect();
    const states: ChannelState[] = ['dispatched', 'receipted', 'acknowledged'];
    const due = `sla.${clock}DueAt`, received = `sla.${clock}ReceivedAt`, breached = `sla.${clock}Breached`;
    if (this.submissions) {
      const result = await this.submissions.updateOne(
        { submissionId, state: { $in: states }, [due]: { $type: 'date', $lt: now }, [received]: null, [breached]: { $ne: true } },
        { $set: { [breached]: true, updatedAt: now } },
      );
      assertAcknowledged(result);
      return result.modifiedCount === 1;
    }
    const sub = [...this.memSubmissions.values()].find(s => s.submissionId === submissionId);
    const sla = sub?.sla;
    if (!sub || !sla || !states.includes(sub.state)) return false;
    const dueAt = clock === 'ack' ? sla.ackDueAt : sla.feedbackDueAt;
    const receivedAt = clock === 'ack' ? sla.ackReceivedAt : sla.feedbackReceivedAt;
    const already = clock === 'ack' ? sla.ackBreached : sla.feedbackBreached;
    if (!dueAt || receivedAt || already || !(now > new Date(dueAt))) return false;
    if (clock === 'ack') sla.ackBreached = true; else sla.feedbackBreached = true;
    sub.updatedAt = now;
    return true;
  }

  /**
   * Submissions needing admin attention (alerts rail, NFR-3 + §8):
   * dead-lettered channels and open channels with a breached SLA clock.
   */
  async listAttentionSubmissions(limit = 100): Promise<SubmissionDoc[]> {
    await this.connect();
    const openStates: ChannelState[] = ['dispatched', 'receipted', 'acknowledged'];
    if (this.submissions) {
      try {
        return await this.submissions
          .find({
            $or: [
              { state: 'failed' },
              { state: { $in: openStates }, 'sla.ackBreached': true },
              { state: { $in: openStates }, 'sla.feedbackBreached': true },
            ],
          })
          .sort({ updatedAt: -1 })
          .limit(limit)
          .toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list attention submissions: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memSubmissions.values()]
      .filter(
        (s) =>
          s.state === 'failed' ||
          (openStates.includes(s.state) && (s.sla?.ackBreached || s.sla?.feedbackBreached)),
      )
      .sort((a, b) => (b.updatedAt?.getTime() ?? 0) - (a.updatedAt?.getTime() ?? 0))
      .slice(0, limit);
  }

  /** All submissions, newest first (outcome analytics). */
  async listSubmissions(limit = 2000): Promise<SubmissionDoc[]> {
    await this.connect();
    if (this.submissions) {
      try {
        return await this.submissions.find({}).sort({ createdAt: -1 }).limit(limit).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list submissions: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memSubmissions.values()]
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  // ── Receipts ──────────────────────────────────────────────────────

  async insertReceipt(doc: ReceiptDoc, idempotencyKey?: string): Promise<void> {
    await this.connect();
    if (this.receipts) {
      try {
        if (idempotencyKey) {
          assertAcknowledged(await this.receipts.updateOne({ _id: idempotencyKey as any }, { $setOnInsert: doc }, { upsert: true }));
        } else {
          assertAcknowledged(await this.receipts.insertOne(doc));
        }
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to insert receipt: ${errMsg(err)}`);
        throw err;
      }
    }
    if (!idempotencyKey || !this.memReceiptKeys.has(idempotencyKey)) {
      this.memReceipts.push(doc);
      if (idempotencyKey) this.memReceiptKeys.add(idempotencyKey);
    }
  }

  async getReceiptsForReport(trackingId: string): Promise<ReceiptDoc[]> {
    await this.connect();
    if (this.receipts) {
      try {
        return await this.receipts.find({ trackingId }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list receipts: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memReceipts.filter((r) => r.trackingId === trackingId);
  }

  // ── Routing rules ─────────────────────────────────────────────────

  /**
   * Seed the default routing matrix as version-1 rules when the collection
   * is empty (PDR §6: rules are data, editable without redeploy).
   */
  async seedDefaultRules(): Promise<void> {
    if (this.seeded) return;
    await this.connect();
    const now = new Date();
    const seeds: RoutingRuleDoc[] = CATEGORY_SLUGS.map((slug) => ({
      ruleId: `default-${slug}-v1`,
      match: { categories: [slug] },
      route: DEFAULT_ROUTING_MATRIX[slug],
      version: 1,
      effectiveFrom: now,
      active: true,
      createdAt: now,
    }));
    // EU Directive rules (Phase 4c) — jurisdiction-constrained.
    seeds.push(
      ...EU_ROUTING_RULES.map((rule) => ({
        ruleId: rule.ruleId,
        match: {
          ...(rule.categories ? { categories: [...rule.categories] } : {}),
          jurisdiction: [...rule.jurisdiction],
        },
        route: [...rule.route],
        version: 1,
        effectiveFrom: now,
        active: true,
        createdAt: now,
      })),
    );

    // Seed only ruleIds that don't exist yet (active or not), so
    // deployments that seeded before a later phase added rules pick up
    // the new ones without resurrecting admin-deactivated rules.
    let existing: Set<string>;
    if (this.routingRules) {
      try {
        const docs = await this.routingRules.find({}, { projection: { ruleId: 1 } }).toArray();
        existing = new Set(docs.map((d) => d.ruleId));
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to read routing rules for seeding: ${errMsg(err)}`);
        throw err;
      }
    } else {
      existing = new Set(this.memRules.map((r) => r.ruleId));
    }
    const missing = seeds.filter((s) => !existing.has(s.ruleId));
    if (missing.length === 0) { this.seeded = true; return; }

    if (this.routingRules) {
      try {
        assertAcknowledged(await this.routingRules.insertMany(missing, { ordered: false }));
        this.seeded = true;
        logger.info(`[DISSEMINATION] Seeded ${missing.length} default routing rules`);
        return;
      } catch (err: unknown) {
        if (!isDuplicateKeyError(err)) {
          logger.error(`[DISSEMINATION] Failed to seed routing rules: ${errMsg(err)}`);
          throw err;
        }
        return;
      }
    }
    this.memRules.push(...missing);
    this.seeded = true;
  }

  async getActiveRules(): Promise<RoutingRuleDoc[]> {
    await this.connect();
    if (this.routingRules) {
      try {
        return await this.routingRules.find({ active: true }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list routing rules: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memRules.filter((r) => r.active);
  }

  /** All rules including deactivated ones — for the admin rules editor. */
  async listAllRules(): Promise<RoutingRuleDoc[]> {
    await this.connect();
    await this.seedDefaultRules();
    if (this.routingRules) {
      try {
        return await this.routingRules.find({}).sort({ ruleId: 1 }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list all routing rules: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memRules].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  }

  /**
   * Create or update a routing rule (admin rules editor). Updates bump
   * `version`; `createdAt` is preserved on existing rules.
   */
  async upsertRoutingRule(
    rule: Omit<RoutingRuleDoc, 'version' | 'createdAt' | 'effectiveFrom'> &
      Partial<Pick<RoutingRuleDoc, 'effectiveFrom'>>,
  ): Promise<RoutingRuleDoc> {
    await this.connect();
    const now = new Date();

    if (this.routingRules) {
      try {
        const existing = await this.routingRules.findOne({ ruleId: rule.ruleId });
        const doc: RoutingRuleDoc = {
          ruleId: rule.ruleId,
          match: rule.match,
          route: rule.route,
          active: rule.active,
          version: (existing?.version ?? 0) + 1,
          effectiveFrom: rule.effectiveFrom ?? now,
          createdAt: existing?.createdAt ?? now,
        };
        assertAcknowledged(await this.routingRules.replaceOne({ ruleId: rule.ruleId }, doc, { upsert: true }));
        return doc;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to upsert routing rule: ${errMsg(err)}`);
        throw err;
      }
    }

    const idx = this.memRules.findIndex((r) => r.ruleId === rule.ruleId);
    const doc: RoutingRuleDoc = {
      ruleId: rule.ruleId,
      match: rule.match,
      route: rule.route,
      active: rule.active,
      version: (idx >= 0 ? this.memRules[idx].version : 0) + 1,
      effectiveFrom: rule.effectiveFrom ?? now,
      createdAt: idx >= 0 ? this.memRules[idx].createdAt : now,
    };
    if (idx >= 0) this.memRules[idx] = doc;
    else this.memRules.push(doc);
    return doc;
  }

  // ── Inbound receipt mail (Phase 2a) ───────────────────────────────

  async insertInboundMail(doc: InboundMailDoc): Promise<void> {
    await this.connect();
    doc = await protectFields(doc, `inbound:${doc.inboundId}`, ['body', 'subject', 'from', 's3Key'], 'seal');
    if (this.inboundMail) {
      try {
        assertAcknowledged(await this.inboundMail.insertOne(doc));
        return;
      } catch (err: unknown) {
        if (isDuplicateKeyError(err)) return; // SES redelivery — already stored
        logger.error(`[DISSEMINATION] Failed to insert inbound mail: ${errMsg(err)}`);
        throw err;
      }
    }
    if (!this.memInbound.has(doc.inboundId)) this.memInbound.set(doc.inboundId, doc);
  }

  async getInboundMail(inboundId: string): Promise<InboundMailDoc | null> {
    await this.connect();
    if (this.inboundMail) {
      try {
        return protectFields((await this.inboundMail.findOne({ inboundId })) ?? null, `inbound:${inboundId}`, ['body', 'subject', 'from', 's3Key'], 'open');
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get inbound mail: ${errMsg(err)}`);
        throw err;
      }
    }
    return protectFields(this.memInbound.get(inboundId) ?? null, `inbound:${inboundId}`, ['body', 'subject', 'from', 's3Key'], 'open');
  }

  async listInboundMail(status?: InboundMailDoc['status'], limit = 100): Promise<InboundMailDoc[]> {
    await this.connect();
    if (this.inboundMail) {
      try {
        const filter = status ? { status } : {};
        return Promise.all((await this.inboundMail.find(filter).sort({ receivedAt: -1 }).limit(limit).toArray()).map(doc => protectFields(doc, `inbound:${doc.inboundId}`, ['body', 'subject', 'from', 's3Key'], 'open')));
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list inbound mail: ${errMsg(err)}`);
        throw err;
      }
    }
    return Promise.all([...this.memInbound.values()]
      .filter((m) => !status || m.status === status)
      .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime())
      .slice(0, limit).map(doc => protectFields(doc, `inbound:${doc.inboundId}`, ['body', 'subject', 'from', 's3Key'], 'open')));
  }

  async patchInboundMail(
    inboundId: string,
    updates: Partial<Omit<InboundMailDoc, 'inboundId' | 'createdAt'>>,
  ): Promise<void> {
    await this.connect();
    updates = await protectFields(updates, `inbound:${inboundId}`, ['body', 'subject', 'from', 's3Key'], 'seal');
    if (this.inboundMail) {
      try {
        assertAcknowledged(await this.inboundMail.updateOne({ inboundId }, { $set: updates }));
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to patch inbound mail: ${errMsg(err)}`);
        throw err;
      }
    }
    const existing = this.memInbound.get(inboundId);
    if (existing) this.memInbound.set(inboundId, { ...existing, ...updates });
  }

  // ── Counsel bench (Phase 3a) ──────────────────────────────────────

  async upsertCounselPartner(doc: CounselPartnerDoc): Promise<void> {
    await this.connect();
    if (this.counselPartners) {
      try {
        assertAcknowledged(await this.counselPartners.replaceOne({ counselId: doc.counselId }, doc, { upsert: true }));
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to upsert counsel partner: ${errMsg(err)}`);
        throw err;
      }
    }
    this.memCounsel.set(doc.counselId, doc);
  }

  async getCounselPartner(counselId: string): Promise<CounselPartnerDoc | null> {
    await this.connect();
    if (this.counselPartners) {
      try {
        return (await this.counselPartners.findOne({ counselId })) ?? null;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get counsel partner: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memCounsel.get(counselId) ?? null;
  }

  async listCounselPartners(activeOnly = false): Promise<CounselPartnerDoc[]> {
    await this.connect();
    if (this.counselPartners) {
      try {
        const filter = activeOnly ? { active: true } : {};
        return await this.counselPartners.find(filter).sort({ name: 1 }).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list counsel partners: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memCounsel.values()]
      .filter((c) => !activeOnly || c.active)
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Active partners able to file a given entity channel. */
  async findCounselForChannel(entityId: string): Promise<CounselPartnerDoc[]> {
    const partners = await this.listCounselPartners(true);
    return partners.filter((c) => c.channels.includes(entityId));
  }

  // ── Relay threads (Phase 3c) ──────────────────────────────────────

  async insertRelayMessage(doc: RelayMessageDoc): Promise<void> {
    await this.connect();
    doc = await protectFields(doc, `relay:${doc.trackingId}:${doc.messageId}`, ['body'], 'seal');
    if (this.relayThreads) {
      try {
        assertAcknowledged(await this.relayThreads.insertOne(doc));
        return;
      } catch (err: unknown) {
        if (isDuplicateKeyError(err)) return;
        logger.error(`[DISSEMINATION] Failed to insert relay message: ${errMsg(err)}`);
        throw err;
      }
    }
    if (!this.memRelay.some((m) => m.messageId === doc.messageId)) this.memRelay.push(doc);
  }

  async getRelayThread(trackingId: string, limit = 200): Promise<RelayMessageDoc[]> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) throw new Error('Invalid relay window size');
    await this.connect();
    if (this.relayThreads) {
      try {
        const latest = await this.relayThreads.find({ trackingId }).sort({ createdAt: -1, _id: -1 }).limit(limit).toArray();
        return Promise.all(latest.reverse().map(doc => protectFields(doc, `relay:${doc.trackingId}:${doc.messageId}`, ['body'], 'open')));
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get relay thread: ${errMsg(err)}`);
        throw err;
      }
    }
    return Promise.all(this.memRelay
      .filter((m) => m.trackingId === trackingId)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
      .slice(-limit).map(doc => protectFields(doc, `relay:${doc.trackingId}:${doc.messageId}`, ['body'], 'open')));
  }

  /** Reply authorization must not depend on whether an older question is in the visible window. */
  async hasRelayQuestion(trackingId: string): Promise<boolean> {
    await this.connect();
    if (this.relayThreads) {
      return !!await this.relayThreads.findOne({ trackingId, direction: 'to-reporter' }, { projection: { _id: 1 } });
    }
    return this.memRelay.some(message => message.trackingId === trackingId && message.direction === 'to-reporter');
  }

  // ── Audit log (NFR-4) ─────────────────────────────────────────────

  async appendAudit(event: Omit<AuditEventDoc, 'eventId' | 'at'>, idempotencyKey?: string): Promise<void> {
    await this.connect();
    const doc: AuditEventDoc = {
      ...event,
      eventId: idempotencyKey ?? crypto.randomUUID(),
      at: new Date(),
    };
    if (this.auditLog) {
      try {
        if (idempotencyKey) {
          // Mongo's built-in unique _id makes retries (including lost acknowledgements) idempotent.
          assertAcknowledged(await this.auditLog.updateOne({ _id: idempotencyKey as any }, { $setOnInsert: doc }, { upsert: true }));
        } else {
          assertAcknowledged(await this.auditLog.insertOne(doc));
        }
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to append audit event: ${errMsg(err)}`);
        throw err;
      }
    }
    if (!this.memAudit.some(e => e.eventId === doc.eventId)) this.memAudit.push(doc);
  }

  async getAuditForReport(trackingId: string): Promise<AuditEventDoc[]> {
    await this.connect();
    if (this.auditLog) {
      try {
        return await this.auditLog.find({ trackingId }).sort({ at: -1 }).limit(200).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list audit events: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memAudit.filter((e) => e.trackingId === trackingId);
  }

  /** Unanchored events, oldest first; event timestamps are not ingestion cursors. */
  async getUnanchoredAuditEvents(limit = 2048): Promise<AuditEventDoc[]> {
    await this.connect();
    if (this.auditLog) {
      try {
        return await this.auditLog.aggregate<AuditEventDoc>([
          { $sort: { at: 1, _id: 1 } },
          { $lookup: {
            from: 'audit_anchors', localField: 'eventId', foreignField: 'leaves.eventId',
            pipeline: [{ $limit: 1 }, { $project: { _id: 1 } }], as: 'existingAnchor',
          } },
          { $match: { 'existingAnchor.0': { $exists: false } } },
          { $limit: limit },
          { $unset: 'existingAnchor' },
        ]).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to page audit events: ${errMsg(err)}`);
        throw err;
      }
    }
    const anchored = new Set(this.memAnchors.flatMap((anchor) => anchor.leaves.map((leaf) => leaf.eventId)));
    return this.memAudit
      .filter((e) => !anchored.has(e.eventId))
      .sort((a, b) => a.at.getTime() - b.at.getTime())
      .slice(0, limit);
  }

  // ── Audit anchors (Phase 4b) ──────────────────────────────────────

  async getAuditBatchState(): Promise<AuditBatchState> {
    await this.connect();
    if (!this.auditBatchState) return structuredClone(this.memAuditBatchState);
    try {
      assertAcknowledged(await this.auditBatchState.updateOne({ _id: 'audit-anchor' },
        { $setOnInsert: { revision: 0 } }, { upsert: true }));
    } catch (error) {
      if (!isDuplicateKeyError(error)) throw error;
    }
    const state = await this.auditBatchState.findOne({ _id: 'audit-anchor' });
    if (!state) throw new Error('Audit coordinator unavailable');
    return state;
  }

  /** Every state change fences stale snapshots, including candidate batch selection. */
  async compareAuditBatch(revision: number, batch: AuditBatchState['batch'], completedRoot?: string): Promise<boolean> {
    if (completedRoot !== undefined && (batch !== undefined || !/^[a-f0-9]{64}$/.test(completedRoot))) throw new Error('Invalid completed audit root');
    await this.connect();
    if (!this.auditBatchState) {
      if (this.memAuditBatchState.revision !== revision || (completedRoot !== undefined &&
          (this.memAuditBatchState.batch?.state !== 'complete' || this.memAuditBatchState.batch.anchor.root !== completedRoot))) return false;
      this.memAuditBatchState = { _id: 'audit-anchor', revision: revision + 1,
        ...((completedRoot ?? this.memAuditBatchState.lastRoot) ? { lastRoot: completedRoot ?? this.memAuditBatchState.lastRoot } : {}),
        ...(batch ? { batch: structuredClone(batch) } : {}) };
      return true;
    }
    const result = await this.auditBatchState.updateOne({ _id: 'audit-anchor', revision,
      ...(completedRoot !== undefined ? { 'batch.state': 'complete', 'batch.anchor.root': completedRoot } : {}) },
      batch ? { $inc: { revision: 1 }, $set: { batch } } : { $inc: { revision: 1 }, $unset: { batch: '' },
        ...(completedRoot !== undefined ? { $set: { lastRoot: completedRoot } } : {}) });
    assertAcknowledged(result);
    return result.matchedCount === 1;
  }

  /** Retry the same completed batch after an uncertain insert acknowledgement. */
  async ensureAuditAnchor(doc: AuditAnchorDoc): Promise<void> {
    await this.connect();
    if (!this.auditAnchors) {
      const existing = this.memAnchors.find(anchor => anchor.anchorId === doc.anchorId);
      if (!existing) { this.memAnchors.push(structuredClone(doc)); return; }
      if (!isDeepStrictEqual(existing, doc)) throw new Error('Conflicting completed audit batch');
      return;
    }
    try {
      assertAcknowledged(await this.auditAnchors.insertOne({ ...doc }));
    } catch (error) {
      if (!isDuplicateKeyError(error)) throw error;
      const existing = await this.auditAnchors.findOne({ anchorId: doc.anchorId });
      if (!existing) throw error;
      const { _id, ...stored } = existing;
      if (!isDeepStrictEqual(stored, doc)) throw new Error('Conflicting completed audit batch');
    }
  }

  async insertAuditAnchor(doc: AuditAnchorDoc): Promise<void> {
    await this.connect();
    if (this.auditAnchors) {
      try {
        assertAcknowledged(await this.auditAnchors.insertOne({ ...doc }));
        return;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to insert audit anchor: ${errMsg(err)}`);
        throw err;
      }
    }
    this.memAnchors.push(doc);
  }

  async getLatestAuditAnchor(): Promise<AuditAnchorDoc | null> {
    await this.connect();
    if (this.auditAnchors) {
      try {
        const [latest] = await this.auditAnchors.find({}).sort({ anchoredAt: -1 }).limit(1).toArray();
        return latest ?? null;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to get latest anchor: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memAnchors.length > 0 ? this.memAnchors[this.memAnchors.length - 1] : null;
  }

  async listAuditAnchors(limit = 50): Promise<AuditAnchorDoc[]> {
    await this.connect();
    if (this.auditAnchors) {
      try {
        return await this.auditAnchors.find({}).sort({ anchoredAt: -1 }).limit(limit).toArray();
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to list anchors: ${errMsg(err)}`);
        throw err;
      }
    }
    return [...this.memAnchors].reverse().slice(0, limit);
  }

  async findAuditHistoryEntry(root: string, timeoutMS: number): Promise<AuditHistoryEntry | null> {
    if (!/^[a-f0-9]{64}$/.test(root) || !Number.isInteger(timeoutMS) || timeoutMS < 1 || timeoutMS > 1000) throw new Error('Invalid audit history lookup');
    await this.connect();
    const matches = this.auditAnchors ? await this.auditAnchors.find({ root }, { timeoutMS, projection: {
      _id: 0, root: 1, commitmentVersion: 1, batchRoot: 1, eventCount: 1, prevRoot: 1, proofHash: 1, txHash: 1, network: 1,
    } }).limit(2).toArray() : this.memAnchors.filter(anchor => anchor.root === root).slice(0, 2);
    if (matches.length > 1) throw new Error('Ambiguous audit history root');
    const anchor = matches[0];
    if (!anchor) return null;
    return { root: anchor.root, commitmentVersion: anchor.commitmentVersion, batchRoot: anchor.batchRoot,
      eventCount: anchor.eventCount, prevRoot: anchor.prevRoot, proofHash: anchor.proofHash,
      txHash: anchor.txHash, network: anchor.txHash ? anchor.network : 'local' };
  }

  /** Anchor batch that contains a given audit event, if any. */
  async findAnchorForEvent(eventId: string): Promise<AuditAnchorDoc | null> {
    await this.connect();
    if (this.auditAnchors) {
      try {
        return (await this.auditAnchors.findOne({ 'leaves.eventId': eventId })) ?? null;
      } catch (err: unknown) {
        logger.error(`[DISSEMINATION] Failed to find anchor for event: ${errMsg(err)}`);
        throw err;
      }
    }
    return this.memAnchors.find((a) => a.leaves.some((l) => l.eventId === eventId)) ?? null;
  }

  // ── Distributed locks (review finding M6) ─────────────────────────

  /**
   * Best-effort distributed lease lock (review finding M6): only one process
   * runs a given periodic job at a time across the fleet. Returns true when
   * this process acquired or renewed the lease. Test-only memory storage
   * is single-process, so it always acquires.
   */
  async tryAcquireLock(name: string, leaseMs: number): Promise<boolean> {
    await this.connect();
    if (!this.locks) return true; // connect() permits this only in NODE_ENV=test
    const now = new Date();
    const lockedUntil = new Date(now.getTime() + leaseMs);
    try {
      const res = await this.locks.findOneAndUpdate(
        { _id: name, lockedUntil: { $lt: now } },
        { $set: { lockedUntil } },
        { upsert: true, returnDocument: 'after' },
      );
      return !!res;
    } catch (err: unknown) {
      if (isDuplicateKeyError(err)) return false; // held by another process (unexpired lease)
      logger.error(`[DISSEMINATION] Lock acquire failed: ${errMsg(err)}`);
      throw err;
    }
  }
}

function assertAcknowledged(result: { acknowledged: boolean }): void {
  if (!result.acknowledged) throw new Error('Dissemination write was not acknowledged');
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isDuplicateKeyError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: number }).code === 11000;
}

export const disseminationPersistence = new DisseminationPersistenceService();

function receiptPredecessors(state: 'receipted' | 'acknowledged' | 'feedback_received'): ChannelState[] {
  const delivered: ChannelState[] = ['packet_ready', 'dispatched', 'receipted'];
  if (state === 'receipted') return delivered;
  const acknowledged: ChannelState[] = [...delivered, 'approved', 'deferred', 'sla_breached', 'acknowledged'];
  return state === 'feedback_received' ? [...acknowledged, 'feedback_received'] : acknowledged;
}
