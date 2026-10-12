import { randomBytes } from 'node:crypto';
import type { Collection, Db } from 'mongodb';
import type { LegalOrganizationPreparationSource } from '../utils/legalOnboarding';
import { projectLegalOrganization, validateNewLegalOrganization } from '../utils/legalOnboarding';
import { LEGAL_APPLICATION_ID, LegalProvisioningError, parseLegalApplication, projectLegalApplication, projectLegalApplicationDecision } from '../utils/legalApplications';
import type { LegalProvisioningDetail, LegalProvisioningErrorCode } from '../utils/legalApplications';
import type { LegalApplicationInput, LegalApplicationView } from '../utils/legalApplications';
import { applicationOrganizationId, applicationReviewDigest, parseApplicationSubmission } from '../utils/legalApplicationEnrollment';
import type { KeyedApplication } from '../utils/legalApplicationEnrollment';
import { verifyFirmKeyBinding } from '../utils/legalApplicationKey';

type Row = LegalApplicationView & { _id: string; firstSignInSubject?: string; combinedApproval?: string; notifyAt: number; notificationDelivered?: boolean; notificationLease?: string;
  provisionAt?: number; provisionLease?: string; expiresAt?: Date };

/** Applicant contact details are kept only while needed. Pending applications
 * expire 180 days after submission and denied ones 180 days after the decision
 * (review can be slow; never less than 90 days). Approved applications are the
 * provenance of their organization and are retained. A TTL index on `expiresAt`
 * deletes due rows; approval removes the field. */
export const LEGAL_APPLICATION_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;
const expiry = (from: number) => new Date(from + LEGAL_APPLICATION_RETENTION_MS);
export type ProvisioningOutcome = { applicationId: string; status: 'ready' | 'retrying'; error?: LegalProvisioningErrorCode; detail?: LegalProvisioningDetail };
export type LegalApplicationSource = Pick<LegalApplications, keyof LegalApplications>;

/** Public firm intake. Persisted decisions alone cannot sign a firm key. */
export class LegalApplications {
  private constructor(private readonly rows: Collection<Row>) {}
  static async fromDatabase(db: Db): Promise<LegalApplications> {
    const rows = db.collection<Row>('legal_applications');
    await Promise.all([rows.createIndex({ createdAt: -1, _id: -1 }), rows.createIndex({ notifyAt: 1 }),
      rows.createIndex({ domain: 1, createdAt: -1 }), rows.createIndex({ provisionAt: 1 }),
      rows.createIndex({ domain: 1 }, { unique: true, partialFilterExpression: { status: { $eq: 'approved' } }, name: 'one_approved_application_per_domain' }),
      rows.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0, name: 'legal_application_retention' })]);
    await LegalApplications.backfillRetention(rows);
    return new LegalApplications(rows);
  }
  /** Rows written before the retention policy have no `expiresAt` and would never
   * expire. Idempotent and safe across concurrently starting processes: each row
   * is fenced on its status and a still-missing expiry. Per-row updates avoid
   * pipeline updates, which DocumentDB does not uniformly support. */
  private static async backfillRetention(rows: Collection<Row>, now = Date.now()): Promise<void> {
    await rows.updateMany({ status: 'approved', expiresAt: { $exists: true } }, { $unset: { expiresAt: '' } });
    const legacy = rows.find({ status: { $in: ['pending', 'denied'] }, expiresAt: { $exists: false } },
      { projection: { status: 1, createdAt: 1, decidedAt: 1 } });
    for await (const row of legacy) {
      const from = row.status === 'denied' && Number.isSafeInteger(row.decidedAt) ? row.decidedAt!
        : Number.isSafeInteger(row.createdAt) ? row.createdAt : now;
      await rows.updateOne({ _id: row._id, status: row.status, expiresAt: { $exists: false } }, { $set: { expiresAt: expiry(from) } });
    }
  }
  async submit(input: LegalApplicationInput | KeyedApplication, now = Date.now()): Promise<void> {
    const checked = parseApplicationSubmission(input);
    if (!checked) throw new Error('Invalid application');
    // Do not reveal whether a domain already applied. An application does not reserve
    // a firm domain or confer membership, and bogus applicants cannot lock it out.
    const id = checked && 'enrollment' in checked ? checked.enrollment.organizationId : randomBytes(32).toString('hex');
    if ('enrollment' in checked) {
      const key = await verifyFirmKeyBinding(checked.enrollment.bindingDocument, { domain: checked.domain, organizationId: id });
      if (key.binding.recipientKeyId !== checked.enrollment.recipientKeyId || !key.profile) throw new Error('Invalid application key');
      const existing = await this.get(id);
      if (existing) {
        if (await applicationReviewDigest(existing) !== await applicationReviewDigest({ ...checked, id, status: 'pending', createdAt: now })) throw new Error('Application conflict');
        return;
      }
      // Existing immutable submissions may retry after an upgrade. New public
      // applications must prove ownership of their ID through the signing key.
      // Assigned legacy IDs use authenticated/manual onboarding, not this route.
      if (id !== await applicationOrganizationId(key.binding.recipientKeyId)) throw new Error('Invalid application ID');
    }
    await this.rows.insertOne({ _id: id, id, ...checked, status: 'pending', createdAt: now, notifyAt: now, expiresAt: expiry(now) });
  }
  async list(before?: string): Promise<{ applications: LegalApplicationView[]; next: string | null }> {
    // Newest first. The cursor is the last row's random ID (no contact in URLs);
    // its createdAt anchors the (createdAt, _id) keyset.
    let filter = {};
    if (before) {
      const anchor = await this.rows.findOne({ _id: before }, { projection: { createdAt: 1 } });
      if (!anchor) return { applications: [], next: null };
      filter = { $or: [{ createdAt: { $lt: anchor.createdAt } }, { createdAt: anchor.createdAt, _id: { $lt: before } }] };
    }
    const rows = await this.rows.find(filter).sort({ createdAt: -1, _id: -1 }).limit(51).toArray();
    return { applications: rows.slice(0, 50).flatMap(row => { const result = projectLegalApplication(row); return result ? [result] : []; }),
      next: rows.length > 50 ? rows[49]._id : null };
  }
  async decide(id: string, status: 'approved' | 'denied', actor: string, now = Date.now(), reviewDigest?: string, confirmedKeyId?: string): Promise<boolean> {
    const candidate = await this.get(id);
    if (candidate?.enrollment && (!reviewDigest || await applicationReviewDigest(candidate) !== reviewDigest)) return false;
    if (candidate?.enrollment && status === 'approved' && confirmedKeyId !== candidate.enrollment.recipientKeyId) return false;
    if (reviewDigest && !candidate?.enrollment) return false;
    if (candidate?.enrollment && candidate.status === 'approved' && candidate.keyReviewStatus) {
      const changed = await this.rows.updateOne({ _id: id, status: 'approved', keyReviewStatus: 'pending' },
        { $set: { keyReviewStatus: status, keyReviewedBy: actor, keyReviewedAt: now } });
      return changed.modifiedCount === 1 || !!await this.rows.findOne({ _id: id, status: 'approved', keyReviewStatus: status });
    }
    // Decision + immutable actor/time are a single atomic write. Retried Slack
    // deliveries cannot change an earlier decision or create duplicate enrollment.
    try {
      // Approval keeps the record (organization provenance); denial restarts the
      // retention clock from the decision.
      const updated = await this.rows.updateOne({ _id: id, status: 'pending' }, status === 'approved'
        ? { $set: { status, decidedBy: actor, decidedAt: now, provisioningStatus: 'queued' as const, provisionAt: now,
          ...(candidate?.enrollment ? { keyReviewStatus: status, keyReviewedBy: actor, keyReviewedAt: now } : {}) }, $unset: { expiresAt: '' } }
        : { $set: { status, decidedBy: actor, decidedAt: now, expiresAt: expiry(now) } });
      if (updated.modifiedCount) return true;
    } catch (error) {
      // An approved domain cannot acquire a second provider organization through
      // concurrent applications. The losing request remains pending for review.
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
    return !!await this.rows.findOne({ _id: id, status });
  }
  async decision(id: string) {
    return projectLegalApplicationDecision(await this.rows.findOne({ _id: id },
      { projection: { id: 1, status: 1, decidedBy: 1, decidedAt: 1, displayName: 1 } }));
  }
  /** One staff action records vetting and prepares the public roster record.
   * Neither write approves a key or grants membership. A fixed ID and provider
   * binding on the created roster make retries safe, including concurrent retries. */
  async approveAndPrepare(id: string, providerOrganizationId: string, actor: string,
    store: LegalOrganizationPreparationSource,
    now = Date.now()): Promise<boolean> {
    const row = await this.rows.findOne({ _id: id });
    if (!row) return false;
    // Legacy application rows may predate the stricter intake validator. Reject
    // them before recording approval or reserving any domain/provider claims.
    const application = parseLegalApplication(Object.fromEntries(
      ['displayName', 'domain', 'email', 'lawyerName', 'jurisdiction', 'registrationNumber'].map(key => [key, row[key as keyof Row]])));
    if (!application) return false;
    const checked = validateNewLegalOrganization({ displayName: application.displayName, domain: application.domain, providerOrganizationId });
    if (!checked.ok) return false;
    const organization = checked.value;
    if (!await this.decide(id, 'approved', actor, now)) return false;
    const matches = (value: unknown) => {
      const org = projectLegalOrganization(value);
      return org && org.organizationId === id && org.domain === organization.domain && org.displayName === organization.displayName &&
        org.providerOrganizationId === organization.providerOrganizationId && org.status !== 'revoked';
    };
    const existing = await store.getLegalOrganizationRecord(id);
    if (existing && !matches(existing)) return false;
    if (!existing) {
      try {
        await store.createLegalOrganization({ organizationId: id, ...organization }, actor, now);
      } catch (error) {
        // A racing retry may already have committed the same record. A conflict
        // with another application/domain must never become a successful link.
        if (!matches(await store.getLegalOrganizationRecord(id))) throw error;
      }
    }
    await this.rows.updateOne({ _id: id, status: 'approved' }, { $set: { organizationId: id, providerOrganizationId: organization.providerOrganizationId, provisioningStatus: 'ready', provisionedAt: now }, $unset: { provisionAt: '', provisionLease: '' } });
    return true;
  }
  async get(id: string): Promise<LegalApplicationView | null> {
    return projectLegalApplication(await this.rows.findOne({ _id: id }));
  }
  async applicationStatus(id: string) {
    const row = await this.rows.findOne({ _id: id, enrollment: { $exists: true } });
    if (!row || id !== await applicationOrganizationId(row.enrollment!.recipientKeyId)) return { state: 'unavailable' as const };
    return { state: row.status === 'denied' || row.keyReviewStatus === 'denied' ? 'denied' as const : row.status === 'approved' && row.keyReviewStatus === 'approved' && row.provisioningStatus === 'ready' && row.combinedApproval
      ? 'ready' as const : row.status === 'approved' && row.keyReviewStatus === 'approved' && row.provisioningStatus === 'ready' ? 'sign-in-ready' as const : 'pending' as const,
      ...(row.status === 'approved' && row.keyReviewStatus === 'approved' && row.provisioningStatus === 'ready' ? { providerOrganizationId: row.providerOrganizationId } : {}) };
  }
  async firstSignInApproved(organizationId: string, email: string): Promise<boolean> {
    return !!await this.rows.findOne({ _id: organizationId, email, status: 'approved', keyReviewStatus: 'approved',
      provisioningStatus: 'ready', firstSignInSubject: { $exists: false }, combinedApproval: { $exists: false } }, { projection: { _id: 1 } });
  }
  async consumeFirstSignIn(organizationId: string, email: string, subject: string): Promise<void> {
    await this.rows.updateOne({ _id: organizationId, email, status: 'approved', firstSignInSubject: { $exists: false } },
      { $set: { firstSignInSubject: subject } });
  }
  async saveCombinedApproval(id: string, digest: string, approval: string): Promise<boolean> {
    if (typeof approval !== 'string' || approval.length > 150000) return false;
    const row = await this.get(id);
    if (!row?.enrollment || row.status !== 'approved' || row.keyReviewStatus !== 'approved' || row.provisioningStatus !== 'ready' || await applicationReviewDigest(row) !== digest) return false;
    const eligible = { _id: id, status: 'approved' as const, keyReviewStatus: 'approved' as const, provisioningStatus: 'ready' as const };
    const result = await this.rows.updateOne({ ...eligible, combinedApproval: { $exists: false } }, { $set: { combinedApproval: approval } });
    return result.modifiedCount === 1 || !!await this.rows.findOne({ ...eligible, combinedApproval: approval });
  }
  async getCombinedApproval(id: string): Promise<string | null> {
    const row = await this.rows.findOne({ _id: id, status: 'approved', keyReviewStatus: 'approved', provisioningStatus: 'ready' }, { projection: { combinedApproval: 1 } });
    return row?.combinedApproval ?? null;
  }
  /** Migration for an already-approved applicant who had no key at the original
   * review. Only called after enclave-verified candidate submission. The old
   * applicant approval cannot silently authorize this new key. */
  async queueFirstKeyReview(id: string, providerOrganizationId: string, enrollment: KeyedApplication['enrollment'], now: number) {
    // Older assigned IDs require the administrator's signed enrollment path.
    // The worker is authorized only for IDs derived from the reviewed first key.
    if (id !== await applicationOrganizationId(enrollment.recipientKeyId)) return;
    await this.rows.updateOne({ _id: id, status: 'approved', providerOrganizationId, enrollment: { $exists: false } },
      { $set: { enrollment, keyReviewStatus: 'pending', notifyAt: now }, $unset: { notificationDelivered: '', notificationLease: '' } });
  }
  async provisionOne(provision: (application: LegalApplicationView, signal?: AbortSignal) => Promise<string>, now = Date.now(),
    onOutcome?: (outcome: ProvisioningOutcome) => void): Promise<boolean> {
    const lease = randomBytes(16).toString('hex');
    const row = await this.rows.findOneAndUpdate({ status: 'approved', provisioningStatus: { $ne: 'ready' },
      $or: [{ provisionAt: { $lte: now } }, { provisionAt: { $exists: false } }] },
      { $set: { provisionAt: now + 60_000, provisionLease: lease } }, { returnDocument: 'after', sort: { decidedAt: 1 } });
    if (!row) return false;
    const applicationId = typeof row.id === 'string' && LEGAL_APPLICATION_ID.test(row.id) ? row.id : 'invalid';
    try {
      // The callback MUST be idempotent: a crashed worker or an expired lease
      // can repeat a successful remote call before its completion is persisted.
      const application = projectLegalApplication(row);
      if (!application) throw new LegalProvisioningError('invalid_application');
      const providerOrganizationId = await provision(application);
      if (!/^org_[A-Za-z0-9]+$/.test(providerOrganizationId)) throw new Error('Invalid organization');
      const saved = await this.rows.updateOne({ _id: row._id, provisionLease: lease }, {
        $set: { provisioningStatus: 'ready', providerOrganizationId, organizationId: row.id, provisionedAt: now },
        $unset: { provisionLease: '', provisionAt: '', provisioningError: '' },
      });
      if (saved.modifiedCount) { try { onOutcome?.({ applicationId, status: 'ready' }); } catch { /* Diagnostics only. */ } }
    } catch (error) {
      // Never retain provider errors, tokens or applicant contact in logs. Failed
      // attempts remain visible to staff and survive restarts for automatic retry.
      const code = error instanceof LegalProvisioningError ? error.code : 'provider_unavailable';
      const saved = await this.rows.updateOne({ _id: row._id, provisionLease: lease }, {
        $set: { provisioningStatus: 'retrying', provisioningError: code, provisionAt: now + 300_000 }, $unset: { provisionLease: '' },
      });
      const detail = error instanceof LegalProvisioningError ? error.detail : undefined;
      if (saved.modifiedCount) { try { onOutcome?.({ applicationId, status: 'retrying', error: code, ...(detail ? { detail } : {}) }); } catch { /* Diagnostics only. */ } }
    }
    return true;
  }
  async deliverOne(deliver: (application: LegalApplicationView) => Promise<boolean>, now = Date.now()): Promise<boolean> {
    const lease = randomBytes(16).toString('hex');
    const row = await this.rows.findOneAndUpdate({ notificationDelivered: { $ne: true }, notifyAt: { $lte: now } },
      { $set: { notifyAt: now + 60_000, notificationLease: lease } }, { returnDocument: 'after', sort: { notifyAt: 1 } });
    if (!row) return false;
    let delivered = false;
    try { delivered = await deliver(projectLegalApplication(row)!); } catch { /* Retry; no contact or webhook secrets in logs. */ }
    await this.rows.updateOne({ _id: row._id, notificationLease: lease }, {
      $set: delivered ? { notificationDelivered: true } : { notifyAt: now + 300_000 }, $unset: { notificationLease: '' },
    });
    return true;
  }
}
