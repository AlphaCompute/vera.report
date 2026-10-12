import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { Collection, Db } from 'mongodb';
import type { ApplicationOrganization, ApplicationOrganizations } from './legalApplicationOrganizations';
import { LEGAL_APPLICATION_RETENTION_MS } from './legalApplications';
import type { LegalApplicationSource, ProvisioningOutcome } from './legalApplications';
import { LegalApplicationIntakeClosedError, LegalProvisioningError, projectLegalApplication, projectLegalApplicationDecision } from '../utils/legalApplications';
import type { LegalApplicationInput, LegalApplicationView } from '../utils/legalApplications';
import { applicationOrganizationId, applicationReviewDigest, parseApplicationSubmission } from '../utils/legalApplicationEnrollment';
import type { KeyedApplication } from '../utils/legalApplicationEnrollment';
import { verifyFirmKeyBinding } from '../utils/legalApplicationKey';

type Work = { _id: string; enrollment?: KeyedApplication['enrollment']; combinedApproval?: string;
  notifyAt: number; notificationDelivered?: boolean; notificationLease?: string;
  provisionAt: number; provisionLease?: string; providerOrganizationId?: string;
  // Intake capacity counters only, never application or domain authority. Set at
  // intake, cleared once the application is decided, deleted or found missing.
  pendingDomain?: string; pendingUntil?: number };
/** Every unreviewed application holds an Auth0 organization until it is decided
 * or expires, while approval and legal sign-in list the whole directory and fail
 * closed at 1,000 organizations. Intake refuses new applications well below that. */
// Leave headroom for staff/manual provisioning below the directory's 1,000-row
// fail-closed boundary. Denied and expired records still occupy Auth0 slots.
export const LEGAL_APPLICATION_ORGANIZATION_LIMIT = 900;
export const LEGAL_PENDING_APPLICATION_LIMIT = 300;
export const LEGAL_PENDING_APPLICATION_LIMIT_MAX = 600;
export const LEGAL_DOMAIN_PENDING_APPLICATION_LIMIT = 3;
export type ApplicationIntakeLimits = { pending: number; domainPending: number };
/** `LEGAL_APPLICATION_PENDING_LIMIT` may lower or raise the tenant-wide cap up to
 * the safe maximum; anything unparseable keeps the default. */
export function applicationIntakeLimits(value = process.env.LEGAL_APPLICATION_PENDING_LIMIT): ApplicationIntakeLimits {
  const parsed = value?.trim() ? Number(value) : NaN;
  return { pending: Number.isInteger(parsed) && parsed >= 1 ? Math.min(parsed, LEGAL_PENDING_APPLICATION_LIMIT_MAX) : LEGAL_PENDING_APPLICATION_LIMIT,
    domainPending: LEGAL_DOMAIN_PENDING_APPLICATION_LIMIT };
}
const notPending = { $unset: { pendingDomain: '', pendingUntil: '' } } as const;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const name = (id: string) => `vera-legal-${id.slice(0, 32)}`;
const fields = { displayName: 'vera_display_name', domain: 'vera_domain', email: 'vera_email', lawyerName: 'vera_lawyer_name',
  jurisdiction: 'vera_jurisdiction', registrationNumber: 'vera_registration_number', id: 'vera_application_id',
  status: 'vera_approval_status', createdAt: 'vera_created_at', decidedBy: 'vera_decided_by', decidedAt: 'vera_decided_at',
  keyReviewStatus: 'vera_key_review_status', keyReviewedBy: 'vera_key_reviewed_by', keyReviewedAt: 'vera_key_reviewed_at',
  provisioningStatus: 'vera_provisioning_status', provisioningError: 'vera_provisioning_error', provisionedAt: 'vera_provisioned_at' } as const;
// Organizations approved before application records moved to Auth0 carry no
// status or version. Match the Action, which still treats them as approved.
const approvedMetadata = (metadata: Record<string, string>) => metadata.vera_approval_status === 'approved' ||
  (metadata.vera_approval_status === undefined && metadata.vera_application_version === undefined);
const numbers = new Set(['createdAt', 'decidedAt', 'keyReviewedAt', 'provisionedAt']);
const unavailable = async (): Promise<never> => { throw new LegalProvisioningError('provider_configuration'); };
const unavailableDirectory: ApplicationOrganizations = { get: unavailable, getById: unavailable, list: unavailable,
  create: unavailable, update: unavailable, remove: unavailable };

/** Auth0 owns every application and decision. Mongo holds only signed public-key
 * artifacts, notification/provisioning work and concurrency leases, never a copy
 * of contact details or an approval/domain claim. A missing Auth0 org is missing,
 * regardless of historical Mongo rows. Auth0 failure is never treated as absence. */
export class Auth0LegalApplications implements LegalApplicationSource {
  private constructor(private readonly directory: ApplicationOrganizations, private readonly work: Collection<Work>,
    private readonly locks: Collection<{ _id: string; lease: string; until: number }>, private readonly limits: ApplicationIntakeLimits) {}
  static async fromDatabase(db: Db, directory: ApplicationOrganizations | null, limits = applicationIntakeLimits()) {
    const work = db.collection<Work>('legal_application_work');
    await Promise.all([work.createIndex({ notifyAt: 1 }), work.createIndex({ provisionAt: 1 }),
      work.createIndex({ pendingUntil: 1 }), work.createIndex({ pendingDomain: 1, pendingUntil: 1 })]);
    const source = new Auth0LegalApplications(directory ?? unavailableDirectory, work, db.collection('legal_auth0_membership_locks'), limits);
    if (directory) await source.migrateLegacy(db);
    return source;
  }
  private async locked<T>(id: string, action: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const lease = randomBytes(16).toString('hex'), waitUntil = Date.now() + 5000;
    for (;;) {
      const now = Date.now();
      try {
        await this.locks.updateOne({ _id: id, until: { $lte: now } }, { $set: { lease, until: now + 60_000 } }, { upsert: true });
        break;
      } catch (error) {
        if ((error as { code?: number }).code !== 11000) throw error;
        if (Date.now() >= waitUntil) throw new LegalProvisioningError('provider_unavailable', 'lock_wait');
        await delay(50);
      }
    }
    try { return await action(AbortSignal.timeout(45_000)); }
    finally { await this.locks.updateOne({ _id: id, lease }, { $set: { until: 0 } }); }
  }
  private metadata(row: LegalApplicationView): Record<string, string> {
    const result: Record<string, string> = { vera_application_version: '1' };
    for (const [key, field] of Object.entries(fields)) {
      if ((key === 'keyReviewedBy' && row.keyReviewedBy === row.decidedBy) ||
          (key === 'keyReviewedAt' && row.keyReviewedAt === row.decidedAt)) continue;
      const value = row[key as keyof LegalApplicationView];
      if (value !== undefined) result[field] = String(value);
    }
    if (row.status !== 'approved') result.vera_expires_at = String((row.decidedAt ?? row.createdAt) + LEGAL_APPLICATION_RETENTION_MS);
    if (row.enrollment) {
      result.vera_key_id = row.enrollment.recipientKeyId;
      result.vera_binding_sha256 = hash(row.enrollment.bindingDocument);
    }
    return result;
  }
  private async decode(org: ApplicationOrganization): Promise<LegalApplicationView | null> {
    const m = org.metadata;
    if (m.vera_application_version !== '1') return null;
    if (m.vera_legal_disabled === 'true') return null;
    if (!/^[a-f0-9]{64}$/.test(m.vera_application_id) || org.name !== name(m.vera_application_id)) throw new LegalProvisioningError('provider_binding');
    const data: Record<string, unknown> = {};
    for (const [key, field] of Object.entries(fields)) if (m[field] !== undefined) data[key] = numbers.has(key) ? Number(m[field]) : m[field];
    if (data.keyReviewStatus && data.keyReviewStatus === data.status) {
      data.keyReviewedBy ??= data.decidedBy; data.keyReviewedAt ??= data.decidedAt;
    }
    if (m.vera_key_id || m.vera_binding_sha256) {
      const artifact = await this.work.findOne({ _id: m.vera_application_id }, { projection: { enrollment: 1 } });
      if (!artifact?.enrollment || artifact.enrollment.recipientKeyId !== m.vera_key_id ||
          hash(artifact.enrollment.bindingDocument) !== m.vera_binding_sha256) throw new LegalProvisioningError('provider_binding');
      data.enrollment = artifact.enrollment;
    }
    data.providerOrganizationId = org.id;
    if (m.vera_provisioning_status === 'ready') data.organizationId = m.vera_application_id;
    const row = projectLegalApplication(data);
    if (!row || row.domain !== m.vera_domain) throw new LegalProvisioningError('provider_binding');
    return row;
  }
  private async save(org: ApplicationOrganization, row: LegalApplicationView, signal: AbortSignal) {
    const metadata = { ...org.metadata };
    for (const key of Object.values(fields)) delete metadata[key];
    delete metadata.vera_expires_at;
    await this.directory.update({ ...org, metadata: { ...metadata, ...this.metadata(row) } }, signal);
  }
  private expired(row: LegalApplicationView, now = Date.now()) {
    return row.status !== 'approved' && (row.decidedAt ?? row.createdAt) + LEGAL_APPLICATION_RETENTION_MS <= now;
  }
  /** One-way cutover. Approved rows are imported only into the SAME existing,
   * approved Auth0 organization. Deleting it must never recreate old approval.
   * Old records remain untouched for rollback/audit, but are never read by the
   * live application flow and their Mongo indexes cannot block new decisions. */
  private async migrateLegacy(db: Db) {
    for await (const raw of db.collection('legal_applications').find({})) {
      const row = projectLegalApplication(raw);
      if (!row || (row.status !== 'approved' && (row.decidedAt ?? row.createdAt) + LEGAL_APPLICATION_RETENTION_MS <= Date.now())) continue;
      await this.locked(`application:${row.id}`, async signal => {
        const existing = await this.directory.get(name(row.id), signal);
        if (existing?.metadata.vera_application_version === '1') return;
        if (!existing && (await this.work.findOne({ _id: row.id }))?.providerOrganizationId) return;
        if (row.status === 'approved' && (!existing || existing.id !== row.providerOrganizationId ||
            !approvedMetadata(existing.metadata))) return;
        if (existing?.metadata.vera_approval_status && existing.metadata.vera_approval_status !== row.status) return;
        if (existing && (existing.metadata.vera_application_id !== row.id || existing.metadata.vera_domain !== row.domain))
          throw new LegalProvisioningError('provider_binding');
        await this.work.updateOne({ _id: row.id }, { $setOnInsert: { _id: row.id,
          ...(row.enrollment ? { enrollment: row.enrollment } : {}),
          ...(typeof raw.combinedApproval === 'string' ? { combinedApproval: raw.combinedApproval } : {}),
          ...(row.status === 'pending' ? { pendingDomain: hash(row.domain), pendingUntil: row.createdAt + LEGAL_APPLICATION_RETENTION_MS } : {}),
          notifyAt: Date.now(), provisionAt: Date.now(), notificationDelivered: raw.notificationDelivered === true } }, { upsert: true });
        let savedId = existing?.id;
        if (existing) await this.locked(existing.id, async () => {
          const current = await this.directory.getById(existing.id, signal);
          if (!current || current.metadata.vera_application_version === '1') return;
          if (typeof raw.firstSignInSubject === 'string' && raw.firstSignInSubject.length <= 255)
            current.metadata.vera_first_sign_in = raw.firstSignInSubject;
          await this.save(current, row, signal);
        });
        else savedId = (await this.directory.create({ name: name(row.id), display_name: row.displayName, metadata: this.metadata(row) }, signal)).id;
        await this.work.updateOne({ _id: row.id }, { $set: { providerOrganizationId: savedId } });
      });
    }
  }
  async get(id: string): Promise<LegalApplicationView | null> {
    if (!/^[a-f0-9]{64}$/.test(id)) return null;
    const org = await this.directory.get(name(id), AbortSignal.timeout(45_000));
    const row = org ? await this.decode(org) : null;
    return row && !this.expired(row) ? row : null;
  }
  async submit(input: LegalApplicationInput | KeyedApplication, now = Date.now()): Promise<void> {
    const checked = parseApplicationSubmission(input);
    if (!checked) throw new Error('Invalid application');
    const id = 'enrollment' in checked ? checked.enrollment.organizationId : randomBytes(32).toString('hex');
    if ('enrollment' in checked) {
      const key = await verifyFirmKeyBinding(checked.enrollment.bindingDocument, { domain: checked.domain, organizationId: id });
      if (!key.profile || key.binding.recipientKeyId !== checked.enrollment.recipientKeyId || id !== await applicationOrganizationId(key.binding.recipientKeyId)) throw new Error('Invalid application key');
    }
    await this.locked(`application:${id}`, async signal => {
      const row: LegalApplicationView = { ...checked, id, status: 'pending', createdAt: now };
      const existing = await this.directory.get(name(id), signal);
      if (existing) {
        const saved = await this.decode(existing);
        if (!saved?.enrollment || !row.enrollment || await applicationReviewDigest(saved) !== await applicationReviewDigest(row)) throw new Error('Application conflict');
        await this.work.updateOne({ _id: id }, { $set: { providerOrganizationId: existing.id } });
        return;
      }
      // A deleted organization cannot be recreated using an old Slack button or
      // key backup. A new application generates a new key and review identity.
      const work = await this.work.findOne({ _id: id });
      if (work?.providerOrganizationId) throw new Error('Application removed');
      if (work && JSON.stringify(work.enrollment) !== JSON.stringify('enrollment' in checked ? checked.enrollment : undefined)) throw new Error('Application conflict');
      // Workers must not see this row before its organization exists: a missing
      // organization reads as deleted, so they would mark the notification sent
      // and discard the signed key. Release the work once the create succeeds;
      // a failed create is cleaned up after the deferral, as before.
      await this.work.updateOne({ _id: id }, { $setOnInsert: { _id: id, ...('enrollment' in checked ? { enrollment: checked.enrollment } : {}) },
        $set: { notifyAt: now + 120_000, provisionAt: now + 120_000, pendingDomain: hash(row.domain), pendingUntil: now + LEGAL_APPLICATION_RETENTION_MS } }, { upsert: true });
      let created: ApplicationOrganization;
      try {
        const closed = await this.intakeClosed(hash(row.domain), now);
        if (closed) throw new LegalApplicationIntakeClosedError(closed);
        // Serialize count + create across replicas. Decisions may free pending
        // slots, but never free total directory capacity until Auth0 deletes them.
        created = await this.locked('application-intake-total', async intakeSignal => {
          signal.throwIfAborted();
          const requestSignal = AbortSignal.any([signal, intakeSignal]);
          let organizations: ApplicationOrganization[];
          try { organizations = await this.directory.list(requestSignal); }
          catch (error) {
            if (error instanceof LegalProvisioningError && error.code === 'lookup_limit')
              throw new LegalApplicationIntakeClosedError('applications-closed');
            throw error;
          }
          if (organizations.length >= LEGAL_APPLICATION_ORGANIZATION_LIMIT)
            throw new LegalApplicationIntakeClosedError('applications-closed');
          requestSignal.throwIfAborted();
          return this.directory.create({ name: name(id), display_name: row.displayName, metadata: this.metadata(row) }, requestSignal);
        });
      } catch (error) {
        if (error instanceof LegalApplicationIntakeClosedError) {
          // No create was attempted for a capacity refusal. Ambiguous provider
          // failures retain their work row for the existing reconciliation path.
          if (work) await this.work.updateOne({ _id: id }, notPending);
          else await this.work.deleteOne({ _id: id, providerOrganizationId: { $exists: false } });
        }
        throw error;
      }
      const saved = await this.decode(created);
      if (!saved || saved.id !== id || (row.enrollment && await applicationReviewDigest(saved) !== await applicationReviewDigest(row))) throw new LegalProvisioningError('provider_binding');
      await this.work.updateOne({ _id: id }, { $set: { providerOrganizationId: created.id, notifyAt: now, provisionAt: now } });
    });
  }
  /** Counted after this application's own reservation, so concurrent submissions
   * near a cap can both be refused but never both exceed it. */
  private async intakeClosed(domain: string, now: number, reconciled = false): Promise<'applications-closed' | 'domain-applications-pending' | null> {
    const live = { pendingUntil: { $gt: now } };
    const closed = await this.work.countDocuments({ pendingDomain: domain, ...live }) > this.limits.domainPending ? 'domain-applications-pending' as const
      : await this.work.countDocuments(live) > this.limits.pending ? 'applications-closed' as const : null;
    if (!closed || reconciled || !await this.reconcilePending(now)) return closed;
    return this.intakeClosed(domain, now, true);
  }
  /** Counters normally clear on decision, retention deletion or a missing org seen
   * by the worker. An organization deleted directly in Auth0 is caught here: at a
   * cap, at most once a minute tenant-wide, clear counters for applications that
   * are no longer pending in Auth0. A failed listing leaves the counters, and so
   * intake stays closed rather than reopening on an incomplete directory. */
  private async reconcilePending(now: number): Promise<boolean> {
    try {
      await this.locks.updateOne({ _id: 'application-intake-reconcile', until: { $lte: now } },
        { $set: { lease: randomBytes(16).toString('hex'), until: now + 60_000 } }, { upsert: true });
    } catch (error) {
      if ((error as { code?: number }).code === 11000) return false;
      throw error;
    }
    let organizations: ApplicationOrganization[];
    try { organizations = await this.directory.list(AbortSignal.timeout(45_000)); } catch { return false; }
    const pending = organizations.flatMap(({ metadata: m }) => m.vera_application_version === '1' && m.vera_approval_status === 'pending' &&
      m.vera_legal_disabled !== 'true' && Number(m.vera_expires_at) > now ? [m.vera_application_id] : []);
    // A submission still inside its lock may not be listed yet; leave recent ones.
    const cleared = await this.work.updateMany({ _id: { $nin: pending },
      pendingUntil: { $lte: now - 120_000 + LEGAL_APPLICATION_RETENTION_MS } }, notPending);
    return cleared.modifiedCount > 0;
  }
  async list(before?: string) {
    const rows: LegalApplicationView[] = [];
    for (const org of await this.directory.list(AbortSignal.timeout(45_000))) {
      const row = await this.decode(org); if (row && !this.expired(row)) rows.push(row);
    }
    rows.sort((a, b) => b.createdAt - a.createdAt || b.id.localeCompare(a.id));
    const index = before ? rows.findIndex(row => row.id === before) : -1;
    if (before && index === -1) return { applications: [], next: null };
    const page = rows.slice(index + 1, index + 52);
    return { applications: page.slice(0, 50), next: page.length > 50 ? page[49].id : null };
  }
  async decide(id: string, status: 'approved' | 'denied', actor: string, now = Date.now(), reviewDigest?: string, confirmedKeyId?: string): Promise<boolean> {
    const found = await this.directory.get(name(id), AbortSignal.timeout(45_000));
    const initial = found && await this.decode(found);
    if (!found || !initial) return false;
    // Only competing decisions for this domain serialize across replicas. Other
    // domains continue independently; the org lock also protects membership hints.
    return this.locked(`application-domain:${hash(initial.domain)}`, async signal => {
      return this.locked(found.id, async () => {
        const org = await this.directory.getById(found.id, signal);
        const row = org && await this.decode(org);
        if (!org || !row || row.domain !== initial.domain || this.expired(row) || (row.enrollment && (!reviewDigest || await applicationReviewDigest(row) !== reviewDigest ||
            (status === 'approved' && confirmedKeyId !== row.enrollment.recipientKeyId))) || (reviewDigest && !row.enrollment)) return false;
        if (row.enrollment && row.status === 'approved' && row.keyReviewStatus) {
          if (row.keyReviewStatus !== 'pending') return row.keyReviewStatus === status;
          await this.save(org, { ...row, keyReviewStatus: status, keyReviewedBy: actor, keyReviewedAt: now }, signal);
          return true;
        }
        if (row.status !== 'pending') {
          if (row.status === 'approved' && row.status === status && row.provisioningStatus !== 'ready')
            await this.work.updateOne({ _id: id }, { $set: { provisionAt: now } });
          await this.work.updateOne({ _id: id }, notPending);
          return row.status === status;
        }
        if (status === 'approved') {
          const organizations = await this.directory.list(signal);
          for (const listed of organizations) {
            if (listed.id === org.id || listed.metadata.vera_domain !== row.domain) continue;
            // A directory snapshot is discovery, not proof that an organization
            // still exists or is still approved. Confirm the exact live record.
            const current = await this.directory.getById(listed.id, signal);
            if (current?.metadata.vera_domain === row.domain && approvedMetadata(current.metadata)) return false;
          }
        }
        await this.work.updateOne({ _id: id }, { $set: { provisionAt: now } });
        await this.save(org, { ...row, status, decidedBy: actor, decidedAt: now,
          ...(status === 'approved' ? { provisioningStatus: 'queued' } : {}),
          ...(row.enrollment ? { keyReviewStatus: status, keyReviewedBy: actor, keyReviewedAt: now } : {}) }, signal);
        await this.work.updateOne({ _id: id }, notPending);
        return true;
      });
    });
  }
  async decision(id: string) { return projectLegalApplicationDecision(await this.get(id)); }
  async approveAndPrepare(): Promise<boolean> { return false; } // Auth0-backed intake always uses automatic provisioning.
  async applicationStatus(id: string) {
    const row = await this.get(id);
    if (!row?.enrollment || id !== await applicationOrganizationId(row.enrollment.recipientKeyId)) return { state: 'unavailable' as const };
    const ready = row.status === 'approved' && row.keyReviewStatus === 'approved' && row.provisioningStatus === 'ready';
    return { state: row.status === 'denied' || row.keyReviewStatus === 'denied' ? 'denied' as const : ready
      ? (await this.work.findOne({ _id: id }, { projection: { combinedApproval: 1 } }))?.combinedApproval ? 'ready' as const : 'sign-in-ready' as const : 'pending' as const,
    ...(ready ? { providerOrganizationId: row.providerOrganizationId } : {}) };
  }
  async firstSignInApproved(id: string, email: string): Promise<boolean> {
    const org = await this.directory.get(name(id), AbortSignal.timeout(45_000));
    const row = org && await this.decode(org);
    return !!row && row.email === email && row.status === 'approved' && row.keyReviewStatus === 'approved' &&
      row.provisioningStatus === 'ready' && !org!.metadata.vera_first_sign_in &&
      !(await this.work.findOne({ _id: id }, { projection: { combinedApproval: 1 } }))?.combinedApproval;
  }
  async consumeFirstSignIn(id: string, email: string, subject: string): Promise<void> {
    const found = await this.directory.get(name(id), AbortSignal.timeout(45_000));
    if (!found) return;
    await this.locked(found.id, async signal => {
      const org = await this.directory.getById(found.id, signal);
      const row = org && await this.decode(org);
      if (org && row?.status === 'approved' && row.email === email && !org.metadata.vera_first_sign_in)
        await this.directory.update({ ...org, metadata: { ...org.metadata, vera_first_sign_in: subject } }, signal);
    });
  }
  async saveCombinedApproval(id: string, digest: string, approval: string): Promise<boolean> {
    if (typeof approval !== 'string' || approval.length > 150000) return false;
    const row = await this.get(id);
    if (!row?.enrollment || row.status !== 'approved' || row.keyReviewStatus !== 'approved' || row.provisioningStatus !== 'ready' || await applicationReviewDigest(row) !== digest) return false;
    await this.work.updateOne({ _id: id, combinedApproval: { $exists: false } }, { $set: { combinedApproval: approval } });
    return !!await this.work.findOne({ _id: id, combinedApproval: approval });
  }
  async getCombinedApproval(id: string): Promise<string | null> {
    const row = await this.get(id);
    if (row?.status !== 'approved' || row.keyReviewStatus !== 'approved' || row.provisioningStatus !== 'ready') return null;
    return (await this.work.findOne({ _id: id }, { projection: { combinedApproval: 1 } }))?.combinedApproval ?? null;
  }
  async queueFirstKeyReview(id: string, providerOrganizationId: string, enrollment: KeyedApplication['enrollment'], now: number): Promise<void> {
    if (id !== await applicationOrganizationId(enrollment.recipientKeyId)) return;
    await this.locked(providerOrganizationId, async signal => {
      const org = await this.directory.getById(providerOrganizationId, signal);
      const row = org && await this.decode(org);
      if (!org || row?.id !== id || row.status !== 'approved' || row.enrollment) return;
      const key = await verifyFirmKeyBinding(enrollment.bindingDocument, { domain: row.domain, organizationId: id });
      if (key.binding.recipientKeyId !== enrollment.recipientKeyId) throw new Error('Invalid application key');
      await this.work.updateOne({ _id: id }, { $set: { enrollment, notifyAt: now }, $unset: { notificationDelivered: '', notificationLease: '' } });
      await this.save(org, { ...row, enrollment, keyReviewStatus: 'pending' }, signal);
    });
  }
  async provisionOne(provision: (application: LegalApplicationView, signal?: AbortSignal) => Promise<string>, now = Date.now(), onOutcome?: (outcome: ProvisioningOutcome) => void): Promise<boolean> {
    const lease = randomBytes(16).toString('hex');
    const job = await this.work.findOneAndUpdate({ provisionAt: { $lte: now } }, { $set: { provisionAt: now + 300_000, provisionLease: lease } },
      { returnDocument: 'after', sort: { provisionAt: 1 } });
    if (!job) return false;
    const found = await this.directory.get(name(job._id), AbortSignal.timeout(45_000));
    if (!found) {
      await this.work.updateOne({ _id: job._id, provisionLease: lease }, { $set: { provisionAt: Number.MAX_SAFE_INTEGER },
        $unset: { provisionLease: '', enrollment: '', combinedApproval: '', ...notPending.$unset } });
      return true;
    }
    await this.locked(found.id, async signal => {
      const org = await this.directory.getById(found.id, signal);
      const row = org && await this.decode(org);
      if (org && row && this.expired(row, now)) {
        await this.directory.remove(org.id, signal);
        await this.work.updateOne({ _id: row.id }, { $unset: { enrollment: '', combinedApproval: '', ...notPending.$unset },
          $set: { notificationDelivered: true, provisionAt: Number.MAX_SAFE_INTEGER } });
        return;
      }
      if (!org || !row || row.status !== 'approved' || row.provisioningStatus === 'ready') {
        if (row?.status !== 'pending') await this.work.updateOne({ _id: job._id }, notPending);
        await this.work.updateOne({ _id: job._id, provisionLease: lease }, { $set: { provisionAt: row && row.status !== 'approved'
          ? (row.decidedAt ?? row.createdAt) + LEGAL_APPLICATION_RETENTION_MS : Number.MAX_SAFE_INTEGER } });
        return;
      }
      let outcome: ProvisioningOutcome;
      try {
        const providerOrganizationId = await provision(row, signal);
        signal.throwIfAborted();
        if (providerOrganizationId !== org.id) throw new LegalProvisioningError('provider_binding');
        await this.save(org, { ...row, provisioningStatus: 'ready', provisionedAt: now, provisioningError: undefined }, signal);
        await this.work.updateOne({ _id: job._id, provisionLease: lease }, { $set: { provisionAt: Number.MAX_SAFE_INTEGER } });
        outcome = { applicationId: row.id, status: 'ready' };
      } catch (error) {
        const code = error instanceof LegalProvisioningError ? error.code : 'provider_unavailable';
        await this.save(org, { ...row, provisioningStatus: 'retrying', provisioningError: code }, signal);
        await this.work.updateOne({ _id: job._id, provisionLease: lease }, { $set: { provisionAt: now + 15_000 } });
        outcome = { applicationId: row.id, status: 'retrying', error: code,
          ...(error instanceof LegalProvisioningError && error.detail ? { detail: error.detail } : {}) };
      }
      try { onOutcome?.(outcome); } catch { /* Diagnostics only. */ }
    });
    await this.work.updateOne({ _id: job._id, provisionLease: lease }, { $unset: { provisionLease: '' } });
    return true;
  }
  async deliverOne(deliver: (application: LegalApplicationView) => Promise<boolean>, now = Date.now()): Promise<boolean> {
    const lease = randomBytes(16).toString('hex');
    const row = await this.work.findOneAndUpdate({ notificationDelivered: { $ne: true }, notifyAt: { $lte: now } },
      { $set: { notifyAt: now + 300_000, notificationLease: lease } }, { returnDocument: 'after', sort: { notifyAt: 1 } });
    if (!row) return false;
    let delivered = false;
    try { const application = await this.get(row._id); delivered = application ? await deliver(application) : true; } catch { /* Retry. */ }
    await this.work.updateOne({ _id: row._id, notificationLease: lease }, { $set: { notificationDelivered: delivered }, $unset: { notificationLease: '' } });
    return true;
  }
}
