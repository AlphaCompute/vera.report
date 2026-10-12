import { createHash, randomBytes } from 'node:crypto';
import type { Collection, Db } from 'mongodb';
import type { ApplicationIdentityProvider, LegalSignInTarget } from './legalApplicationAuth0';
import { LegalProvisioningError } from '../utils/legalApplications';
import { failureReason } from '../utils/failureReason';

export type LegalMembershipApproval = LegalSignInTarget & {
  organizationId: string; approvalId: string; expires: number;
};
type Job = LegalMembershipApproval & {
  _id: string; state: 'pending' | 'applying' | 'complete' | 'review' | 'cancelled';
  nextCheck: number; lease?: string; subject?: string;
};

/** One durable membership write per explicit approval. Auth0 Actions only read
 * Auth0; approval prepares the account and membership before native OTP sign-in.
 * Never replay a possibly successful account creation or remote grant. */
export class LegalAuth0Memberships {
  private constructor(private readonly rows: Collection<Job>,
    private readonly locks: Collection<{ _id: string; until: number; lease: string }>) {}
  static async fromDatabase(db: Db) {
    const rows = db.collection<Job>('legal_auth0_membership_approvals');
    await rows.createIndex({ state: 1, nextCheck: 1 });
    return new LegalAuth0Memberships(rows, db.collection('legal_auth0_membership_locks'));
  }
  async queue(value: LegalMembershipApproval) {
    if (!/^[a-f0-9]{64}$/.test(value.organizationId) || !/^[a-f0-9]{64}$/.test(value.approvalId) ||
        !/^org_[A-Za-z0-9]{1,64}$/.test(value.providerOrganizationId) ||
        value.email.length > 254 || value.email !== value.email.toLowerCase() ||
        !/^[^@\s]+@[^@\s]+$/.test(value.email) || value.email.split('@')[1] !== value.domain ||
        !Number.isSafeInteger(value.expires)) throw new Error('Invalid membership approval');
    const _id = createHash('sha256').update(JSON.stringify([value.organizationId, value.email, value.approvalId])).digest('hex');
    // No TTL: completed/ambiguous writes remain tombstones against old approval retries.
    await this.rows.updateOne({ _id }, { $setOnInsert: { ...value, _id, state: 'pending', nextCheck: 0 } }, { upsert: true });
  }
  async consumed(organizationId: string, email: string): Promise<boolean> {
    return !!await this.rows.findOne({ organizationId, email, state: { $ne: 'pending' } }, { projection: { _id: 1 } });
  }
  async prepared(organizationId: string, email: string, approvalId: string): Promise<boolean> {
    return !!await this.rows.findOne({ organizationId, email, approvalId, state: 'complete' }, { projection: { _id: 1 } });
  }
  /** `retire` runs once Auth0 reports the target organization deleted; the job is
   * cancelled first, so a failed retirement is logged, not retried here. */
  async runOne(provider: ApplicationIdentityProvider,
    authorized: (target: LegalMembershipApproval, subject?: string) => Promise<boolean>, now = Date.now(),
    retire?: (target: LegalMembershipApproval) => Promise<void>): Promise<boolean> {
    if (!provider.nativeEntry || !provider.registrationApproval || !provider.candidate ||
        !provider.createApprovedAccount || !provider.approveMembership) return false;
    const lease = randomBytes(16).toString('hex');
    const row = await this.rows.findOneAndUpdate({ state: 'pending', expires: { $gt: now }, nextCheck: { $lte: now } },
      { $set: { lease, nextCheck: now + 60_000 } }, { returnDocument: 'after', sort: { nextCheck: 1, _id: 1 } });
    if (!row) return false;
    let consumed = false;
    const filter = { _id: row._id, lease };
    const signal = AbortSignal.timeout(45_000);
    try {
      // Serialize full organization-metadata replacement across backend replicas.
      // Only these workers publish hints; login Actions are strictly read-only.
      try {
        await this.locks.updateOne({ _id: row.providerOrganizationId, until: { $lte: now } },
          { $set: { lease, until: now + 60_000 } }, { upsert: true });
      } catch (error) {
        if ((error as { code?: number }).code !== 11000) throw error;
        await this.rows.updateOne(filter, { $set: { nextCheck: Date.now() + 2000 }, $unset: { lease: '' } });
        return true;
      }
      if (!await authorized(row)) {
        await this.rows.updateOne(filter, { $set: { state: 'cancelled' }, $unset: { lease: '' } });
        return true;
      }
      signal.throwIfAborted();
      await provider.registrationApproval(row, signal);
      let subject = await provider.candidate(row, signal);
      if (!await authorized(row, subject ?? undefined)) {
        await this.rows.updateOne(filter, { $set: { state: 'cancelled' }, $unset: { lease: '' } });
        return true;
      }
      // CAS before side effects: even an expired lease cannot grant twice.
      signal.throwIfAborted();
      const claimed = await this.rows.updateOne({ ...filter, state: 'pending', expires: { $gt: Date.now() } },
        { $set: { state: 'applying', ...(subject ? { subject } : {}) } });
      if (claimed.modifiedCount !== 1) return true;
      consumed = true;
      const created = !subject;
      if (!subject) {
        subject = await provider.createApprovedAccount(row, signal);
        await this.rows.updateOne(filter, { $set: { subject } });
      }
      if (!await authorized(row, subject)) throw new Error('Membership approval revoked');
      if (await provider.approveMembership(row, subject, signal, created) !== subject) throw new Error('Membership subject mismatch');
      await this.rows.updateOne(filter, { $set: { state: 'complete' }, $unset: { lease: '' } });
    } catch (error) {
      // A timeout may mean Auth0 committed. Retrying it could resurrect access
      // removed in the meantime. An operator must review ambiguous grants.
      // A deleted organization is final; nothing was written, so cancel.
      const deleted = !consumed && error instanceof LegalProvisioningError && error.detail === 'organization_deleted';
      const job = row._id.slice(0, 8);
      console.warn('Legal membership job failed', job, consumed ? 'review' : deleted ? 'cancelled' : 'retrying', failureReason(error));
      await this.rows.updateOne(filter, { $set: consumed ? { state: 'review' } : deleted ? { state: 'cancelled' } : { nextCheck: Date.now() + 10_000 },
        $unset: { lease: '' } });
      if (deleted && retire) {
        try { await retire(row); } catch (retireError) { console.warn('Legal membership roster retirement failed', job, failureReason(retireError)); }
      }
    } finally {
      await this.locks.updateOne({ _id: row.providerOrganizationId, lease }, { $set: { until: 0 } });
    }
    return true;
  }
}
