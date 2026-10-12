import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { LegalAuth0Memberships } from '../../../src/services/legalAuth0Memberships';
import type { LegalMembershipApproval } from '../../../src/services/legalAuth0Memberships';
import { LegalProvisioningError } from '../../../src/utils/legalApplications';

describe('one-time Auth0 membership provisioning without a login callback', () => {
  let server: MongoMemoryServer, client: MongoClient, service: LegalAuth0Memberships;
  const db = () => client.db('native_memberships');
  const rows = () => db().collection<any>('legal_auth0_membership_approvals');
  const approval = (): LegalMembershipApproval => ({ organizationId: 'a'.repeat(64), approvalId: 'b'.repeat(64),
    providerOrganizationId: 'org_approved', domain: 'firm.example', email: 'lawyer@firm.example', expires: Date.now() + 300_000 });
  const fixture = () => {
    let user: string | null = null;
    const provider = { nativeEntry: true, organization: jest.fn(), invite: jest.fn(),
      registrationApproval: jest.fn(async () => {}), candidate: jest.fn(async () => user),
      createApprovedAccount: jest.fn(async () => 'email|approved'),
      approveMembership: jest.fn(async () => 'email|approved') };
    return { provider, authorized: jest.fn(async () => true), user: (value: string | null) => { user = value; } };
  };
  beforeAll(async () => {
    server = await MongoMemoryServer.create(); client = await MongoClient.connect(server.getUri());
    service = await LegalAuth0Memberships.fromDatabase(db());
  });
  afterAll(async () => { await client?.close(); await server?.stop(); });
  beforeEach(async () => { await rows().deleteMany({}); await db().collection('legal_auth0_membership_locks').deleteMany({}); });
  it('prepares a missing account and grants membership on approval before any sign-in', async () => {
    const f = fixture(), value = approval(); await service.queue(value);
    expect(await service.consumed(value.organizationId, value.email)).toBe(false);
    await service.runOne(f.provider, f.authorized);
    expect(f.provider.registrationApproval).toHaveBeenCalledWith(expect.objectContaining(value), expect.any(AbortSignal));
    expect(f.provider.createApprovedAccount).toHaveBeenCalledTimes(1);
    expect(f.provider.approveMembership).toHaveBeenCalledWith(expect.objectContaining(value), 'email|approved', expect.any(AbortSignal), true);
    expect(await rows().findOne({})).toMatchObject({ state: 'complete', subject: 'email|approved' });
    expect(await service.consumed(value.organizationId, value.email)).toBe(true);
    // An old Slack retry and a later sign-in must not resurrect removed access.
    await service.queue(value); f.user('email|recreated');
    expect(await service.runOne(f.provider, f.authorized, Date.now() + 6000)).toBe(false);
    expect(f.provider.approveMembership).toHaveBeenCalledTimes(1);
  });
  it('consumes before the Auth0 write and never retries an ambiguous success', async () => {
    const f = fixture(); f.user('email|approved'); const value = approval(); await service.queue(value);
    f.provider.approveMembership.mockImplementation(async () => {
      expect(await rows().findOne({})).toMatchObject({ state: 'applying', subject: 'email|approved' });
      throw new Error('Response lost after Auth0 added the role');
    });
    await service.runOne(f.provider, f.authorized);
    expect(await rows().findOne({})).toMatchObject({ state: 'review' });
    expect(await service.consumed(value.organizationId, value.email)).toBe(true);
    await service.queue(value);
    expect(await service.runOne(f.provider, f.authorized, Date.now() + 61_000)).toBe(false);
    expect(f.provider.approveMembership).toHaveBeenCalledTimes(1);
    expect(f.provider.createApprovedAccount).not.toHaveBeenCalled();
  });
  it('fences account creation before writing and never repeats an ambiguous creation', async () => {
    const f = fixture(); await service.queue(approval());
    f.provider.createApprovedAccount.mockImplementation(async () => {
      expect(await rows().findOne({})).toMatchObject({ state: 'applying' });
      throw new Error('Lost account creation response');
    });
    await service.runOne(f.provider, f.authorized);
    expect(await rows().findOne({})).toMatchObject({ state: 'review' });
    expect(await service.runOne(f.provider, f.authorized, Date.now() + 61000)).toBe(false);
    expect(f.provider.createApprovedAccount).toHaveBeenCalledTimes(1);
    expect(f.provider.approveMembership).not.toHaveBeenCalled();
  });
  it('rechecks authorization after account creation before adding or unblocking it', async () => {
    const f = fixture(); await service.queue(approval());
    f.authorized.mockResolvedValueOnce(true).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    await service.runOne(f.provider, f.authorized);
    expect(await rows().findOne({})).toMatchObject({ state: 'review', subject: 'email|approved' });
    expect(f.provider.approveMembership).not.toHaveBeenCalled();
  });
  it('crashed grants stay fenced even after the worker lease expires', async () => {
    const f = fixture(); f.user('email|approved'); await service.queue(approval());
    await rows().updateOne({}, { $set: { state: 'applying', nextCheck: 0 } });
    expect(await service.runOne(f.provider, f.authorized)).toBe(false);
    expect(f.provider.approveMembership).not.toHaveBeenCalled();
  });
  it('concurrent replicas grant once', async () => {
    const f = fixture(); f.user('email|approved'); await service.queue(approval());
    const replica = await LegalAuth0Memberships.fromDatabase(db());
    await Promise.all([service.runOne(f.provider, f.authorized), replica.runOne(f.provider, f.authorized)]);
    expect(f.provider.approveMembership).toHaveBeenCalledTimes(1);
  });
  it('serializes metadata publishers for different applicants in the same organization', async () => {
    const f = fixture(); f.user('email|approved');
    await service.queue(approval()); await service.queue({ ...approval(), email: 'colleague@firm.example', approvalId: 'c'.repeat(64) });
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    let started!: () => void; const entered = new Promise<void>(resolve => { started = resolve; });
    f.provider.registrationApproval.mockImplementationOnce(async () => { started(); await held; });
    const first = service.runOne(f.provider, f.authorized); await entered;
    await service.runOne(f.provider, f.authorized);
    expect(f.provider.registrationApproval).toHaveBeenCalledTimes(1);
    release(); await first;
    await service.runOne(f.provider, f.authorized, Date.now() + 3000);
    expect(f.provider.registrationApproval).toHaveBeenCalledTimes(2);
  });
  it('an expired job or revoked organization cannot create an account hint or grant membership', async () => {
    const f = fixture(); await service.queue({ ...approval(), expires: Date.now() - 1 });
    expect(await service.runOne(f.provider, f.authorized)).toBe(false);
    await service.queue({ ...approval(), approvalId: 'c'.repeat(64) }); f.authorized.mockResolvedValue(false);
    await service.runOne(f.provider, f.authorized);
    expect(f.provider.registrationApproval).not.toHaveBeenCalled(); expect(f.provider.approveMembership).not.toHaveBeenCalled();
  });
  it('rechecks removal after resolving the exact Auth0 subject', async () => {
    const f = fixture(); f.user('email|approved'); await service.queue(approval());
    f.authorized.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    await service.runOne(f.provider, f.authorized);
    expect(await rows().findOne({})).toMatchObject({ state: 'cancelled' });
    expect(f.provider.approveMembership).not.toHaveBeenCalled();
  });
  it('retries read outages without consuming the approval or granting anything', async () => {
    const f = fixture(); f.user('email|approved'); await service.queue(approval());
    f.provider.candidate.mockRejectedValueOnce(new Error('Auth0 unavailable'));
    await service.runOne(f.provider, f.authorized);
    expect(await rows().findOne({})).toMatchObject({ state: 'pending' });
    expect(f.provider.approveMembership).not.toHaveBeenCalled();
    await service.runOne(f.provider, f.authorized, Date.now() + 11000);
    expect(f.provider.approveMembership).toHaveBeenCalledTimes(1);
  });
  it('logs every failed attempt with a job prefix and a log-safe reason only', async () => {
    const f = fixture(); await service.queue(approval());
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
    f.provider.registrationApproval.mockRejectedValueOnce(new LegalProvisioningError('provider_unavailable', 'auth0_status_503'))
      .mockRejectedValueOnce(new Error('lawyer@firm.example org_approved'));
    await service.runOne(f.provider, f.authorized);
    await service.runOne(f.provider, f.authorized, Date.now() + 11_000);
    const job = (await rows().findOne({}))!;
    expect(job).toMatchObject({ state: 'pending' });
    expect(warn.mock.calls).toEqual([
      ['Legal membership job failed', job._id.slice(0, 8), 'retrying', 'provider_unavailable:auth0_status_503'],
      ['Legal membership job failed', job._id.slice(0, 8), 'retrying', 'Error'],
    ]);
    expect(JSON.stringify(warn.mock.calls)).not.toMatch(/firm\.example|org_approved/);
    warn.mockRestore();
  });
  it('cancels a job whose Auth0 organization was deleted instead of retrying until expiry', async () => {
    const f = fixture(), value = approval(); await service.queue(value);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
    const retire = jest.fn(async () => {});
    f.provider.registrationApproval.mockRejectedValue(new LegalProvisioningError('provider_binding', 'organization_deleted'));
    await service.runOne(f.provider, f.authorized, undefined, retire);
    expect(await rows().findOne({})).toMatchObject({ state: 'cancelled' });
    expect(retire).toHaveBeenCalledWith(expect.objectContaining(value));
    expect(warn).toHaveBeenCalledWith('Legal membership job failed', expect.any(String), 'cancelled', 'provider_binding:organization_deleted');
    expect(await service.runOne(f.provider, f.authorized, Date.now() + 11_000, retire)).toBe(false);
    expect(f.provider.registrationApproval).toHaveBeenCalledTimes(1);
    expect(f.provider.createApprovedAccount).not.toHaveBeenCalled(); expect(f.provider.approveMembership).not.toHaveBeenCalled();
    // A cancelled job is a tombstone like every other final state.
    expect(await service.consumed(value.organizationId, value.email)).toBe(true);
    warn.mockRestore();
  });
  it('keeps the deleted-organization job cancelled when roster retirement fails', async () => {
    const f = fixture(); await service.queue(approval());
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
    f.provider.registrationApproval.mockRejectedValue(new LegalProvisioningError('provider_binding', 'organization_deleted'));
    await service.runOne(f.provider, f.authorized, undefined, async () => { throw new LegalProvisioningError('provider_unavailable', 'fetch'); });
    expect(await rows().findOne({})).toMatchObject({ state: 'cancelled' });
    expect(warn).toHaveBeenLastCalledWith('Legal membership roster retirement failed', expect.any(String), 'provider_unavailable:fetch');
    warn.mockRestore();
  });
  it('treats only a deleted organization as final; other provider failures still retry', async () => {
    const f = fixture(); await service.queue(approval());
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
    const retire = jest.fn(async () => {});
    f.provider.registrationApproval.mockRejectedValueOnce(new LegalProvisioningError('provider_unavailable', 'auth0_status_404'));
    await service.runOne(f.provider, f.authorized, undefined, retire);
    expect(await rows().findOne({})).toMatchObject({ state: 'pending' });
    expect(retire).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});
