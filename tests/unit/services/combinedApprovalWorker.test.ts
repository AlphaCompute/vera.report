import { generateKey, createMessage, sign } from '../../../enclave/src/confidential/pgp';
import { createFirmKeyBinding } from '../../../enclave/src/confidential/firmKeyBinding';
import { caseRecipientKeyId } from '../../../enclave/src/confidential/caseObject';
import { applicationOrganizationId } from '../../../enclave/src/confidential/applicationOrganization';
import { applicationReviewDigest } from '../../../src/utils/legalApplicationEnrollment';
import { combinedApprovalWorker, failureReason } from '../../../scripts/lib/combinedApprovalWorker';
import { authorizeSlackApplicationDecision } from '../../../src/services/legalApplicationSlack';
import { LegalProvisioningError, type LegalApplicationView } from '../../../src/utils/legalApplications';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { signCombinedApplicationApproval, verifyCombinedApplicationApproval } from '../../../enclave/src/confidential/combinedApplicationApproval';
const REVIEW_LIFETIME = 7 * 86400000;
let authority: PrivateKey, application: LegalApplicationView, digest: string;
beforeAll(async () => {
  const [a, firm] = await Promise.all(['authority', 'firm'].map(async name => (await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name }], format: 'object' })).privateKey)); authority = a;
  const id = await applicationOrganizationId(await caseRecipientKeyId(firm.toPublic())), domain = 'firm.example';
  application = { id, domain, displayName: 'Firm', email: 'counsel@firm.example', lawyerName: 'Counsel', jurisdiction: 'New York', registrationNumber: 'TEST-123', createdAt: Date.now(), status: 'pending',
    enrollment: { organizationId: id, recipientKeyId: await caseRecipientKeyId(firm.toPublic()), bindingDocument: await createFirmKeyBinding({ organizationId: id, domain, issuedAt: Date.now(),
      profile: { practiceAreas: ['whistleblower'], jurisdiction: 'New York', website: 'https://firm.example/' } }, firm) } };
  digest = await applicationReviewDigest(application);
});
function fixture() {
  const records = new Map<string, string>(), approvals = new Map<string, string>(), done = new Set<string>();
  let current = { ...application };
  let clock = Date.now();
  const backend = { get: jest.fn(async () => current), decide: jest.fn(async () => true), publish: jest.fn(async () => {}) };
  const resolveApprovedMember = jest.fn(async () => 'email|approved');
  const journal = {
    record: async (id: string, wire: string) => { if (!records.has(id)) records.set(id, wire); return records.get(id)!; },
    entries: async () => [...records].filter(([id]) => !done.has(id)).map(([, value]) => value),
    saveApproval: jest.fn(async (id: string, wire: string) => { if (!approvals.has(id)) approvals.set(id, wire); return approvals.get(id)!; }),
    complete: jest.fn(async (id: string, _outcome?: 'published' | 'expired') => { done.add(id); }),
  };
  const restart = () => combinedApprovalWorker({ authority, backend, now: () => clock,
    provider: { organization: jest.fn(), invite: jest.fn(), resolveApprovedMember }, journal });
  return { worker: restart(), restart, backend, records, approvals, journal, resolveApprovedMember,
    time: () => clock, setTime: (time: number) => { clock = time; }, current: (row: LegalApplicationView) => { current = row; } };
}
const ready = (): LegalApplicationView => ({ ...application, status: 'approved', keyReviewStatus: 'approved',
  provisioningStatus: 'ready', providerOrganizationId: 'org_firm' });
const decision = () => ({ id: application.id, status: 'approved' as const, actor: 'slack:T123:U123', reviewDigest: digest, confirmedKeyId: application.enrollment!.recipientKeyId });
test('Slack requires allowlisted workspace/reviewer and transports the exact snapshot digest', () => {
  const payload = { type: 'block_actions', team: { id: 'T123' }, user: { id: 'U123' },
    actions: [{ action_id: 'vera_application_approve', value: `v2:${application.id}:${digest}:${application.enrollment!.recipientKeyId}` }] };
  const env = { SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: 'U123' };
  expect(authorizeSlackApplicationDecision(payload, env)).toEqual(decision());
  expect(authorizeSlackApplicationDecision(payload, { ...env, SLACK_APPLICATION_APPROVERS: 'U999' })).toBeNull();
  expect(authorizeSlackApplicationDecision({ ...payload, team: { id: 'T999' } }, env)).toBeNull();
  expect(authorizeSlackApplicationDecision({ ...payload, actions: [{ action_id: 'vera_application_approve', value: `v1:${application.id}:${digest}` }] }, env)).toBeNull();
});
test('missing or mismatched full Key ID never creates a journal, backend intent or certificate', async () => {
  for (const confirmedKeyId of [undefined, '', '0'.repeat(64), application.enrollment!.recipientKeyId.slice(0, 16)]) {
    const f = fixture();
    expect(await f.worker.decide({ ...decision(), confirmedKeyId })).toBe(false);
    expect(f.records.size).toBe(0); expect(f.backend.decide).not.toHaveBeenCalled();
    await f.worker.provision(); expect(f.backend.publish).not.toHaveBeenCalled();
  }
});
test('a signed journal without an approved key cannot resume signing', async () => {
  const f = fixture();
  const { confirmedKeyId: _, ...legacyDecision } = decision();
  const record = { decision: legacyDecision, application, decidedAt: Date.now() };
  const signature = await sign({ message: await createMessage({ binary: new TextEncoder().encode(JSON.stringify(record)) }),
    signingKeys: authority, detached: true, format: 'armored' });
  f.records.set(application.id, JSON.stringify({ record, signature }));
  await expect(f.worker.provision()).rejects.toThrow('Some approvals remain pending');
  expect(f.backend.decide).not.toHaveBeenCalled(); expect(f.resolveApprovedMember).not.toHaveBeenCalled();
  expect(f.backend.publish).not.toHaveBeenCalled();
});
test('changed applicant, key or profile cannot inherit the displayed approval', async () => {
  const f = fixture(); f.current({ ...application, email: 'attacker@firm.example' });
  expect(await f.worker.decide(decision())).toBe(false); expect(f.records.size).toBe(0); expect(f.backend.decide).not.toHaveBeenCalled();
});
test('approval is journaled once, survives retries, and waits for independent IdP resolution', async () => {
  const f = fixture(); expect(await f.worker.decide(decision())).toBe(true);
  expect(JSON.parse(f.records.get(application.id)!).record.decision.confirmedKeyId).toBe(application.enrollment!.recipientKeyId);
  expect(await f.worker.decide({ ...decision(), status: 'denied' })).toBe(false);
  await f.worker.provision(); expect(f.backend.publish).not.toHaveBeenCalled();
  f.current({ ...application, status: 'approved', keyReviewStatus: 'approved', provisioningStatus: 'ready', providerOrganizationId: 'org_firm' });
  await f.worker.provision(); expect(f.resolveApprovedMember).toHaveBeenCalledTimes(1); expect(f.backend.publish).toHaveBeenCalledTimes(1);
  await f.worker.provision(); expect(f.resolveApprovedMember).toHaveBeenCalledTimes(1);
});
test('a forged host approval without a Slack journal never invokes the signer or provider', async () => {
  const f = fixture(); f.current({ ...application, status: 'approved', provisioningStatus: 'ready', providerOrganizationId: 'org_firm' });
  await f.worker.provision(); expect(f.resolveApprovedMember).not.toHaveBeenCalled(); expect(f.backend.publish).not.toHaveBeenCalled();
});
test('removal in the identity provider does not get repaired by the signing worker', async () => {
  const f = fixture(); await f.worker.decide(decision());
  f.current({ ...application, status: 'approved', keyReviewStatus: 'approved', provisioningStatus: 'ready', providerOrganizationId: 'org_firm' });
  f.resolveApprovedMember.mockRejectedValue(new Error('membership removed'));
  await expect(f.worker.provision()).rejects.toThrow('Some approvals remain pending');
  expect(f.approvals.size).toBe(0); expect(f.backend.publish).not.toHaveBeenCalled();
});
test('denial and tampering with a signed journal never produce an enrollment certificate', async () => {
  const denied = fixture(); await denied.worker.decide({ ...decision(), status: 'denied' });
  await denied.worker.provision(); expect(denied.resolveApprovedMember).not.toHaveBeenCalled();
  const altered = fixture(); await altered.worker.decide(decision());
  const wire = JSON.parse(altered.records.get(application.id)!); wire.record.decision.actor = 'slack:T123:U999';
  altered.records.set(application.id, JSON.stringify(wire));
  await expect(altered.worker.provision()).rejects.toThrow();
  expect(altered.resolveApprovedMember).not.toHaveBeenCalled(); expect(altered.backend.publish).not.toHaveBeenCalled();
});

test.each([REVIEW_LIFETIME, REVIEW_LIFETIME + 1])('an approval aged %i ms is dropped unsigned before backend replay or IdP access', async age => {
  const f = fixture(); await f.worker.decide(decision()); f.current(ready());
  f.backend.decide.mockClear(); f.backend.get.mockClear(); f.setTime(f.time() + age);
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
  await f.worker.provision();
  expect(f.journal.complete).toHaveBeenCalledWith(application.id, 'expired');
  expect(warn).toHaveBeenCalledWith(expect.stringContaining('expired'), application.id.slice(0, 8));
  expect(JSON.stringify(warn.mock.calls)).not.toContain(application.id);
  expect(f.backend.decide).not.toHaveBeenCalled(); expect(f.backend.get).not.toHaveBeenCalled();
  expect(f.resolveApprovedMember).not.toHaveBeenCalled(); expect(f.approvals.size).toBe(0);
  expect(f.backend.publish).not.toHaveBeenCalled();
  // Not retried every cycle once dropped.
  expect(await f.journal.entries()).toEqual([]);
  await f.worker.provision(); expect(f.journal.complete).toHaveBeenCalledTimes(1);
  warn.mockRestore();
});
test('restart and repeat approval cannot replace the original signed decision time', async () => {
  const f = fixture(); await f.worker.decide(decision());
  const original = f.records.get(application.id);
  f.setTime(f.time() + REVIEW_LIFETIME); f.backend.decide.mockClear();
  await expect(f.restart().decide(decision())).rejects.toThrow();
  expect(f.records.get(application.id)).toBe(original);
  expect(f.backend.decide).not.toHaveBeenCalled(); expect(f.approvals.size).toBe(0);
});
test('delayed first sign-in receives only the time remaining from the original decision', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision());
  f.setTime(decidedAt + REVIEW_LIFETIME - 1); f.current(ready());
  await f.restart().provision();
  const checked = await verifyCombinedApplicationApproval(f.approvals.get(application.id)!, authority.toPublic(), f.time());
  expect(checked.authorization.issuedAt).toBe(f.time());
  expect(checked.authorization.expiresAt).toBe(decidedAt + REVIEW_LIFETIME);
  expect(f.backend.publish).toHaveBeenCalledTimes(1);
});
test('expiry while resolving the approved IdP member prevents signing and caching', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision()); f.current(ready());
  f.resolveApprovedMember.mockImplementationOnce(async () => { f.setTime(decidedAt + REVIEW_LIFETIME); return 'email|approved'; });
  await expect(f.worker.provision()).rejects.toMatchObject({ failures: ['review-age: Error'] });
  expect(f.journal.saveApproval).not.toHaveBeenCalled(); expect(f.backend.publish).not.toHaveBeenCalled();
});
test('expiry during the backend snapshot read prevents IdP access', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision());
  f.backend.get.mockImplementationOnce(async () => { f.setTime(decidedAt + REVIEW_LIFETIME); return ready(); });
  await expect(f.worker.provision()).rejects.toThrow('Some approvals remain pending');
  expect(f.resolveApprovedMember).not.toHaveBeenCalled(); expect(f.backend.publish).not.toHaveBeenCalled();
});
test('expiry during durable certificate storage prevents publication', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision()); f.current(ready());
  f.journal.saveApproval.mockImplementationOnce(async (_id, wire) => { f.setTime(decidedAt + REVIEW_LIFETIME); return wire; });
  await expect(f.worker.provision()).rejects.toMatchObject({ failures: ['review-age: Error'] });
  expect(f.backend.publish).not.toHaveBeenCalled();
});
test('publication retries use the same certificate and never extend its original deadline', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision()); f.current(ready());
  f.backend.publish.mockRejectedValueOnce(new Error('temporary outage'));
  await expect(f.worker.provision()).rejects.toThrow();
  const original = f.approvals.get(application.id);
  f.setTime(decidedAt + 86400000);
  await f.restart().provision();
  expect(f.approvals.get(application.id)).toBe(original);
  const checked = await verifyCombinedApplicationApproval(original!, authority.toPublic(), f.time());
  expect(checked.authorization.expiresAt).toBe(decidedAt + REVIEW_LIFETIME);
});
test('a certificate cached before a publication outage cannot be published after expiry', async () => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision()); f.current(ready());
  f.backend.publish.mockRejectedValueOnce(new Error('temporary outage'));
  await expect(f.worker.provision()).rejects.toThrow();
  const original = f.approvals.get(application.id);
  f.backend.publish.mockClear(); f.resolveApprovedMember.mockClear(); f.journal.saveApproval.mockClear();
  f.setTime(decidedAt + REVIEW_LIFETIME);
  const warn = jest.spyOn(console, 'warn').mockImplementation(() => {}); warn.mockClear();
  await f.restart().provision(); warn.mockRestore();
  expect(f.journal.complete).toHaveBeenCalledWith(application.id, 'expired');
  expect(f.backend.publish).not.toHaveBeenCalled(); expect(f.resolveApprovedMember).not.toHaveBeenCalled();
  expect(f.journal.saveApproval).not.toHaveBeenCalled(); expect(f.approvals.get(application.id)).toBe(original);
});
test.each(['decidedAt', 'actor'])('cached certificate must preserve the journaled %s', async field => {
  const f = fixture(), decidedAt = f.time(); await f.worker.decide(decision()); f.current(ready());
  const wire = await signCombinedApplicationApproval({ organizationId: application.id, providerOrganizationId: 'org_firm',
    domain: application.domain, displayName: application.displayName, subject: 'email|approved',
    bindingDocument: application.enrollment!.bindingDocument, recipientKeyId: application.enrollment!.recipientKeyId,
    applicationDigest: digest, actor: field === 'actor' ? 'slack:T123:U456' : decision().actor,
    decidedAt: field === 'decidedAt' ? decidedAt - 1 : decidedAt, now: f.time() }, authority);
  f.journal.saveApproval.mockResolvedValueOnce(wire);
  await expect(f.worker.provision()).rejects.toThrow();
  expect(f.backend.publish).not.toHaveBeenCalled();
});
test.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER])('invalid worker clock %s cannot create a decision', async time => {
  const f = fixture(); f.setTime(time);
  await expect(f.worker.decide(decision())).rejects.toThrow();
  expect(f.records.size).toBe(0); expect(f.backend.decide).not.toHaveBeenCalled();
});
test('a future-dated signed journal is rejected before backend or IdP replay', async () => {
  const f = fixture(); await f.worker.decide(decision()); f.backend.decide.mockClear();
  f.setTime(f.time() - 1);
  await expect(f.worker.provision()).rejects.toMatchObject({ failures: ['decode: Error'] });
  expect(f.backend.decide).not.toHaveBeenCalled(); expect(f.resolveApprovedMember).not.toHaveBeenCalled();
  // A clock behind the decision is not expiry; the entry stays for a later retry.
  expect(f.journal.complete).not.toHaveBeenCalled(); expect(await f.journal.entries()).toHaveLength(1);
});
test('expiry never turns a durable denial into an approval', async () => {
  const f = fixture(); await f.worker.decide({ ...decision(), status: 'denied' });
  const original = f.records.get(application.id);
  f.setTime(f.time() + REVIEW_LIFETIME + 1);
  expect(await f.restart().decide(decision())).toBe(false);
  expect(f.records.get(application.id)).toBe(original);
  await f.worker.provision(); expect(f.backend.publish).not.toHaveBeenCalled();
});
test('failed approvals report the step and a log-safe reason, never the error message', async () => {
  const f = fixture(); await f.worker.decide(decision());
  f.current({ ...application, status: 'approved', keyReviewStatus: 'approved', provisioningStatus: 'ready', providerOrganizationId: 'org_firm' });
  f.resolveApprovedMember.mockRejectedValue(new LegalProvisioningError('provider_configuration'));
  await expect(f.worker.provision()).rejects.toMatchObject({ failures: ['resolve-member: provider_configuration'] });
  f.resolveApprovedMember.mockRejectedValue(new Error('owner@firm.example missing'));
  const error = await f.worker.provision().catch(caught => caught);
  expect(error.failures).toEqual(['resolve-member: Error']);
  expect(JSON.stringify(error.failures)).not.toContain('firm.example');
});
test('failure reasons keep only statuses, timeouts and fixed codes', () => {
  expect(failureReason(Object.assign(new Error(), { status: 401 }))).toBe('HTTP 401');
  expect(failureReason(new DOMException('slow', 'TimeoutError'))).toBe('timeout');
  expect(failureReason(Object.assign(new Error(), { code: 'EACCES' }))).toBe('EACCES');
  expect(failureReason(Object.assign(new Error(), { code: 'user@firm.example' }))).toBe('Error');
  expect(failureReason(null)).toBe('error');
  expect(failureReason(new TypeError('fetch failed', { cause: Object.assign(new Error('connect ECONNREFUSED 10.0.0.1:443'), { code: 'ECONNREFUSED' }) }))).toBe('ECONNREFUSED');
  expect(failureReason(new TypeError('fetch failed', { cause: Object.assign(new Error(), { code: 'UND_ERR_CONNECT_TIMEOUT' }) }))).toBe('UND_ERR_CONNECT_TIMEOUT');
  expect(failureReason(new TypeError('fetch failed', { cause: new Error('x') }))).toBe('TypeError');
});
test('failure reasons name the fixed provisioning source without identities', () => {
  expect(failureReason(new LegalProvisioningError('provider_unavailable', 'auth0_status_404'))).toBe('provider_unavailable:auth0_status_404');
  expect(failureReason(new LegalProvisioningError('provider_unavailable', 'lock_wait'))).toBe('provider_unavailable:lock_wait');
  expect(failureReason(new LegalProvisioningError('provider_unavailable'))).toBe('provider_unavailable');
  expect(failureReason(Object.assign(new Error(), { code: 'provider_unavailable', detail: 'user@firm.example' }))).toBe('provider_unavailable');
});
test('failure reasons keep MongoDB code names but not their messages', () => {
  expect(failureReason(Object.assign(new Error('E11000 duplicate key { email: "a@firm.example" }'), { code: 11000, codeName: 'DuplicateKey' }))).toBe('DuplicateKey');
});
