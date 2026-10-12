// Synthetic Socket Mode boundary for QA only. The real reviewer allowlist,
// immutable journal signatures, provider resolution and worker run unchanged.
import { combinedApprovalWorker } from '../../../scripts/lib/combinedApprovalWorker';
import { legalApplicationProvisioner } from '../../../src/services/legalApplicationAuth0';
import { authorizeSlackApplicationDecision } from '../../../src/services/legalApplicationSlack';
import { projectLegalApplication } from '../../../src/utils/legalApplications';
import type { PrivateKey } from '../../../enclave/src/confidential/pgp';
import { applicationFixtures } from './legalApplications';

export function startCombinedApprovalFixture(authority: PrivateKey, apiOrigin: string, secret: string, identity: { issuer: string; clientId: string; audience: string }) {
  const reviews = new Map<string, string>(), approvals = new Map<string, string>(), completed = new Set<string>();
  const request = async (action: string, data: unknown) => {
    const response = await fetch(`${apiOrigin}/api/internal/legal-approval/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-internal-secret': secret }, body: JSON.stringify(data) });
    if (response.status === 409) return { success: false };
    if (!response.ok) throw new Error('Fixture backend unavailable');
    return response.json();
  };
  const worker = combinedApprovalWorker({ authority, provider: legalApplicationProvisioner(applicationFixtures.backend, identity)!,
    backend: {
      get: async id => projectLegalApplication((await request('get', { id })).application),
      decide: async decision => (await request('decide', decision)).success === true,
      publish: async (id, digest, approval) => { if (!(await request('combined-approval', { id, digest, approval })).success) throw new Error(); },
    }, journal: {
      record: async (id, wire) => { if (!reviews.has(id)) reviews.set(id, wire); return reviews.get(id)!; },
      entries: async () => [...reviews].filter(([id]) => !completed.has(id)).map(([, wire]) => wire),
      saveApproval: async (id, wire) => { if (!approvals.has(id)) approvals.set(id, wire); return approvals.get(id)!; },
      complete: async id => { completed.add(id); },
    } });
  let pending: Promise<void> | null = null;
  const timer = setInterval(() => { if (!pending) pending = worker.provision().catch(() => {}).finally(() => { pending = null; }); }, 1000);
  return {
    decide: async (payload: unknown) => {
      const decision = authorizeSlackApplicationDecision(payload, applicationFixtures.frontend);
      if (!decision) return 403;
      return await worker.decide(decision) ? 200 : 409;
    },
    stop: async () => { clearInterval(timer); await pending; },
  };
}
