import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { FirmSession } from '../../../lib/confidential/firmCase';

jest.mock('../../../lib/confidential/client', () => ({ forgetChannelSessions: jest.fn() }));
const readSharedList = jest.fn();
jest.mock('../../../lib/confidential/firmSharedRequests', () => ({ readSharedList: (...args: unknown[]) => readSharedList(...args) }));

const CASE_ID = 'ab'.repeat(32);
const NOW = Date.UTC(2026, 8, 27, 12);
const entry = { caseId: CASE_ID, requestId: 'cd'.repeat(32), ownerPublicKey: 'owner-key', summary: 'Shared summary',
  requestedAt: NOW - 1000, expiresAt: NOW + 1000, recipientKeyId: 'key-1', state: 'requested', updatedAt: NOW, grantExpiresAt: null };
const session = (): FirmSession => ({ firm: { organizationId: 'org-1', recipientKeyId: 'key-1' },
  // The reporter key is already pinned (from a saved checkpoint), but this device never saw the request itself.
  owners: new Map([[CASE_ID, {}]]), pins: new Map() } as unknown as FirmSession);

describe('the report view learns its request once the shared list loads', () => {
  beforeEach(() => { readSharedList.mockReset(); jest.resetModules(); });

  test('a request known only from the shared list is returned after loading it', async () => {
    readSharedList.mockResolvedValue({ version: 1, list: { keyEpoch: 1, requests: [entry] }, previousKeySigned: false });
    const portal = await import('../../../lib/confidential/firmPortal');
    const current = session();
    portal.setFirmSession(current);
    expect(portal.rememberedRequests('org-1')).toEqual([]);
    const resolved = await portal.resolveCaseRequest(current, CASE_ID);
    expect(readSharedList).toHaveBeenCalledTimes(1);
    expect(resolved).toEqual({ pinned: true, request: { caseId: CASE_ID, requestId: entry.requestId,
      ownerPublicKey: 'owner-key', summary: 'Shared summary', requestedAt: entry.requestedAt } });
    // Once the list is loaded it is not fetched again.
    await portal.resolveCaseRequest(current, CASE_ID);
    expect(readSharedList).toHaveBeenCalledTimes(1);
    portal.setFirmSession(null);
  });

  test('a cached list that predates a colleague\'s request is reloaded', async () => {
    readSharedList.mockResolvedValueOnce({ version: 1, list: { keyEpoch: 1, requests: [] }, previousKeySigned: false })
      .mockResolvedValueOnce({ version: 2, list: { keyEpoch: 1, requests: [entry] }, previousKeySigned: false });
    const portal = await import('../../../lib/confidential/firmPortal');
    const current = session();
    portal.setFirmSession(current);
    await portal.loadSharedRequests(current);
    expect(portal.currentSharedList()).not.toBeNull();
    const resolved = await portal.resolveCaseRequest(current, CASE_ID);
    expect(readSharedList).toHaveBeenCalledTimes(2);
    expect(resolved.request?.requestId).toBe(entry.requestId);
    portal.setFirmSession(null);
  });

  test('an unavailable shared list leaves the request unknown without failing', async () => {
    readSharedList.mockRejectedValue(new Error('unavailable'));
    const portal = await import('../../../lib/confidential/firmPortal');
    const current = session();
    portal.setFirmSession(current);
    await expect(portal.resolveCaseRequest(current, CASE_ID)).resolves.toEqual({ pinned: true, request: null });
    portal.setFirmSession(null);
  });

  test('CaseView keeps the request in state and uses the resolved one for the status lookup', () => {
    const source = readFileSync(path.join(__dirname, '../../../components/vera/confidential/LegalReportView.tsx'), 'utf8');
    const view = source.slice(source.indexOf('export function CaseView('));
    expect(view).not.toMatch(/const remembered = useMemo/);
    expect(view).toMatch(/const \[remembered, setRemembered\] = useState/);
    expect(view).toMatch(/const resolved = await resolveCaseRequest\(session, caseId\);[\s\S]*?request = resolved\.request;\s*setRemembered\(request\);/);
    expect(view).toMatch(/if \(request\) \{[\s\S]*?try \{ status = refusedCaseStatus\(await readRequestStatus\(session, caseId, request\.requestId/);
    // load() must not depend on the request it refreshes.
    expect(view).toMatch(/\}, \[session, caseId\]\);\s*useEffect\(\(\) => \{ void load\(\);/);
  });
});
