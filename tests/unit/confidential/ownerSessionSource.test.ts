import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ownerSessionFor, sameOwnerSessionSource, type OwnerSessionSource } from '../../../lib/confidential/ownerSessionSource';
import type { CheckpointPin } from '../../../enclave/src/confidential/recovery';

type FakeSession = { recoveryPackage: string | null; pin: CheckpointPin | undefined };
const CODE = 'ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-6789-ABCD-EFGH-JKLM-NPQR-STUV-WXYZ';
const pin = (revision: number, digest = `d${revision}`): CheckpointPin =>
  ({ caseId: 'case-1', ownerFingerprint: 'fp', revision, keyEpoch: 1, digest });

const harness = () => {
  const held = { session: { current: null as FakeSession | null }, source: { current: null as OwnerSessionSource | null } };
  // Stands in for owner.restoreOwnerSession: records what it was given.
  const restoreOwnerSession = jest.fn(async (source: OwnerSessionSource) =>
    ({ recoveryPackage: source.recoveryPackage, pin: source.savedPin }) as FakeSession);
  const release = jest.fn();
  const open = (source: OwnerSessionSource) => ownerSessionFor(held, source, restoreOwnerSession, release);
  return { held, restoreOwnerSession, release, open };
};

describe('owner session source', () => {
  test('a newer recovery file for the report already open restores from the newer file', async () => {
    const { restoreOwnerSession, release, open } = harness();
    const first = await open({ recoveryCode: CODE, recoveryPackage: 'file-A', savedPin: undefined });
    const second = await open({ recoveryCode: CODE, recoveryPackage: 'file-B', savedPin: undefined });
    expect(restoreOwnerSession).toHaveBeenCalledTimes(2);
    expect(restoreOwnerSession.mock.calls[1][0].recoveryPackage).toBe('file-B');
    expect(second).not.toBe(first);
    expect(second?.recoveryPackage).toBe('file-B');
    // The older session's channel sessions are released, never reused.
    expect(release).toHaveBeenCalledWith(first);
  });

  test('a newer checkpoint pin for the same code restores again', async () => {
    const { restoreOwnerSession, open } = harness();
    await open({ recoveryCode: CODE, recoveryPackage: 'file-A', savedPin: pin(3) });
    const next = await open({ recoveryCode: CODE, recoveryPackage: 'file-A', savedPin: pin(4) });
    expect(restoreOwnerSession).toHaveBeenCalledTimes(2);
    expect(next?.pin?.revision).toBe(4);
  });

  test('reloading the same source reuses the attested session', async () => {
    const { restoreOwnerSession, release, open } = harness();
    const source = { recoveryCode: CODE, recoveryPackage: 'file-A', savedPin: pin(3) };
    const first = await open(source);
    const again = await open({ ...source, savedPin: pin(3) });
    expect(again).toBe(first);
    expect(restoreOwnerSession).toHaveBeenCalledTimes(1);
    expect(release).not.toHaveBeenCalled();
  });

  test('a superseded restore stores nothing', async () => {
    const { held, release, open } = harness();
    await open({ recoveryCode: CODE, recoveryPackage: 'file-A', savedPin: undefined });
    const result = await ownerSessionFor(held, { recoveryCode: CODE, recoveryPackage: 'file-B', savedPin: undefined },
      async () => null, release);
    expect(result).toBeNull();
    expect(held.session.current).toBeNull();
    expect(held.source.current).toBeNull();
  });

  test('pins differing in digest are different sources', () => {
    const a = { recoveryCode: CODE, recoveryPackage: null, savedPin: pin(3, 'x') };
    expect(sameOwnerSessionSource(a, { ...a, savedPin: pin(3, 'y') })).toBe(false);
    expect(sameOwnerSessionSource(null, a)).toBe(false);
  });

  test('the status page remounts the report view on every open', () => {
    const page = readFileSync(join(__dirname, '../../../pages/status.tsx'), 'utf8');
    expect(page).toMatch(/setOpenCount\(count => count \+ 1\)/);
    expect(page).toMatch(/<ConfidentialCaseStatus key=\{`open-\$\{openCount\}`\}/);
    const view = readFileSync(join(__dirname, '../../../components/vera/confidential/ConfidentialCaseStatus.tsx'), 'utf8');
    expect(view).toContain('ownerSessionFor(');
    expect(view).not.toMatch(/if \(!session\.current\) \{/);
  });
});
