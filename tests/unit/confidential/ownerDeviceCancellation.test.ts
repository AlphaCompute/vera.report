const cleanups: (() => void)[] = [];
let stateIndex = 0;
jest.mock('react', () => ({ ...jest.requireActual('react'),
  useState: (value: unknown) => [stateIndex++ === 0 ? 'device' : value, jest.fn()],
  useRef: (value: unknown) => ({ current: value }),
  useEffect: (effect: () => () => void) => cleanups.push(effect()),
}));
jest.mock('../../../lib/confidential/deviceVault', () => ({
  browserVaultStore: jest.fn(), createDeviceBoundVault: jest.fn(), createDeviceVault: jest.fn(),
}));
jest.mock('../../../lib/confidential/deviceWorkspace', () => ({
  clearDeviceLocked: jest.fn(), lockParticipantTabs: jest.fn(), subscribeDeviceLock: jest.fn(),
}));
import { OwnerDevicePanel } from '../../../components/vera/confidential/OwnerDevice';
import { browserVaultStore, createDeviceBoundVault } from '../../../lib/confidential/deviceVault';
import { clearDeviceLocked, subscribeDeviceLock } from '../../../lib/confidential/deviceWorkspace';
import type { UnlockedVault } from '../../../lib/confidential/deviceVault';

function deferred() {
  let resolve!: () => void, reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function findConfirm(node: any): any {
  if (!node || typeof node !== 'object') return;
  if (node.type === 'button' && node.props.children === 'I understand — keep unlocked on this device') return node;
  for (const child of [node.props?.children].flat(Infinity)) { const found = findConfirm(child); if (found) return found; }
}
afterEach(() => { while (cleanups.length) cleanups.pop()!(); jest.clearAllMocks(); });

test.each(['completed', 'failed'] as const)('lock during old-vault deletion (%s) retains one saved copy without unlocking', async outcome => {
  stateIndex = 0;
  const old = { id: 'old', protection: 'passphrase', lock: jest.fn() } as unknown as UnlockedVault;
  const replacement = { id: 'new', protection: 'device', lock: jest.fn() } as unknown as UnlockedVault;
  const saved = new Set(['old']), started = deferred(), removal = deferred();
  const remove = jest.fn(async (id: string) => {
    if (id === old.id) { started.resolve(); await removal.promise; }
    saved.delete(id);
  });
  jest.mocked(browserVaultStore).mockReturnValue({ remove } as any);
  jest.mocked(createDeviceBoundVault).mockImplementation(async () => { saved.add('new'); return replacement; });
  let lock!: () => void;
  jest.mocked(subscribeDeviceLock).mockImplementation(callback => { lock = callback; return () => {}; });
  const changed = jest.fn();
  const tree = OwnerDevicePanel({ className: '', vault: old, onVaultChange: changed, getPayload: async () => ({}) });
  findConfirm(tree).props.onClick();
  await started.promise;
  lock();
  if (outcome === 'completed') removal.resolve(); else removal.reject(new Error('storage failure'));
  // Finish the asynchronous handler, including its rollback, without timer retries.
  await new Promise(resolve => setImmediate(resolve));
  expect(saved).toEqual(new Set([outcome === 'completed' ? 'new' : 'old']));
  expect(replacement.lock).toHaveBeenCalledTimes(1);
  expect(old.lock).toHaveBeenCalledTimes(outcome === 'completed' ? 1 : 0);
  expect(clearDeviceLocked).not.toHaveBeenCalled();
  expect(changed).not.toHaveBeenCalled();
});
