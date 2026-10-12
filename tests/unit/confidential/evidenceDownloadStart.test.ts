const cleanups: (() => void)[] = [];
jest.mock('react', () => ({
  ...jest.requireActual('react'),
  useCallback: (fn: unknown) => fn,
  useReducer: (_reducer: unknown, value: unknown) => [value, jest.fn()],
  useRef: (value: unknown) => ({ current: value }),
  useState: (value: unknown) => [value, jest.fn()],
  useEffect: (effect: () => (() => void) | void) => { const cleanup = effect(); if (cleanup) cleanups.push(cleanup); },
}));
jest.mock('../../../lib/confidential/participantLock', () => ({ useParticipantLockHold: jest.fn() }));
jest.mock('../../../lib/confidential/evidenceTransfer', () => ({
  chooseEvidenceSink: jest.fn(),
  memorySink: jest.fn(),
  EvidenceDownload: jest.fn(),
  EvidenceDownloadError: class extends Error {},
}));
jest.mock('../../../lib/confidential/ownerCase', () => ({
  listOwnerEvidence: jest.fn().mockResolvedValue([]), openOwnerWholeEvidence: jest.fn(),
}));
import { OwnerFiles } from '../../../components/vera/confidential/OwnerFiles';
import { openOwnerWholeEvidence } from '../../../lib/confidential/ownerCase';
import { EvidenceDownloadButton } from '../../../components/vera/confidential/EvidenceDownloadButton';
import { chooseEvidenceSink, EvidenceDownload, memorySink } from '../../../lib/confidential/evidenceTransfer';

const flush = () => new Promise<void>(resolve => setImmediate(resolve));
const sink = () => ({ write: jest.fn(), close: jest.fn(), abort: jest.fn().mockResolvedValue(undefined) });
function click(open = jest.fn()) {
  const view = EvidenceDownloadButton({ name: 'evidence', open });
  return view.props.children[0].props.children[0].props.onClick as () => void;
}
afterEach(() => { while (cleanups.length) cleanups.pop()!(); jest.clearAllMocks(); });

test('locking before the lazy import resolves never opens the save dialog', async () => {
  click()();
  cleanups.pop()!();
  await flush();
  expect(chooseEvidenceSink).not.toHaveBeenCalled();
  expect(EvidenceDownload).not.toHaveBeenCalled();
});

test('locking while the save dialog is open aborts the late sink without opening private evidence', async () => {
  let resolve!: (value: ReturnType<typeof sink>) => void;
  jest.mocked(chooseEvidenceSink).mockReturnValue(new Promise(done => { resolve = done; }));
  const open = jest.fn();
  click(open)(); await flush();
  cleanups.pop()!();
  const file = sink(); resolve(file); await flush();
  expect(file.abort).toHaveBeenCalledTimes(1);
  expect(EvidenceDownload).not.toHaveBeenCalled();
  expect(open).not.toHaveBeenCalled();
});

test('double clicks share one pending start and cancellation of the dialog allows retry', async () => {
  let resolve!: (value: null) => void;
  jest.mocked(chooseEvidenceSink).mockReturnValue(new Promise(done => { resolve = done; }));
  const start = click(); start(); start(); await flush();
  expect(chooseEvidenceSink).toHaveBeenCalledTimes(1);
  resolve(null); await flush();
  jest.mocked(chooseEvidenceSink).mockResolvedValue(null);
  start(); await flush();
  expect(chooseEvidenceSink).toHaveBeenCalledTimes(2);
});


test('locking while an earlier whole-file format is opening discards plaintext without offering a download', async () => {
  let resolve!: (value: any) => void;
  jest.mocked(openOwnerWholeEvidence).mockReturnValue(new Promise(done => { resolve = done; }));
  const list = OwnerFiles({ session: {} as any, inbox: {} as any, panel: '' });
  const element = list.props.renderDownload({ chunked: false, objectId: 'test' });
  const view = element.type(element.props);
  view.props.children[0].props.onClick();
  await flush();
  while (cleanups.length) cleanups.pop()!();
  const bytes = new Uint8Array([1, 2, 3]);
  resolve({ name: 'private', bytes }); await flush();
  expect(memorySink).not.toHaveBeenCalled();
  expect([...bytes]).toEqual([0, 0, 0]);
});
