import { installFatalHandlers } from '../src/fatal.js';
import { createCaseKeyring } from '../src/cases/sealedStore.js';

it('wipes, logs a content-free line and exits on an escaped rejection or exception', () => {
  const handlers = new Map<string, (error: unknown) => void>();
  const on = jest.spyOn(process, 'on').mockImplementation(((event: string, handler: (error: unknown) => void) => {
    handlers.set(event, handler); return process;
  }) as typeof process.on);
  const exit = jest.spyOn(process, 'exit').mockImplementation((() => { throw new Error('exit'); }) as typeof process.exit);
  const stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  try {
    const wipe = jest.fn();
    installFatalHandlers('Test process', wipe);
    expect([...handlers.keys()].sort()).toEqual(['uncaughtException', 'unhandledRejection']);
    expect(() => handlers.get('unhandledRejection')!(new Error('case key 0123456789abcdef'))).toThrow('exit');
    expect(wipe).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
    expect(stderr.mock.calls.map(call => String(call[0]))).toEqual(['Test process: fatal runtime failure\n']);
    // A second failure while exiting neither wipes twice nor logs exception text.
    expect(() => handlers.get('uncaughtException')!(new Error('secret'))).toThrow('exit');
    expect(wipe).toHaveBeenCalledTimes(1);
    expect(stderr).toHaveBeenCalledTimes(1);
  } finally { on.mockRestore(); exit.mockRestore(); stderr.mockRestore(); }
});

it('still exits when wiping throws', () => {
  let handler: ((error: unknown) => void) | undefined;
  const on = jest.spyOn(process, 'on').mockImplementation(((event: string, h: (error: unknown) => void) => {
    if (event === 'uncaughtException') handler = h; return process;
  }) as typeof process.on);
  const exit = jest.spyOn(process, 'exit').mockImplementation((() => { throw new Error('exit'); }) as typeof process.exit);
  const stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  try {
    installFatalHandlers('Test process', () => { throw new Error('wipe failed'); });
    expect(() => handler!(new Error('x'))).toThrow('exit');
    expect(exit).toHaveBeenCalledWith(1);
  } finally { on.mockRestore(); exit.mockRestore(); stderr.mockRestore(); }
});

it('clearing the case keyring drops every held key', () => {
  const keyring = createCaseKeyring({ clock: () => 1 });
  keyring.set('a'.repeat(64), { stateEpoch: 1, key: new Uint8Array(32).fill(7) });
  keyring.set('b'.repeat(64), { stateEpoch: 1, key: new Uint8Array(32).fill(9) });
  const held = keyring.get('a'.repeat(64))!;
  expect(held.key.every(byte => byte === 7)).toBe(true);
  keyring.clear();
  expect(keyring.get('a'.repeat(64))).toBeNull();
  expect(keyring.get('b'.repeat(64))).toBeNull();
});
