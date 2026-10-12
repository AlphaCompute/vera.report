import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { StackState } from '../stack/stack';
import { appendSecretRegister } from './leaks';

export const STATE_FILE = join(__dirname, '..', '.stack-state.json');
let cached: StackState | undefined;
export function stackState(): StackState {
  return cached ??= JSON.parse(readFileSync(STATE_FILE, 'utf8')) as StackState;
}

/**
 * Also sweep the host for these at teardown: the Next log, the API and enclave
 * output and every stored record. Returns the same list, so a spec can wrap the
 * secrets it already checks browser traffic for:
 *   expect(leakedSecrets(traffic, sweptFromHost([...SENTINELS]))).toEqual([]);
 * allowedIn names the only collections ("database.collection") the architecture
 * lets the host keep these in; everywhere else (logs included) is a leak.
 */
export function sweptFromHost(secrets: string[], options: { allowedIn?: string[] } = {}): string[] {
  appendSecretRegister(stackState().secretRegister, secrets, (file, data) => appendFileSync(file, data, { mode: 0o600 }), options.allowedIn);
  return secrets;
}

/** "database.collection" of a collection in the stack's confidential database. */
export function confidentialCollection(name: string): string {
  return `${stackState().confidentialDb}.${name}`;
}
