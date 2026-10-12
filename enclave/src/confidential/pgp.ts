/** All protocol key/message objects must come from this entry point. OpenPGP
 * packet classes are runtime-specific: importing another installed copy and
 * passing its live objects here can fail even when the versions match.
 * Across process/bundle boundaries exchange serialized keys/messages and parse
 * them with this runtime; never transfer library objects. The browser bundler
 * resolves this dependency's browser export, the enclave its Node export.
 */
import * as pgp from 'openpgp';
import { pgpSigningDate, pgpVerificationDate } from './pgpClock.ts';
export { enums, readKey, readMessage, readPrivateKey, readSignature } from 'openpgp';
export type { PrivateKey, PublicKey, SessionKey } from 'openpgp';

/** Preserve OpenPGP's overloads and explicit dates; only its implicit device
 * clock changes. Snapshot at invocation so an async operation uses one date.
 * Signing uses the lower attested bound, verification the conservative upper
 * bound. This also covers key self-signatures and encrypted object envelopes. */
function dated<T extends (options: never) => unknown>(operation: T, now: () => Date): T {
  return ((options: { date?: Date }) => operation({ ...options,
    date: options.date === undefined ? now() : options.date } as never)) as unknown as T;
}
export const createMessage = dated(pgp.createMessage, pgpSigningDate);
export const generateKey = dated(pgp.generateKey, pgpSigningDate);
export const encrypt = dated(pgp.encrypt, pgpSigningDate);
export const sign = dated(pgp.sign, pgpSigningDate);
export const decrypt = dated(pgp.decrypt, pgpVerificationDate);
export const verify = dated(pgp.verify, pgpVerificationDate);
