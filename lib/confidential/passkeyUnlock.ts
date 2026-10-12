import type { PasskeySecret } from './deviceVault';

/** WebAuthn PRF for unlocking a legal organization's saved workspace.
 *
 * The passkey is used only as a local key source: its PRF output never leaves
 * this browser, is not stored and is not sent to VERA. No server verifies these
 * ceremonies, so the challenge is random and unused; possession of the passkey
 * (with user verification) is what produces the key. Browsers without PRF fall
 * back to a device passphrase or the key file. The key file stays the recovery
 * route: a lost or deleted passkey cannot be recovered through VERA.
 */
export class PasskeyUnavailableError extends Error {
  constructor(message = 'This browser or passkey cannot unlock a saved workspace. Choose another way to keep it on this device.') {
    super(message);
  }
}
// Public user-facing guidance, not a password or credential.
// nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_password
export const PASSKEY_CANCELLED = 'The passkey request was cancelled or timed out. Try again when you are ready.';

type PrfResults = { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };
type PrfCapable = {
  getClientCapabilities?: () => Promise<Record<string, boolean | undefined>>;
  signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
};

function base64url(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function bytes(value: ArrayBuffer | ArrayBufferView): Uint8Array {
  return value instanceof ArrayBuffer ? new Uint8Array(value.slice(0)) : new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
}
function prfOf(credential: Credential | null): PrfResults | undefined {
  const results = (credential as PublicKeyCredential | null)?.getClientExtensionResults?.() as { prf?: PrfResults } | undefined;
  return results?.prf;
}
function failure(error: unknown): Error {
  if (error instanceof PasskeyUnavailableError) return error;
  if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) return new Error(PASSKEY_CANCELLED);
  if (error instanceof DOMException && error.name === 'NotSupportedError') return new PasskeyUnavailableError();
  return new PasskeyUnavailableError('The passkey could not be used. Try again, or choose another way to keep this workspace on this device.');
}

/** 'supported' and 'unsupported' are definite; 'unknown' means try and handle failure. */
export async function passkeyPrfSupport(): Promise<'supported' | 'unsupported' | 'unknown'> {
  if (typeof window === 'undefined' || !window.isSecureContext || typeof PublicKeyCredential === 'undefined' ||
      !navigator.credentials?.create) return 'unsupported';
  const api = PublicKeyCredential as unknown as PrfCapable;
  try {
    if (api.getClientCapabilities) {
      const capabilities = await api.getClientCapabilities();
      if (capabilities['extension:prf'] === true) return 'supported';
      if (capabilities['extension:prf'] === false) return 'unsupported';
    }
  } catch { /* Fall through to trying. */ }
  return 'unknown';
}

/** Evaluate the PRF of an existing credential. Requires user verification. */
export async function evaluatePasskeyPrf(credentialId: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, signal?: AbortSignal): Promise<Uint8Array> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get({ signal, publicKey: {
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)), timeout: 120_000, userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    } });
  } catch (error) { throw failure(error); }
  const first = prfOf(credential)?.results?.first;
  if (!first) throw new PasskeyUnavailableError();
  const output = bytes(first);
  if (output.length !== 32) { output.fill(0); throw new PasskeyUnavailableError(); }
  return output;
}

/** Create a passkey for this site and return its PRF secret for `salt`.
 * Some authenticators return PRF output at creation; others need one more prompt. */
export async function createPasskeySecret(input: { organizationDomain: string; signal?: AbortSignal }): Promise<PasskeySecret> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let credential: PublicKeyCredential;
  try {
    const created = await navigator.credentials.create({ signal: input.signal, publicKey: {
      challenge: globalThis.crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'VERA legal portal' },
      // A random handle: nothing in the passkey identifies a person or a case.
      user: { id: globalThis.crypto.getRandomValues(new Uint8Array(16)), name: `VERA legal (${input.organizationDomain})`,
        displayName: `VERA legal (${input.organizationDomain})` },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
      timeout: 120_000, attestation: 'none',
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    } });
    if (!created) throw new PasskeyUnavailableError();
    credential = created as PublicKeyCredential;
  } catch (error) { throw failure(error); }
  const credentialId = new Uint8Array(credential.rawId.slice(0));
  const prf = prfOf(credential);
  try {
    if (!prf?.enabled && !prf?.results?.first) throw new PasskeyUnavailableError();
    const prfOutput = prf.results?.first ? bytes(prf.results.first) : await evaluatePasskeyPrf(credentialId, salt, input.signal);
    if (prfOutput.length !== 32) { prfOutput.fill(0); throw new PasskeyUnavailableError(); }
    return { credentialId, salt, prfOutput };
  } catch (error) {
    await forgetPasskey(credentialId);
    throw failure(error);
  }
}

/** Ask the browser to hide a passkey this site no longer uses (where supported).
 * The person may still need to delete it in their device or password manager. */
export async function forgetPasskey(credentialId: Uint8Array): Promise<void> {
  const api = typeof PublicKeyCredential === 'undefined' ? null : PublicKeyCredential as unknown as PrfCapable;
  try { await api?.signalUnknownCredential?.({ rpId: window.location.hostname, credentialId: base64url(credentialId) }); }
  catch { /* Best effort only. */ }
}
