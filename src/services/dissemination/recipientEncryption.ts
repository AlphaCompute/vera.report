import { createMessage, encrypt, readKey } from 'openpgp';
import { DispatchNotSentError } from './types';

// Every failure here happens before the outbound transport is called, so it is
// a DispatchNotSentError: the dispatch worker must retry it as a clean failure,
// never dead-letter it as an uncertain delivery.

function loadPolicies(): Record<string, unknown> {
  const raw = process.env.DISSEMINATION_EMAIL_POLICIES;
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new DispatchNotSentError('Invalid dissemination email encryption policy');
  }
}

function policyFor(recipient: string): { address: string; value: unknown } {
  const policies = loadPolicies();
  const address = recipient.trim().toLowerCase();
  const value = Object.prototype.hasOwnProperty.call(policies, address) ? policies[address] : undefined;
  return { address, value };
}

/** A documented no-key exception: no key fields, explicit opt-in, and a reason. */
function isPlaintextException(value: unknown): value is { allowUnencrypted: true; reason: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const policy = value as Record<string, unknown>;
  return policy.publicKey === undefined && policy.fingerprint === undefined &&
    policy.allowUnencrypted === true && typeof policy.reason === 'string' && !!policy.reason.trim();
}

/**
 * True when the recipient has a policy that requires encryption (a pinned key,
 * or a malformed entry that encryptForRecipient will refuse). False when there
 * is no policy or only a plaintext exception. Dryrun uses this to decide
 * whether report content may be sent at all.
 */
export function recipientRequiresEncryption(recipient: string): boolean {
  const { value } = policyFor(recipient);
  return value !== undefined && !isPlaintextException(value);
}

/** Encrypt before handing a payload to the outbound transport. Keys are pinned,
 * never discovered from report content, redirects, or an untrusted key server. */
export async function encryptForRecipient(
  recipient: string,
  payload: Uint8Array,
  live: boolean,
  auditException?: (exception: { recipient: string; reason: string }) => Promise<void>,
): Promise<string | null> {
  const { address, value } = policyFor(recipient);
  if (value === undefined && !live) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DispatchNotSentError('Recipient encryption policy is required for live email');
  }
  const policy = value as Record<string, unknown>;
  // A no-key channel needs a specific, documented exception. A broken key can
  // never fall back to plaintext, even if an exception is accidentally present.
  if (isPlaintextException(policy)) {
    if (live) {
      if (!auditException) throw new DispatchNotSentError('A live plaintext exception requires an audit record');
      await auditException({ recipient: address, reason: policy.reason.trim() });
    }
    return null;
  }
  if (typeof policy.publicKey !== 'string' || typeof policy.fingerprint !== 'string') {
    throw new DispatchNotSentError('Recipient public key and fingerprint are required');
  }
  const fingerprint = policy.fingerprint.replace(/\s/g, '').toLowerCase();
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(fingerprint)) throw new DispatchNotSentError('Invalid recipient key fingerprint');
  try {
    const key = await readKey({ armoredKey: policy.publicKey });
    if (key.isPrivate() || key.getFingerprint().toLowerCase() !== fingerprint) {
      throw new Error('Key does not match pinned public fingerprint');
    }
    // OpenPGP verifies key validity (including expiry/revocation) when selecting
    // the encryption subkey. Any error propagates as a retryable dispatch failure.
    return await encrypt({ message: await createMessage({ binary: payload }), encryptionKeys: key, format: 'armored' });
  } catch {
    throw new DispatchNotSentError('Recipient encryption failed; no plaintext email was sent');
  }
}
