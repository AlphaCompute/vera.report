/**
 * Attested secret bootstrap is not implemented yet. Fail closed instead of
 * fabricating PCR measurements or accepting plaintext from the parent proxy.
 *
 * The replacement must obtain an NSM-signed document binding a fresh recipient
 * public key, authenticate the KMS request, and unwrap CiphertextForRecipient
 * exclusively inside the enclave. See docs/security/ARCHITECTURE-REVIEW-2026-09-11.md.
 */
const UNAVAILABLE = 'Nitro attestation unavailable: recipient-key binding and decryption are not implemented';

export async function getSecret(secretId: string): Promise<Buffer> {
  const kmsKeyId = process.env[`KMS_KEY_${secretId.toUpperCase()}`];
  const ciphertextB64 = process.env[`SECRET_${secretId.toUpperCase()}`];
  if (!kmsKeyId || !ciphertextB64) {
    throw new Error(`Secret configuration not found for: ${secretId}`);
  }
  // Never contact a host HTTP service that returns raw plaintext, and never
  // treat configuration or the presence of /dev/nsm as successful attestation.
  throw new Error(UNAVAILABLE);
}

/** No bootstrap secrets are cached until a verified recipient flow exists. */
export function clearSecrets(): void {}
