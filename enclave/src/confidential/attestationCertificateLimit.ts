/** Real Nitro certificates are 533-792 bytes (fixture nsm-channel-indefinite-20260915).
 * The cap is per certificate; the 16 KiB document and 10-entry cabundle bounds
 * already limit total memory, so this only guards against an absurd single entry
 * and leaves room for AWS to grow its certificate profile. */
export const MAX_ATTESTATION_CERTIFICATE_BYTES = 4096;
/** Distinct from a chain or signature failure so an oversized AWS certificate is
 * diagnosable from the error alone. The message carries no certificate data. */
export class AttestationCertificateSizeError extends Error {
  constructor() { super('Attestation certificate exceeds the size limit'); this.name = 'AttestationCertificateSizeError'; }
}
