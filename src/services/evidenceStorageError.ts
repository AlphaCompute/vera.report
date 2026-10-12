/** Fixed operational codes only: never return provider errors or file details to callers. */
export class EvidenceStorageError extends Error {
  constructor(public readonly code: 'evidence_encryption_unavailable' | 'evidence_upload_unavailable' |
    'evidence_upload_auth_unavailable' | 'evidence_upload_quota_exceeded' | 'evidence_key_write_unavailable', cause?: unknown) {
    super(cause instanceof Error ? cause.message : 'Failed to store encrypted evidence');
    this.name = 'EvidenceStorageError';
  }
}
