/** A deterministic file-structure rejection, never a crypto/storage outage. */
export class EvidenceValidationError extends Error {
  constructor(
    format: 'PNG' | 'JPEG' | 'WebP' | 'PDF' | 'TIFF' | 'media' = 'PNG',
    message = `The ${format} file is malformed or unsupported. Remove it or choose a valid ${format} file.`,
  ) {
    super(message);
    this.name = 'EvidenceValidationError';
  }
}
