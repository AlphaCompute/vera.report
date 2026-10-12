import { evidenceByteLimit, evidenceTotalError, MEDIA_EXTENSION_TYPES, resolveEvidenceMimeType, evidenceFileError, EVIDENCE_FILE_ACCEPT, EVIDENCE_MIME_TYPES, MAX_EVIDENCE_BYTES } from '../../../src/utils/evidenceFiles';

describe('evidence file selection', () => {
  it.each(EVIDENCE_MIME_TYPES)('accepts the supported %s type at the size limit', type => {
    expect(evidenceFileError({ type, size: evidenceByteLimit(type) })).toBeNull();
    expect(EVIDENCE_FILE_ACCEPT.split(',')).toContain(type);
  });
  it.each(['audio/unknown', 'video/unknown', 'application/msword', 'application/octet-stream', ''])('rejects unsupported %s before the submission flow', type => {
    expect(evidenceFileError({ type, size: 100 })).toMatch(/not supported/);
  });
  it.each(Object.entries(MEDIA_EXTENSION_TYPES))('routes an untyped .%s upload through its sanitizer', (extension, mime) => {
    expect(resolveEvidenceMimeType('application/octet-stream', `RECORDING.${extension.toUpperCase()}`)).toBe(mime);
    expect(evidenceFileError({ type: '', name: `recording.${extension}`, size: 100 })).toBeNull();
    expect(EVIDENCE_FILE_ACCEPT.split(',')).toContain(`.${extension}`);
  });
  it('does not override an explicit unsupported MIME or unknown extension', () => {
    expect(evidenceFileError({ type: 'text/html', name: 'recording.mp4', size: 100 })).toMatch(/not supported/);
    expect(evidenceFileError({ type: '', name: 'recording.exe', size: 100 })).toMatch(/not supported/);
  });
  it('allows large video but keeps document and aggregate budgets bounded', () => {
    expect(evidenceFileError({ type: 'video/mp4', size: MAX_EVIDENCE_BYTES })).toBeNull();
    expect(evidenceFileError({ type: 'video/mp4', size: MAX_EVIDENCE_BYTES + 1 })).toMatch(/256 MiB/);
    expect(evidenceTotalError([{ size: MAX_EVIDENCE_BYTES }, { size: 1 }])).toMatch(/total/);
  });
  it('rejects oversized evidence', () => {
    expect(evidenceFileError({ type: 'image/png', size: MAX_EVIDENCE_BYTES + 1 })).toMatch(/10 MiB/);
  });
});
