import { CONFIDENTIAL_EVIDENCE_LIMIT, CONFIDENTIAL_EVIDENCE_UPLOAD_LIMIT } from './config';
import { ALLOWED_EVIDENCE_MIME_TYPES, EVIDENCE_FILE_TYPES_LABEL, resolveEvidenceMimeType } from '../../src/utils/evidenceFiles';

/** Evidence limits for confidential reports. Files are encrypted on the
 * reporter's device in 512 KB chunks (the chunked case-object format), read from
 * disk a chunk at a time, so a phone never holds a whole file in memory. The
 * same limits apply to the first submission and to each later "add files" step.
 * VERA cannot inspect or clean these files, so the accepted types stay the
 * familiar document, image and media formats. */
export const CONFIDENTIAL_MAX_FILES = 10;
/** 256 MB (decimal) is below the 256 MiB byte limit, so the stated limit is never generous. */
export const CONFIDENTIAL_FILE_LIMIT_LABEL = '256 MB';
export const CONFIDENTIAL_EVIDENCE_TOTAL_LIMIT = CONFIDENTIAL_EVIDENCE_UPLOAD_LIMIT;
export const CONFIDENTIAL_EVIDENCE_LIMIT_TEXT =
  `Up to ${CONFIDENTIAL_MAX_FILES} files, ${CONFIDENTIAL_FILE_LIMIT_LABEL} in total. Large files upload in parts, and an interrupted upload can resume.`;

/** Why this one file cannot be attached, or null. */
export function confidentialFileError(file: { name: string; type: string; size: number }): string | null {
  if (!ALLOWED_EVIDENCE_MIME_TYPES.has(resolveEvidenceMimeType(file.type, file.name))) {
    return `Choose ${EVIDENCE_FILE_TYPES_LABEL}. This file type is not supported.`;
  }
  if (file.size === 0) return 'This file is empty.';
  if (file.size > CONFIDENTIAL_EVIDENCE_LIMIT) return `This file is larger than ${CONFIDENTIAL_FILE_LIMIT_LABEL}.`;
  return null;
}

/** Why the whole selection cannot be attached, or null. */
export function confidentialSelectionError(files: { size: number }[]): string | null {
  if (files.length > CONFIDENTIAL_MAX_FILES) return `You can attach up to ${CONFIDENTIAL_MAX_FILES} files at a time.`;
  if (files.reduce((total, file) => total + file.size, 0) > CONFIDENTIAL_EVIDENCE_TOTAL_LIMIT) {
    return `Files must total ${CONFIDENTIAL_FILE_LIMIT_LABEL} or less. Remove a file, or add the rest later from your report page.`;
  }
  return null;
}

/** Splits a new selection into accepted files and plain-language problems. */
export function checkConfidentialSelection(existing: readonly { size: number }[], chosen: readonly File[]):
  { accepted: File[]; problems: string[] } {
  const problems: string[] = [];
  const valid = chosen.filter(file => {
    const error = confidentialFileError(file);
    if (error) problems.push(`${file.name}: ${error}`);
    return !error;
  });
  const selection = confidentialSelectionError([...existing, ...valid]);
  if (selection) return { accepted: [], problems: [...problems, selection] };
  return { accepted: valid, problems };
}

/** Human-readable size for evidence lists and progress. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  const megabytes = bytes / (1024 * 1024);
  return `${megabytes < 10 ? megabytes.toFixed(1) : Math.round(megabytes)} MB`;
}
export type TransferProgress = { bytesDone: number; bytesTotal: number };
export function percent(progress: TransferProgress): number {
  return progress.bytesTotal > 0 ? Math.min(100, Math.floor(progress.bytesDone / progress.bytesTotal * 100)) : 0;
}
/** "Uploading encrypted files: 42% (108 MB of 256 MB)" style status text. */
export function progressText(action: string, progress: TransferProgress): string {
  return `${action}: ${percent(progress)}% (${formatBytes(progress.bytesDone)} of ${formatBytes(progress.bytesTotal)})`;
}
