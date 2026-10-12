import { MAX_MEDIA_BYTES, MAX_DOCUMENT_BYTES, MAX_REPORT_EVIDENCE_BYTES } from './evidenceLimits';
import { MEDIA_FORMATS } from './mediaFormats';

/** Shared by the reporter UI and multer. Only formats with a supported
 * sanitization path are offered; MIME hints do not replace server validation. */
export const EVIDENCE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/tiff', 'application/pdf', 'text/csv', ...Object.keys(MEDIA_FORMATS)] as const;
// Some operating systems supply no MIME for MKV/Opus/M4A. Extensions are
// routing hints only: the server still parses and sanitizes every media file.
export const MEDIA_EXTENSION_TYPES: Readonly<Record<string, string>> = {
  mp3: 'audio/mpeg', wav: 'audio/wav', m4a: 'audio/mp4', aac: 'audio/aac',
  ogg: 'audio/ogg', oga: 'audio/ogg', opus: 'audio/opus', flac: 'audio/flac',
  mp4: 'video/mp4', m4v: 'video/mp4', mov: 'video/quicktime',
  webm: 'video/webm', mkv: 'video/x-matroska', avi: 'video/x-msvideo', ogv: 'video/ogg',
};
export const EVIDENCE_FILE_ACCEPT = [...EVIDENCE_MIME_TYPES, ...Object.keys(MEDIA_EXTENSION_TYPES).map(ext => `.${ext}`)].join(',');
export const EVIDENCE_FILE_TYPES_LABEL = 'JPEG, PNG, WebP, TIFF, PDF, CSV, MP3, WAV, M4A, AAC, MP4, MOV, Ogg, Opus, FLAC, WebM, MKV or AVI';
export const MAX_EVIDENCE_FILES = 5;
export const MAX_EVIDENCE_BYTES = MAX_MEDIA_BYTES;
export const EVIDENCE_SIZE_LABEL = 'Audio/video: up to 256 MiB each. Images/documents: up to 10 MiB each. Up to 256 MiB total per report.';
export function evidenceByteLimit(type: string): number {
  return Object.prototype.hasOwnProperty.call(MEDIA_FORMATS, type) ? MAX_MEDIA_BYTES : MAX_DOCUMENT_BYTES;
}
export function evidenceTotalError(files: Array<{ size: number }>): string | null {
  return files.reduce((total, file) => total + file.size, 0) > MAX_REPORT_EVIDENCE_BYTES
    ? 'Report attachments must total 256 MiB or less.' : null;
}
export const ALLOWED_EVIDENCE_MIME_TYPES: ReadonlySet<string> = new Set(EVIDENCE_MIME_TYPES);

export function resolveEvidenceMimeType(type: string, name = ''): string {
  if (type === '' || type === 'application/octet-stream') {
    const extension = name.split('.').pop()?.toLowerCase() || '';
    return Object.prototype.hasOwnProperty.call(MEDIA_EXTENSION_TYPES, extension) ? MEDIA_EXTENSION_TYPES[extension] : type;
  }
  return type;
}

export function evidenceFileError(file: { type: string; size: number; name?: string }): string | null {
  if (!ALLOWED_EVIDENCE_MIME_TYPES.has(resolveEvidenceMimeType(file.type, file.name))) return `Choose ${EVIDENCE_FILE_TYPES_LABEL}. This file type is not supported.`;
  const limit = evidenceByteLimit(resolveEvidenceMimeType(file.type, file.name));
  if (file.size > limit) return `Each file of this type must be ${limit / 1024 / 1024} MiB or smaller.`;
  return null;
}
