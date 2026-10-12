import multer from 'multer';
import { evidenceUploadStorage } from './evidenceUploadStorage';
import { resolveEvidenceMimeType, ALLOWED_EVIDENCE_MIME_TYPES, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_FILES, EVIDENCE_FILE_TYPES_LABEL } from '../utils/evidenceFiles';

// Enforce per-format and aggregate evidence budgets while receiving multipart.
export const evidenceUpload = multer({
  storage: evidenceUploadStorage,
  limits: {
    // Busboy emits LIMIT at equality; the storage reader enforces the inclusive cap.
    fileSize: MAX_EVIDENCE_BYTES + 1,
    files: MAX_EVIDENCE_FILES,
    fields: 32,
    fieldSize: 1024 * 1024,
    parts: MAX_EVIDENCE_FILES + 32
  },
  fileFilter: (_req, file, cb) => {
    file.mimetype = resolveEvidenceMimeType(file.mimetype, file.originalname);
    if (ALLOWED_EVIDENCE_MIME_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed: ${file.mimetype}. Accepted types: ${EVIDENCE_FILE_TYPES_LABEL}.`));
    }
  }
});

