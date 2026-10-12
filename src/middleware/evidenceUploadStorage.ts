import { recordUploadProgress } from './uploadBudget';
import type { Request } from 'express';
import multer from 'multer';
import { Writable, pipeline } from 'node:stream';
import { evidenceByteLimit } from '../utils/evidenceFiles';
import { MAX_REPORT_EVIDENCE_BYTES } from '../utils/evidenceLimits';

const totals = new WeakMap<Request, number>();
/** Enforce the aggregate limit while reading, before multer can retain five large files. */
export const evidenceUploadStorage: multer.StorageEngine = {
  _handleFile(req, file, callback) {
    let chunks: Buffer[] = [];
    let size = 0;
    const sink = new Writable({
      write(chunk: Buffer, _encoding, done) {
        recordUploadProgress(req, chunk);
        size += chunk.length;
        const total = (totals.get(req) || 0) + chunk.length;
        totals.set(req, total);
        if (size > evidenceByteLimit(file.mimetype) || total > MAX_REPORT_EVIDENCE_BYTES) {
          chunks = [];
          done(new multer.MulterError('LIMIT_FILE_SIZE', file.fieldname));
        } else { chunks.push(chunk); done(); }
      },
    });
    pipeline(file.stream, sink, error => {
      if (error) { chunks = []; callback(error); return; }
      const buffer = Buffer.concat(chunks, size);
      chunks = [];
      callback(null, { buffer, size });
    });
  },
  _removeFile(_req, file, callback) {
    file.buffer = Buffer.alloc(0);
    callback(null);
  },
};
