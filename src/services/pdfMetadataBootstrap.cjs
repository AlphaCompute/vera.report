// This guard is private to the disposable parsing worker. Worker heap limits
// do not cover typed-array backing stores allocated by compressed PDF streams.
const { default: DecodeStream } = require('pdf-lib/cjs/core/streams/DecodeStream');
const version = require('pdf-lib/package.json').version;
if (version !== '1.17.1') throw new Error('PDF decoder allocation contract requires review');
const ensureBuffer = DecodeStream.prototype.ensureBuffer;
const STREAM_LIMIT = 8 * 1024 * 1024;
const ALLOCATION_LIMIT = 32 * 1024 * 1024;
let allocated = 0;
DecodeStream.prototype.ensureBuffer = function (requested) {
  if (!Number.isSafeInteger(requested) || requested < 0 || requested > STREAM_LIMIT) {
    throw new Error('PDF decoded stream exceeds allocation limit');
  }
  if (requested > this.buffer.byteLength) {
    let size = this.minBufferLength;
    if (!Number.isSafeInteger(size) || size <= 0) throw new Error('Invalid PDF decoder buffer');
    while (size < requested) size *= 2;
    if (size > STREAM_LIMIT || allocated + size > ALLOCATION_LIMIT) {
      throw new Error('PDF decoded streams exceed allocation budget');
    }
    // Charge the entire new allocation, including replaced buffers. Do not
    // assume GC has freed earlier streams or earlier growth allocations.
    allocated += size;
  }
  return ensureBuffer.call(this, requested);
};
require('./pdfMetadataWorker.cjs');
