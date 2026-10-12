import express from 'express';
import multer from 'multer';
import request from 'supertest';
jest.mock('../../../src/utils/evidenceLimits', () => ({ MAX_MEDIA_BYTES: 8192, MAX_DOCUMENT_BYTES: 4096, MAX_REPORT_EVIDENCE_BYTES: 8192 }));
import { evidenceUpload } from '../../../src/middleware/evidenceUpload';

function app() {
  const server = express();
  server.post('/upload', evidenceUpload.array('files', 5), (req, res) => {
    res.json((req.files as Express.Multer.File[]).map(file => file.size));
  });
  server.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => { res.status(413).json({ error: err.message }); });
  return server;
}
it('enforces the report total during multipart reads, not after five full buffers', async () => {
  const result = await request(app()).post('/upload')
    .attach('files', Buffer.alloc(5000), { filename: 'one.mp4', contentType: 'video/mp4' })
    .attach('files', Buffer.alloc(5000), { filename: 'two.mp4', contentType: 'video/mp4' });
  expect(result.status).toBe(413);
});
it('accepts media at the budget and isolates the next request budget', async () => {
  const server = app();
  for (let i = 0; i < 2; i++) {
    const result = await request(server).post('/upload').attach('files', Buffer.alloc(8192), { filename: 'video.mp4', contentType: 'video/mp4' });
    expect(result.status).toBe(200); expect(result.body).toEqual([8192]);
  }
});
it('keeps the lower document cap even with a higher multipart file limit', async () => {
  const result = await request(app()).post('/upload').attach('files', Buffer.alloc(4097), { filename: 'doc.pdf', contentType: 'application/pdf' });
  expect(result.status).toBe(413);
});

it('rejects a media file one byte above the inclusive limit', async () => {
  const result = await request(app()).post('/upload').attach('files', Buffer.alloc(8193), { filename: 'video.mp4', contentType: 'video/mp4' });
  expect(result.status).toBe(413);
});
