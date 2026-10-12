import { PDFDocument } from 'pdf-lib';
import { sanitizeDocument } from '../../../src/services/documentSanitizer';

it('rebuilds PDF pages while removing metadata, attachments and trailing history', async () => {
  const pdf = await PDFDocument.create();
  pdf.setAuthor('PRIVATE-AUTHOR-CANARY');
  pdf.setSubject('PRIVATE-SUBJECT-CANARY');
  pdf.addPage([200, 100]).drawText('Visible evidence', { x: 10, y: 50, size: 12 });
  await pdf.attach(Buffer.from('PRIVATE-ATTACHMENT-CANARY'), 'secret.txt');
  const input = Buffer.concat([Buffer.from(await pdf.save()), Buffer.from('\nPRIVATE-HISTORY-CANARY')]);
  const clean = await sanitizeDocument(input, 'application/pdf');
  const rebuilt = await PDFDocument.load(clean);
  expect(rebuilt.getPageCount()).toBe(1);
  expect(rebuilt.getAuthor()).toBeUndefined();
  expect(rebuilt.getSubject()).toBeUndefined();
  expect(clean.toString()).not.toContain('CANARY');
  expect(rebuilt.catalog.toString()).not.toMatch(/Names|AcroForm|Metadata|OpenAction/);
  // Output contains only a rendered image on the page, no copied source objects.
  expect(rebuilt.getPages()[0].node.Resources()?.toString()).toContain('Image');
});

it('rejects malformed and oversized documents', async () => {
  await expect(sanitizeDocument(Buffer.from('%PDF-invalid'), 'application/pdf')).rejects.toThrow('safely sanitized');
  await expect(sanitizeDocument(Buffer.alloc(11 * 1024 * 1024), 'application/pdf')).rejects.toThrow('limit');
});

it('rejects excessive page counts', async () => {
  const pdf = await PDFDocument.create();
  for (let n = 0; n < 11; n++) pdf.addPage([100, 100]);
  await expect(sanitizeDocument(Buffer.from(await pdf.save()), 'application/pdf')).rejects.toThrow('safely sanitized');
});

it('does not let a partial selection bypass document reconstruction', async () => {
  const { EvidenceEncryptionService } = await import('../../../src/services/evidenceEncryption');
  const pdf = await PDFDocument.create();
  pdf.addPage();
  pdf.setAuthor('PRIVATE-SELECTION-CANARY');
  const output = await new EvidenceEncryptionService().stripFileMetadata(Buffer.from(await pdf.save()), 'application/pdf', { unrelated_field: true });
  expect((await PDFDocument.load(output)).getAuthor()).toBeUndefined();
});
