import { createDeflate } from 'node:zlib';

export async function pdfExpansionFixture(megabytes: number, streams = 1, objectStream = false): Promise<Buffer> {
  const deflater = createDeflate();
  const chunks: Buffer[] = [];
  deflater.on('data', chunk => chunks.push(chunk));
  const finished = new Promise<void>((resolve, reject) => { deflater.on('end', resolve); deflater.on('error', reject); });
  const whitespace = Buffer.alloc(1024 * 1024, 32);
  for (let index = 0; index < megabytes; index++) {
    if (!deflater.write(whitespace)) await new Promise<void>(resolve => deflater.once('drain', resolve));
  }
  deflater.end(); await finished;
  const encoded = Buffer.concat(chunks);
  const objects = [Buffer.from('<< /Type /Catalog /Pages 2 0 R >>'), Buffer.from('<< /Type /Pages /Kids [3 0 R] /Count 1 >>'), Buffer.from(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents [${Array.from({length: streams}, (_, i) => `${i + 4} 0 R`).join(' ')}] >>`)];
  for (let i = 0; i < streams; i++) objects.push(Buffer.concat([Buffer.from(`<< /Length ${encoded.length} /Filter /FlateDecode ${objectStream ? '/Type /ObjStm /N 1 /First 4' : ''} >>\nstream\n`), encoded, Buffer.from('\nendstream')]));
  const parts = [Buffer.from('%PDF-1.7\n')]; const offsets = [0]; let length = parts[0].length;
  objects.forEach((object, i) => { offsets.push(length); const part = Buffer.concat([Buffer.from(`${i + 1} 0 obj\n`), object, Buffer.from('\nendobj\n')]); parts.push(part); length += part.length; });
  parts.push(Buffer.from(`xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map(offset => `${String(offset).padStart(10, '0')} 00000 n \n`).join('')}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${length}\n%%EOF\n`));
  return Buffer.concat(parts);
}
