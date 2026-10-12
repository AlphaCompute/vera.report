import { PDFDocument, PDFArray, PDFRawStream, decodePDFRawStream } from 'pdf-lib';
import { parseSubmitterElection } from '../../../src/utils/submitterDisclosure';
import { encryptSubmitterDisclosure, packetSubmitterFor, submitterDisclosureUnchanged } from '../../../src/services/submitterDisclosure';
import type { ReportRecord } from '../../../src/services/reportPersistence';
import { buildDisseminationView } from '../../../src/services/dissemination/disseminationView';
import { packetGenerator } from '../../../src/services/dissemination/packetGenerator';

jest.mock('../../../src/services/evidenceStorage', () => ({ evidenceStorageService: { uploadEncryptedFile: jest.fn().mockResolvedValue({ originalCID: 'synthetic-packet' }) } }));
const input = { submitterMode: 'identified', submitterConsent: 'true', submitterName: 'Alex Example',
  submitterContactMethod: 'email', submitterContactValue: 'alex@example.invalid' };
const record = (): ReportRecord => ({ trackingId: 'VRA-0123456789ABCDEF', status: 'reviewing', createdAt: new Date(), updatedAt: new Date(),
  reward: { wantsReward: true, contactMethod: 'email', encryptedContactValue: 'private-reward-contact' } });

async function pdfText(bytes: Buffer): Promise<string> {
  const doc = await PDFDocument.load(bytes);
  const text: string[] = [];
  for (const page of doc.getPages()) {
    const contents = page.node.Contents();
    const streams = contents instanceof PDFArray ? contents.asArray() : contents ? [contents] : [];
    for (const ref of streams) {
      const stream = doc.context.lookup(ref, PDFRawStream);
      const operators = Buffer.from(decodePDFRawStream(stream).decode()).toString();
      for (const match of operators.matchAll(/<([a-f0-9]+)>\s*Tj/gi)) text.push(Buffer.from(match[1], 'hex').toString('latin1'));
    }
  }
  return text.join('\n');
}

beforeAll(() => { process.env.DISSEMINATION_WEBHOOK_SECRET = 'submitter-test-secret'; });

it.each([{}, { ...input, submitterMode: 'anonymous' }, { ...input, submitterMode: undefined }])('defaults to anonymity without an explicit identified election: %j', body => {
  expect(parseSubmitterElection(body)).toEqual({ mode: 'anonymous' });
});
it.each([
  { submitterConsent: undefined }, { submitterConsent: 'false' }, { submitterConsent: 'yes' },
  { submitterName: '' }, { submitterName: 'x'.repeat(121) }, { submitterName: 'Alex\nInjected' },
  { submitterContactMethod: 'invalid' }, { submitterContactValue: 'invalid-email' },
  { submitterContactMethod: 'phone', submitterContactValue: 'not-a-phone' },
])('rejects incomplete or unconsented recipient disclosure: %j', overrides => {
  expect(() => parseSubmitterElection({ ...input, ...overrides })).toThrow();
});
it.each([
  ['email', 'alex@example.invalid'], ['phone', '+1 202 555 0100'], ['encrypted', 'Signal: synthetic.123'],
])('round-trips a consented %s contact through real envelope encryption', async (method, value) => {
  const report = record();
  report.submitter = await encryptSubmitterDisclosure(parseSubmitterElection({ ...input, submitterContactMethod: method, submitterContactValue: value }), report.trackingId);
  expect(JSON.stringify(report.submitter)).not.toContain(value);
  expect(JSON.stringify(report.submitter)).not.toContain(input.submitterName);
  expect(await packetSubmitterFor(report)).toMatchObject({ mode: 'identified', name: input.submitterName, contact: { method, value } });
  const routing = JSON.stringify(buildDisseminationView(report, 'Reviewed narrative'));
  expect(routing).not.toContain(input.submitterName);
  expect(routing).not.toContain(value);
  expect(routing).not.toContain('submitter');
});
it('does not disclose a legacy/private reward contact or a revoked election', async () => {
  const report = record();
  expect(await packetSubmitterFor(report)).toEqual({ mode: 'anonymous' });
  report.submitter = await encryptSubmitterDisclosure(parseSubmitterElection(input), report.trackingId);
  if (report.submitter.mode !== 'identified') throw new Error('Test setup');
  report.submitter.consent.shareWithRecipients = false;
  expect(await packetSubmitterFor(report)).toEqual({ mode: 'anonymous' });
});
it('fails closed on swapped ciphertext, changed consent, and damaged ciphertext', async () => {
  const report = record();
  report.submitter = await encryptSubmitterDisclosure(parseSubmitterElection(input), report.trackingId);
  await expect(packetSubmitterFor({ ...report, trackingId: 'VRA-0000000000000000' })).rejects.toThrow('could not be read');
  if (report.submitter.mode !== 'identified') throw new Error('Test setup');
  const altered = structuredClone(report);
  if (altered.submitter?.mode !== 'identified') throw new Error('Test setup');
  altered.submitter.consent.capturedAt = new Date(0);
  await expect(packetSubmitterFor(altered)).rejects.toThrow('could not be read');
  report.submitter.ciphertext = 'damaged';
  await expect(packetSubmitterFor(report)).rejects.toThrow('could not be read');
});
it('renders the consented name/contact in the actual PDF and JSON, with matching transmittal wording', async () => {
  const report = record();
  report.submitter = await encryptSubmitterDisclosure(parseSubmitterElection(input), report.trackingId);
  const packet = await packetGenerator.generate(buildDisseminationView(report, 'Reviewed narrative'), 'secure-link', await packetSubmitterFor(report));
  const text = await pdfText(packet.pdf);
  expect(text).toContain('Alex Example');
  expect(text).toContain('alex@example.invalid');
  expect(text).toContain('identified submitter');
  expect(packet.sidecar.submitter).toMatchObject({ name: 'Alex Example', contact: { value: 'alex@example.invalid' } });
  expect(JSON.stringify(packet.sidecar)).not.toContain('private-reward-contact');
  expect(text).not.toContain('private-reward-contact');
});
it('labels anonymous packets without a direct contact or an assumed relay', async () => {
  const packet = await packetGenerator.generate(buildDisseminationView(record(), 'Reviewed narrative'), 'secure-link');
  const text = await pdfText(packet.pdf);
  expect(text).toContain('Anonymous');
  expect(text).toContain('has not consented');
  expect(text).not.toContain('alex@example.invalid');
  expect(text).not.toContain('relays messages');
  expect(packet.sidecar.submitter).toEqual({ mode: 'anonymous' });
});
it('detects an election change while a packet is being prepared', async () => {
  const before = record();
  before.submitter = await encryptSubmitterDisclosure(parseSubmitterElection(input), before.trackingId);
  expect(submitterDisclosureUnchanged(before, structuredClone(before))).toBe(true);
  expect(submitterDisclosureUnchanged(before, { ...before, submitter: { mode: 'anonymous' } })).toBe(false);
});

it('renders unsupported identity glyphs reversibly and retains exact Unicode in JSON', async () => {
  const report = record();
  const name = '王 Example';
  const contact = 'Signal: 😀 literal \\u{1F600}';
  report.submitter = await encryptSubmitterDisclosure(parseSubmitterElection({ ...input,
    submitterName: name, submitterContactMethod: 'encrypted', submitterContactValue: contact }), report.trackingId);
  const packet = await packetGenerator.generate(buildDisseminationView(report, 'Reviewed narrative'), 'secure-link', await packetSubmitterFor(report));
  expect(packet.sidecar.submitter).toMatchObject({ name, contact: { value: contact } });
  const text = await pdfText(packet.pdf);
  expect(text).toContain('Unicode escapes');
  expect(text).toContain('\\u{738B} Example');
  expect(text).toContain('\\u{1F600} literal \\u{5C}u{1F600}');
});
