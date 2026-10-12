import { recipientCaseReference } from './recipientCapability';
/**
 * Printable filing-form PDF (Phase 2c, Option B3 paper fallback).
 *
 * Renders the portal companion as a print-ready document: for SEC/CFTC
 * this is the hard-copy TCR counsel needs for the reporter's Rule 21F-9
 * signature; for IRS Form 211 it is the (mail-only) filing itself. Built
 * from the identity-free TCR model — identity sections are printed as
 * explicit "completed by counsel" placeholders.
 */

import { PDFDocument, StandardFonts } from 'pdf-lib';
import { PdfWriter } from './packetGenerator';
import { PORTAL_PROFILES, renderCompanionFields } from './tcrModel';
import type { DisseminationView } from './types';

export async function renderCompanionPdf(view: DisseminationView, entityId: string): Promise<Buffer> {
  view = { ...view, trackingId: recipientCaseReference(view.trackingId, entityId) };
  const profile = PORTAL_PROFILES[entityId];
  if (!profile) throw new Error(`No portal profile for entity ${entityId}`);
  const fields = renderCompanionFields(view, entityId);

  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const mono = await doc.embedFont(StandardFonts.Courier);
  const writer = new PdfWriter(doc, font, bold, mono);

  writer.title(profile.formName);
  writer.subtitle(`Pre-filled filing companion — Vera.Report ${view.trackingId}`);
  writer.spacer(6);

  writer.kv('Portal', profile.portalUrl);
  writer.kv('Tracking ID', view.trackingId);
  writer.spacer(4);

  writer.heading('Filing Notes');
  for (const note of profile.filingNotes) {
    writer.paragraph(`• ${note}`);
  }

  let currentSection = '';
  for (const f of fields) {
    if (f.section !== currentSection) {
      currentSection = f.section;
      writer.heading(f.section);
    }
    writer.kv(f.question, '');
    writer.paragraph(f.answer, true);
  }

  writer.heading('Transmittal');
  writer.paragraph(
    'Prepared by Vera.Report from reporter-authored content with the reporter\'s explicit ' +
      'consent. Contains no reporter identity: identity and signature sections are completed ' +
      'by counsel with the reporter directly, outside Vera.Report.',
  );

  writer.footerAllPages(`Vera.Report filing companion ${view.trackingId} — ${profile.entityName}`);
  return Buffer.from(await doc.save());
}
