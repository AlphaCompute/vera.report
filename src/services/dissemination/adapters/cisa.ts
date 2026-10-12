/**
 * CISA incident reporting adapter (Tier A).
 *
 * CISA accepts incident reports by email to its published intake address.
 * Their guidance asks filers to refrain from including PII unless
 * necessary — which aligns with Vera's identity-free packet design.
 * Inbound acknowledgments carry a CISA incident ID.
 *
 * CISA's guidelines also accept STIX submissions, so cyber-category reports
 * carry a STIX 2.1 bundle as a third attachment — machine-readable threat
 * intel alongside the human-readable dossier.
 */

import { EmailAdapter } from './emailAdapter';
import { stixEmitter } from '../stixEmitter';

export const cisaAdapter = new EmailAdapter({
  entityId: 'cisa',
  entityName: 'CISA Incident Reporting',
  intakeAddress: 'contact@mail.cisa.dhs.gov',
  salutation: 'To the CISA incident reporting team,',
  bodyIntro:
    'Please find attached an anonymous whistleblower report concerning a cyber security ' +
    'incident, submitted through the Vera.Report platform with the reporter\'s explicit ' +
    'consent. In line with CISA guidance, this submission contains no personally ' +
    'identifiable information about the reporter. A STIX 2.1 bundle is attached for ' +
    'machine ingestion where the report is cyber-categorized.',
  receiptPatterns: [
    { pattern: /incident\s*(?:id|number)[:#\s]*([A-Z0-9-]{6,})/i, type: 'incident-id' },
  ],
  extraAttachments: (view) => {
    if (!stixEmitter.applicable(view, 'cisa')) return [];
    const bundle = stixEmitter.emit(view);
    return [
      {
        filename: `vera-stix-${view.trackingId}.json`,
        contentType: 'application/json',
        content: Buffer.from(JSON.stringify(bundle, null, 2)),
      },
    ];
  },
});
