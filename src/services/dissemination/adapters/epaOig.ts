/**
 * EPA Office of Inspector General adapter (Tier A).
 *
 * EPA OIG accepts complaints by email to its hotline. Anonymous
 * complaints are accepted; acknowledgment is not guaranteed, so the SLA
 * profile for this entity converts the 7-day ack timer into a follow-up
 * task rather than an alert (PDR §14).
 */

import { EmailAdapter } from './emailAdapter';

export const epaOigAdapter = new EmailAdapter({
  entityId: 'epa-oig',
  entityName: 'EPA Office of Inspector General',
  intakeAddress: 'OIG.Hotline@epa.gov',
  salutation: 'To the EPA OIG Hotline,',
  bodyIntro:
    'Please find attached an anonymous whistleblower complaint concerning environmental ' +
    'or climate-related conduct, submitted through the Vera.Report platform with the ' +
    'reporter\'s explicit consent. The reporter has elected anonymous filing.',
  receiptPatterns: [
    { pattern: /case\s*(?:number|no\.?|id)[:#\s]*([A-Z0-9-]{4,})/i, type: 'control-number' },
  ],
});
