/**
 * GAO FraudNet adapter (Tier A).
 *
 * GAO FraudNet accepts allegations of fraud, waste, abuse, and
 * mismanagement of federal funds by email. Allegations may be anonymous;
 * GAO's intake assigns a unique control number per allegation, which is
 * the receipt artifact the tracker records.
 */

import { EmailAdapter } from './emailAdapter';

export const gaoFraudnetAdapter = new EmailAdapter({
  entityId: 'gao-fraudnet',
  entityName: 'GAO FraudNet',
  intakeAddress: 'fraud@gao.gov',
  salutation: 'To the GAO FraudNet intake team,',
  bodyIntro:
    'Please find attached an anonymous whistleblower allegation concerning fraud, waste, ' +
    'abuse, or mismanagement, submitted through the Vera.Report platform with the ' +
    'reporter\'s explicit consent. The reporter has elected anonymous filing.',
  receiptPatterns: [
    { pattern: /control\s*(?:number|no\.?)[:#\s]*([A-Z0-9-]{4,})/i, type: 'control-number' },
  ],
});
