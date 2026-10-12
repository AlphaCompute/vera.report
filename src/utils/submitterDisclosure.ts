/** Browser-safe, explicit election for identity disclosed in recipient packets. */
export const SUBMITTER_CONSENT_VERSION = 'submitter-disclosure-v1';
export const SUBMITTER_CONSENT_TEXT =
  'I consent to include my name and contact details in report packets shared with authorized recipients, who may contact me directly. This is separate from private reward follow-up and does not authorize sending my report.';

export interface SubmitterDetails {
  name: string;
  contactMethod: 'email' | 'phone' | 'encrypted' | 'multiple';
  contactValue: string;
}

export type SubmitterElection = { mode: 'anonymous' } | { mode: 'identified'; details: SubmitterDetails };

export interface SubmitterDisclosureInput {
  submitterMode: 'anonymous' | 'identified';
  submitterName: string;
  submitterContactMethod: SubmitterDetails['contactMethod'];
  submitterContactValue: string;
  submitterConsent: boolean;
}

export const EMPTY_SUBMITTER_DISCLOSURE: SubmitterDisclosureInput = {
  submitterMode: 'anonymous', submitterName: '', submitterContactMethod: 'email',
  submitterContactValue: '', submitterConsent: false,
};

/** Legacy clients and anonymous elections never authorize disclosure. */
export function parseSubmitterElection(body: Record<string, unknown>): SubmitterElection {
  if (body.submitterMode === undefined || body.submitterMode === 'anonymous') return { mode: 'anonymous' };
  if (body.submitterMode !== 'identified') throw new Error('Choose anonymous or identified submission.');
  if (body.submitterConsent !== true && body.submitterConsent !== 'true') {
    throw new Error('Consent is required to include your name and contact details in recipient packets.');
  }
  const text = (value: unknown, limit: number): string | null =>
    typeof value === 'string' && value.trim().length > 0 && value.trim().length <= limit && !/[\u0000-\u001f\u007f]/.test(value)
      ? value.trim() : null;
  const name = text(body.submitterName, 120);
  if (!name) throw new Error('Enter a submitter name of 1 to 120 characters.');
  const contactMethod = body.submitterContactMethod;
  if (contactMethod !== 'email' && contactMethod !== 'phone' && contactMethod !== 'encrypted' && contactMethod !== 'multiple') {
    throw new Error('Choose email, phone, or a secure contact method.');
  }
  const limit = contactMethod === 'multiple' ? 1000 : 500;
  const contactValue = text(body.submitterContactValue, limit);
  if (!contactValue) throw new Error(`Enter contact details of 1 to ${limit} characters.`);
  if (contactMethod === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactValue)) {
    throw new Error('Enter a valid submitter email address.');
  }
  if (contactMethod === 'phone' && !/^\+?[\d\s\-().]{7,20}$/.test(contactValue)) {
    throw new Error('Enter a valid submitter phone number.');
  }
  return { mode: 'identified', details: { name, contactMethod, contactValue } };
}
