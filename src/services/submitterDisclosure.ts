import crypto from 'node:crypto';
import { keyEnvelope } from './keyEnvelope';
import type { ReportRecord } from './reportPersistence';
import { parseSubmitterElection, SUBMITTER_CONSENT_VERSION, type SubmitterDetails, type SubmitterElection } from '../utils/submitterDisclosure';

interface DisclosureConsent {
  shareWithRecipients: boolean;
  capturedAt: Date;
  textVersion: string;
}

export type StoredSubmitterDisclosure = { mode: 'anonymous' } | {
  mode: 'identified';
  consent: DisclosureConsent;
  ciphertext: string;
  wrappedKey: string;
};

/** Only this allowlisted projection may enter a PDF/sidecar; never the routing view. */
export type PacketSubmitter = { mode: 'anonymous' } | {
  mode: 'identified';
  name: string;
  contact: { method: SubmitterDetails['contactMethod']; value: string };
  consent: { capturedAt: string; textVersion: string };
};

export async function encryptSubmitterDisclosure(election: SubmitterElection, trackingId: string): Promise<StoredSubmitterDisclosure> {
  if (election.mode === 'anonymous') return { mode: 'anonymous' };
  const consent = { shareWithRecipients: true, capturedAt: new Date(), textVersion: SUBMITTER_CONSENT_VERSION };
  const key = crypto.randomBytes(32);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(trackingId));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify({ ...election.details, consent }), 'utf8'), cipher.final()]);
    return {
      mode: 'identified', consent,
      ciphertext: `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ciphertext.toString('hex')}`,
      wrappedKey: await keyEnvelope.wrap(key.toString('hex'), { trackingId, purpose: 'submitter-disclosure' }),
    };
  } finally { key.fill(0); }
}

/** Called only after recipient authorization, immediately before packet generation. */
export async function packetSubmitterFor(report: ReportRecord): Promise<PacketSubmitter> {
  const stored = report.submitter;
  if (stored?.mode !== 'identified' || stored.consent?.shareWithRecipients !== true) return { mode: 'anonymous' };
  try {
    if (!stored.wrappedKey.startsWith('enc:')) throw new Error('Unwrapped submitter key');
    const key = Buffer.from(await keyEnvelope.unwrap(stored.wrappedKey, { trackingId: report.trackingId, purpose: 'submitter-disclosure' }), 'hex');
    let data: { name?: unknown; contactMethod?: unknown; contactValue?: unknown;
      consent?: { shareWithRecipients?: unknown; capturedAt?: unknown; textVersion?: unknown } };
    try {
      const [iv, tag, ciphertext] = stored.ciphertext.split(':');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'), { authTagLength: 16 });
      decipher.setAAD(Buffer.from(report.trackingId));
      decipher.setAuthTag(Buffer.from(tag, 'hex'));
      data = JSON.parse(Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]).toString('utf8'));
    } finally { key.fill(0); }
    const capturedAt = new Date(stored.consent.capturedAt).toISOString();
    if (data?.consent?.shareWithRecipients !== true || data.consent.capturedAt !== capturedAt ||
        data.consent.textVersion !== stored.consent.textVersion || stored.consent.textVersion !== SUBMITTER_CONSENT_VERSION) {
      throw new Error('Consent mismatch');
    }
    const parsed = parseSubmitterElection({
      submitterMode: 'identified', submitterConsent: true, submitterName: data.name,
      submitterContactMethod: data.contactMethod, submitterContactValue: data.contactValue,
    });
    if (parsed.mode !== 'identified') throw new Error('Invalid identity');
    return { mode: 'identified', name: parsed.details.name,
      contact: { method: parsed.details.contactMethod, value: parsed.details.contactValue },
      consent: { capturedAt, textVersion: stored.consent.textVersion } };
  } catch {
    // Never log identity-bearing plaintext or fall back to a private reward contact.
    throw new Error('Consented submitter details could not be read.');
  }
}

/** Refuse an already-rendered packet if the disclosure election changed while awaiting I/O. */
export function submitterDisclosureUnchanged(before: ReportRecord, after: ReportRecord): boolean {
  return JSON.stringify(before.submitter ?? null) === JSON.stringify(after.submitter ?? null);
}
