/**
 * AI redaction pass (VERA-PDR-001 §7.2 / FR-4).
 *
 * Before a narrative leaves the platform in a packet, an admin can run an
 * AI pass that proposes a redacted version: self-identifying details the
 * reporter left in the text ("as the only woman on the night shift…",
 * names, employee IDs, exact dates that fingerprint one person) are
 * replaced with neutral placeholders. The proposal is exactly that — a
 * proposal. Nothing changes until an admin reviews and accepts it, at
 * which point it is frozen onto the disposition as `narrativeOverride`
 * and every packet generated afterwards uses it instead of the raw text.
 *
 * The raw narrative itself never leaves the platform: it stays encrypted at rest,
 * and this service only sends it to Venice AI (already trusted with it at
 * verification time) — never to agencies.
 */

import axios from 'axios';
import { disseminationPersistence } from './disseminationPersistence';
import { disseminationService } from './disseminationService';

const VENICE_API_URL = 'https://api.venice.ai/api/v1/chat/completions';

export interface RedactionProposal {
  /** The proposed redacted narrative. */
  redacted: string;
  /** Human-readable notes on what was changed and why. */
  notes: string[];
  /** True when the model found nothing to redact. */
  clean: boolean;
}

const SYSTEM_PROMPT = `You are a redaction assistant for a whistleblower platform. The text below will be transmitted to a government agency. Your ONLY job is to remove details that could identify the ANONYMOUS REPORTER — not the wrongdoing, and not the organization or officials being reported.

Redact (replace with neutral bracketed placeholders like [ROLE], [DATE], [NAME]):
- The reporter's own name, job title, team, tenure, or anything phrased in first person that narrows who they are (e.g. "as the only engineer hired last March")
- Names of the reporter's close colleagues, family, or friends when identifying them identifies the reporter
- Employee IDs, badge numbers, email addresses, phone numbers belonging to the reporter
- Hyper-specific details that only one person could know AND that are not needed to describe the wrongdoing

Do NOT redact:
- The organization being reported, its executives, or the people committing the wrongdoing
- Facts describing the misconduct itself (amounts, dates of the misconduct, locations, methods)
- Anything already public

Preserve the original wording everywhere else. Do not summarize, do not rephrase, do not editorialize.

Respond with ONLY valid JSON in this exact format, no other text:
{
  "redacted": "the full narrative with redactions applied",
  "notes": ["what was changed and why", "..."],
  "clean": true/false
}
Set "clean" to true and return the narrative unchanged when there is nothing to redact.`;

class RedactionService {
  /** Ask Venice AI for a redaction proposal. Throws when AI is unavailable. */
  async propose(narrative: string): Promise<RedactionProposal> {
    const apiKey = process.env.VENICE_API_KEY || '';
    if (!apiKey || apiKey === 'your_venice_api_key_here') {
      throw new Error('Redaction unavailable: VENICE_API_KEY not configured');
    }
    if (!narrative.trim()) {
      return { redacted: narrative, notes: ['Narrative is empty — nothing to redact.'], clean: true };
    }

    const response = await axios.post(
      VENICE_API_URL,
      {
        model: process.env.VENICE_VERIFICATION_MODEL || 'mistral-31-24b',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: narrative },
        ],
        temperature: 0.1,
        max_tokens: 4000,
      },
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 60_000,
      },
    );

    let content: string = response.data.choices?.[0]?.message?.content ?? '';
    if (!content) throw new Error('Empty response from Venice AI');

    content = content.trim();
    if (content.startsWith('```json')) content = content.slice(7);
    else if (content.startsWith('```')) content = content.slice(3);
    if (content.endsWith('```')) content = content.slice(0, -3);

    const result = JSON.parse(content.trim());
    if (typeof result.redacted !== 'string' || !result.redacted.trim()) {
      throw new Error('Redaction proposal missing redacted narrative');
    }

    return {
      redacted: result.redacted,
      notes: Array.isArray(result.notes)
        ? result.notes.filter((n: unknown) => typeof n === 'string').slice(0, 20)
        : [],
      clean: result.clean === true,
    };
  }

  /**
   * Freeze an admin-accepted narrative without requiring channel approval.
   */
  async accept(
    trackingId: string,
    narrative: string,
    notes: string[],
    actor: string,
  ): Promise<{ ok: boolean; error?: string }> {
    if (!narrative.trim()) return { ok: false, error: 'narrative_empty' };

    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) return { ok: false, error: 'report_not_found' };
    const consent = disseminationService.consentFromReport(loaded.report);
    if (!consent) return { ok: false, error: 'no_consent_on_record' };
    await disseminationPersistence.saveNarrativeReview(trackingId, consent, {
      narrativeOverride: { narrative, notes, setBy: actor, setAt: new Date() },
    });

    await disseminationPersistence.appendAudit({
      trackingId,
      event: 'narrative_redacted',
      actor,
      detail: { notes: notes.slice(0, 10) },
    });
    return { ok: true };
  }

  /** Remove the override so packets revert to the raw narrative. */
  async clear(trackingId: string, actor: string): Promise<{ ok: boolean; error?: string }> {
    const disposition = await disseminationPersistence.getDisposition(trackingId);
    if (!disposition) return { ok: false, error: 'no_disposition' };
    if (!disposition.narrativeOverride) return { ok: true };

    await disseminationPersistence.clearNarrativeReview(trackingId);

    await disseminationPersistence.appendAudit({
      trackingId,
      event: 'narrative_redaction_cleared',
      actor,
    });
    return { ok: true };
  }

  /**
   * Record the "reviewed, no redaction needed" attestation. Satisfies the
   * H1 gate without freezing an override, so packets keep the raw narrative
   * an admin has judged free of reporter-identifying detail.
   */
  async markReviewedClean(trackingId: string, actor: string): Promise<{ ok: boolean; error?: string }> {
    const loaded = await disseminationService.buildView(trackingId);
    if (!loaded) return { ok: false, error: 'report_not_found' };
    if (!loaded.narrativeReadable) return { ok: false, error: 'narrative_unavailable' };
    const consent = disseminationService.consentFromReport(loaded.report);
    if (!consent) return { ok: false, error: 'no_consent_on_record' };
    await disseminationPersistence.saveNarrativeReview(trackingId, consent, {
      narrativeReviewedAt: new Date(), narrativeReviewedBy: actor,
    });
    await disseminationPersistence.appendAudit({ trackingId, event: 'narrative_reviewed_clean', actor });
    return { ok: true };
  }
}

export const redactionService = new RedactionService();
