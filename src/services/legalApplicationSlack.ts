import { createHmac, timingSafeEqual } from 'node:crypto';
import type { LegalApplicationView, LegalApplicationDecision } from '../utils/legalApplications';
import { LEGAL_APPLICATION_ID } from '../utils/legalApplications';
import { applicationReviewDigest } from '../utils/legalApplicationEnrollment';

export type SlackApplicationDecision = { id: string; status: 'approved' | 'denied'; actor: string; reviewDigest?: string; confirmedKeyId?: string };
const RESPONSE_URL = /^https:\/\/hooks\.slack\.com\/actions\/(T[A-Z0-9]+)\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/;
export type SlackApplicationPolicy = Record<string, string | undefined>;
export const KEY_REVIEW_CALLBACK = 'vera_application_key_confirm';
const COMBINED_REVIEW = /^v1:([a-f0-9]{64}):([a-f0-9]{64})$/;
// The action binds approval to the exact application snapshot and displayed key.
const DIRECT_REVIEW = /^v2:([a-f0-9]{64}):([a-f0-9]{64}):([a-f0-9]{64})$/;

function reviewer(payload: unknown, env: SlackApplicationPolicy): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const body = payload as { team?: { id?: unknown }; user?: { id?: unknown } };
  const approvers = (env.SLACK_APPLICATION_APPROVERS || '').split(',').map(value => value.trim()).filter(Boolean);
  return env.SLACK_APPLICATION_TEAM_ID && body.team?.id === env.SLACK_APPLICATION_TEAM_ID &&
    typeof body.user?.id === 'string' && approvers.includes(body.user.id) && /^U[A-Z0-9]+$/.test(body.user.id)
    ? `slack:${body.team.id}:${body.user.id}` : null;
}

/** Older Review buttons refresh the card; they never approve an application. */
export function authorizeSlackApplicationKeyReview(payload: unknown, env: SlackApplicationPolicy):
  { metadata: string; actor: string; triggerId: string; responseUrl: unknown } | null {
  const actor = reviewer(payload, env);
  if (!actor) return null;
  const body = payload as { type?: unknown; actions?: { action_id?: unknown; value?: unknown }[]; trigger_id?: unknown; response_url?: unknown };
  if (body.type !== 'block_actions' || !Array.isArray(body.actions) || body.actions.length !== 1 ||
      body.actions[0]?.action_id !== 'vera_application_review_key' || typeof body.actions[0].value !== 'string' ||
      !COMBINED_REVIEW.test(body.actions[0].value) || typeof body.trigger_id !== 'string' || !body.trigger_id || body.trigger_id.length > 512) return null;
  return { metadata: body.actions[0].value, actor, triggerId: body.trigger_id, responseUrl: body.response_url };
}

/** Keep the controls available on failures; acknowledging receipt is not approval. */
export async function notifySlackApplicationDecisionFailure(responseUrl: unknown,
  env: SlackApplicationPolicy): Promise<boolean> {
  if (typeof responseUrl !== 'string' || responseUrl.length > 2048 || !env.SLACK_APPLICATION_TEAM_ID ||
      RESPONSE_URL.exec(responseUrl)?.[1] !== env.SLACK_APPLICATION_TEAM_ID) return false;
  try {
    const response = await fetch(responseUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(2500),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        replace_original: false, response_type: 'ephemeral',
        text: 'VERA could not confirm the decision. The application buttons remain available. Try again; an already recorded decision will be preserved. If this continues, ask the operator to check the approval worker’s backend connection.',
      }) });
    if (response.status !== 200) { await response.body?.cancel(); return false; }
    const result = (await response.text()).trim();
    return result === 'ok' || JSON.parse(result)?.ok === true;
  } catch { return false; }
}

/** Authorization only. Call after HTTP HMAC verification or on an authenticated Slack socket. */
export function authorizeSlackApplicationDecision(payload: unknown, env: SlackApplicationPolicy = process.env): SlackApplicationDecision | null {
  const actor = reviewer(payload, env);
  if (!actor) return null;
  const body = payload as { type?: unknown; actions?: unknown };
  if (body.type !== 'block_actions' || !Array.isArray(body.actions) || body.actions.length !== 1) return null;
  const action = body.actions[0];
  if (!action || typeof action !== 'object') return null;
  const status = action.action_id === 'vera_application_approve' ? 'approved' : action.action_id === 'vera_application_deny' ? 'denied' : null;
  if (!status || typeof action.value !== 'string') return null;
  const direct = DIRECT_REVIEW.exec(action.value);
  if (direct) return { id: direct[1], reviewDigest: direct[2], status, actor,
    ...(status === 'approved' ? { confirmedKeyId: direct[3] } : {}) };
  const combined = COMBINED_REVIEW.exec(action.value);
  if (!combined && !LEGAL_APPLICATION_ID.test(action.value)) return null;
  // Old approvals do not bind the displayed key; require the updated card.
  if (combined && status === 'approved') return null;
  return { id: combined ? combined[1] : action.value, status, actor,
    ...(combined ? { reviewDigest: combined[2] } : {}) };
}

export function verifySlackApplicationDecision(raw: Buffer, timestamp: unknown, signature: unknown,
  env: NodeJS.ProcessEnv = process.env, now = Date.now()): (SlackApplicationDecision & { responseUrl: string }) | null {
  const secret = env.SLACK_APPLICATION_SIGNING_SECRET;
  if (!secret || typeof timestamp !== 'string' || !/^\d{10}$/.test(timestamp) ||
      Math.abs(now / 1000 - Number(timestamp)) > 300 || typeof signature !== 'string' || !/^v0=[a-f0-9]{64}$/.test(signature)) return null;
  const digest = `v0=${createHmac('sha256', secret).update(`v0:${timestamp}:`).update(raw).digest('hex')}`;
  if (!timingSafeEqual(Buffer.from(digest), Buffer.from(signature))) return null;
  try {
    const params = new URLSearchParams(raw.toString('utf8'));
    if (params.getAll('payload').length !== 1 || [...params.keys()].some(key => key !== 'payload')) return null;
    const payload = JSON.parse(params.get('payload')!);
    const decision = authorizeSlackApplicationDecision(payload, env);
    if (!decision) return null;
    const responseUrl = payload.response_url;
    if (typeof responseUrl !== 'string' || responseUrl.length > 2048 || RESPONSE_URL.exec(responseUrl)?.[1] !== payload.team.id) return null;
    return { ...decision, responseUrl };
  } catch { return null; }
}

/** Replace the original message using only a Slack-owned interaction response URL.
 * Call after transport authentication AND reviewer authorization; never persist the URL. */
export async function updateSlackApplicationMessage(responseUrl: unknown, application: LegalApplicationView,
  env: SlackApplicationPolicy = process.env): Promise<boolean> {
  if (typeof responseUrl !== 'string' || !['approved', 'denied'].includes(application.status) ||
      (application.enrollment && application.status !== 'denied' && !['approved', 'denied'].includes(application.keyReviewStatus || ''))) return false;
  try {
    // Same exact-origin, same-workspace capability rule as the signed HTTP path.
    if (responseUrl.length > 2048 || !env.SLACK_APPLICATION_TEAM_ID ||
        RESPONSE_URL.exec(responseUrl)?.[1] !== env.SLACK_APPLICATION_TEAM_ID) return false;
    const url = new URL(responseUrl);
    const status = application.status === 'denied' ? 'denied'
      : application.keyReviewStatus && application.keyReviewStatus !== 'pending' ? application.keyReviewStatus : application.status;
    const label = status === 'approved' ? 'Approved' : 'Denied';
    const reviewer = /^slack:(T[A-Z0-9]+):(U[A-Z0-9]+)$/.exec(application.keyReviewedBy || application.decidedBy || '');
    const by = reviewer && reviewer[1] === env.SLACK_APPLICATION_TEAM_ID ? `<@${reviewer[2]}>` : 'a Vera administrator';
    const decidedAt = application.keyReviewedAt ?? application.decidedAt;
    const when = decidedAt === undefined ? '' : ` · ${new Date(decidedAt).toISOString()}`;
    const message = { replace_original: true, response_type: 'in_channel',
      text: `${label}: ${application.displayName}`,
      blocks: [
        { type: 'header', text: { type: 'plain_text', text: status === 'approved' ? '✅ Approved' : '❌ Denied' } },
        { type: 'section', text: { type: 'plain_text', text: `${application.displayName}\nDomain: ${application.domain}\nContact: ${application.email}\nLawyer: ${application.lawyerName}\nJurisdiction: ${application.jurisdiction}\nRegistration: ${application.registrationNumber}` } },
        { type: 'context', elements: [{ type: 'mrkdwn', text: `${label} by ${by}${when}` }] },
        { type: 'section', text: { type: 'plain_text', text: status === 'approved'
          ? application.enrollment ? `Firm and key approved: ${application.enrollment.recipientKeyId}.\nActivation is queued; reporter permission is still required for private reports.` : 'Final decision recorded. Organization onboarding is authorized; firm enrollment and report access remain separate.'
          : `${application.enrollment ? `Public Key ID: ${application.enrollment.recipientKeyId}\n` : ''}Final decision recorded. No Auth0 organization will be created for this application.` } },
      ], unfurl_links: false, unfurl_media: false,
    };
    // The decision is already durable and Slack has been acknowledged. Retry a
    // transient display failure once; never roll back or repeat provisioning.
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await fetch(url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(3000),
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(message) });
        if (response.status === 200) {
          const result = (await response.text()).trim();
          if (result === 'ok' || JSON.parse(result)?.ok === true) return true;
        } else { await response.body?.cancel(); }
      } catch { /* Do not log response URLs or payloads. */ }
    }
  } catch { /* Invalid response URL or application projection. */ }
  return false;
}

async function pendingApplicationMessage(application: LegalApplicationView) {
  const digest = application.enrollment ? await applicationReviewDigest(application) : null;
  const actionValue = digest ? `v2:${application.id}:${digest}:${application.enrollment!.recipientKeyId}` : application.id;
  // Applicant strings are plain_text, never Slack markup or mentions. There is
  // no case ID, summary, reporter data, private key or invitation in this message.
  return { text: 'VERA legal organization application',
      blocks: [
        { type: 'section', text: { type: 'plain_text', text: `${application.displayName}\nDomain: ${application.domain}\nContact: ${application.email}\nLawyer: ${application.lawyerName}\nJurisdiction: ${application.jurisdiction}\nRegistration: ${application.registrationNumber}` } },
        ...(application.enrollment ? [{ type: 'section', text: { type: 'plain_text', text: `Public Key ID: ${application.enrollment.recipientKeyId}\nApprove accepts this firm and public key. Replacement keys require a separate review. No private key or recovery code is needed.` } }] : []),
        { type: 'section', text: { type: 'plain_text', text: 'Verify the domain and lawyer registration before approving. Approval creates an Auth0 organization for onboarding; it does not grant access to reports.' } },
        { type: 'actions', elements: [
          { type: 'button', text: { type: 'plain_text', text: 'Approve' }, style: 'primary', action_id: 'vera_application_approve', value: actionValue },
          { type: 'button', text: { type: 'plain_text', text: 'Deny' }, style: 'danger', action_id: 'vera_application_deny', value: actionValue },
        ] },
      ], unfurl_links: false, unfurl_media: false };
}

/** Upgrade an existing Review card without treating that click as approval. */
export async function refreshSlackApplicationMessage(responseUrl: unknown, application: LegalApplicationView,
  env: SlackApplicationPolicy): Promise<boolean> {
  if (application.status === 'denied' || (application.status === 'approved' && application.keyReviewStatus !== 'pending')) {
    return updateSlackApplicationMessage(responseUrl, application, env);
  }
  if (typeof responseUrl !== 'string' || responseUrl.length > 2048 || !env.SLACK_APPLICATION_TEAM_ID ||
      RESPONSE_URL.exec(responseUrl)?.[1] !== env.SLACK_APPLICATION_TEAM_ID) return false;
  try {
    const response = await fetch(responseUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(3000),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        ...await pendingApplicationMessage(application), replace_original: true, response_type: 'in_channel',
      }) });
    if (response.status !== 200) { await response.body?.cancel(); return false; }
    const result = (await response.text()).trim();
    return result === 'ok' || JSON.parse(result)?.ok === true;
  } catch { return false; }
}

export async function notifyLegalApplication(application: LegalApplicationView, env: NodeJS.ProcessEnv = process.env): Promise<boolean> {
  if (!env.SLACK_APPLICATION_WEBHOOK_URL) return false;
  try {
    const url = new URL(env.SLACK_APPLICATION_WEBHOOK_URL);
    if (url.protocol !== 'https:' || url.hostname !== 'hooks.slack.com' || url.port || url.username || url.password || url.search || url.hash ||
        !/^\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(url.pathname)) return false;
    const response = await fetch(url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(await pendingApplicationMessage(application)) });
    if (response.status !== 200) { await response.body?.cancel(); return false; }
    return (await response.text()).trim() === 'ok';
  } catch { return false; }
}

/** Replace the original controls with the persisted outcome, never with the
 * latest clicker's claim. Capability URL is memory-only and must not be logged. */
export async function updateSlackApplicationDecision(responseUrl: string, decision: LegalApplicationDecision | null): Promise<boolean> {
  if (!RESPONSE_URL.test(responseUrl)) return false;
  const text = decision
    ? `Application ${decision.status}. ${decision.displayName ?? decision.id}\nRecorded by ${decision.decidedBy} at ${new Date(decision.decidedAt).toISOString()}.\nFirm key enrollment and reporter permission are still required for private reports.`
    : 'The application decision could not be confirmed. Check Legal applications in VERA before retrying. No approval is implied by this acknowledgement.';
  try {
    const response = await fetch(responseUrl, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(2500),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        replace_original: decision !== null, ...(decision ? {} : { response_type: 'ephemeral' }),
        text, blocks: [{ type: 'section', text: { type: 'plain_text', text } }], unfurl_links: false, unfurl_media: false,
      }) });
    const ok = response.status === 200;
    await response.body?.cancel();
    return ok;
  } catch { return false; }
}
