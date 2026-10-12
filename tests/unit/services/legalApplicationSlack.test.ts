const mockDecisionRequest = jest.fn();
jest.mock('@/lib/legalApplicationProxy', () => ({ legalApplicationRequest: (...args: unknown[]) => mockDecisionRequest(...args) }));
import handler from '../../../pages/api/legal-applications/slack';
import { Readable } from 'node:stream';
import { createHmac } from 'node:crypto';
import {
  authorizeSlackApplicationDecision, authorizeSlackApplicationKeyReview, refreshSlackApplicationMessage,
  verifySlackApplicationDecision, notifyLegalApplication, updateSlackApplicationDecision, updateSlackApplicationMessage,
  notifySlackApplicationDecisionFailure,
} from '../../../src/services/legalApplicationSlack';
import { applicationReviewDigest } from '../../../src/utils/legalApplicationEnrollment';
import { parseLegalApplication } from '../../../src/utils/legalApplications';
import type { LegalApplicationView } from '../../../src/utils/legalApplications';
const input = { displayName: '<!channel> Test Counsel', domain: 'firm.example', email: 'lawyer@firm.example', lawyerName: 'Test Lawyer', jurisdiction: 'Test', registrationNumber: 'TEST' };
const env = { SLACK_APPLICATION_SIGNING_SECRET: 'synthetic-test-secret', SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: 'U123' };
const responseUrl = 'https://hooks.slack.com/actions/T123/123/synthetic-capability';
const now = 1_800_000_000_000;
const timestamp = String(now / 1000);
const keyId = 'bc'.repeat(32);
const combinedApplication: LegalApplicationView = {
  ...input, id: 'a'.repeat(64), status: 'pending', createdAt: now,
  enrollment: { organizationId: 'a'.repeat(64), recipientKeyId: keyId, bindingDocument: 'synthetic-public-binding' },
};
const metadata = `v1:${combinedApplication.id}:${'d'.repeat(64)}`;
const keyReview = { type: 'block_actions', team: { id: 'T123' }, user: { id: 'U123' },
  trigger_id: 'synthetic-trigger', response_url: responseUrl,
  actions: [{ action_id: 'vera_application_review_key', value: metadata }] };
function signed(overrides = {}) {
  const payload = { type: 'block_actions', team: { id: 'T123' }, user: { id: 'U123' },
    response_url: responseUrl, actions: [{ action_id: 'vera_application_approve', value: 'a'.repeat(64) }], ...overrides };
  const raw = Buffer.from(new URLSearchParams({ payload: JSON.stringify(payload) }).toString());
  const signature = 'v0=' + createHmac('sha256', env.SLACK_APPLICATION_SIGNING_SECRET).update(`v0:${timestamp}:`).update(raw).digest('hex');
  return { raw, signature };
}
describe('firm application input and Slack decisions', () => {
  it('rejects unknown/case fields, domain mismatches, controls, and URL domains', () => {
    expect(parseLegalApplication(input)).toEqual(input);
    for (const extra of [{ caseId: 'private' }, { email: 'other@elsewhere.example' }, { domain: 'https://firm.example' }, { lawyerName: 'name\nsecret' }]) {
      expect(parseLegalApplication({ ...input, ...extra })).toBeNull();
    }
  });
  it('authenticates exact raw bytes, freshness, workspace and approver', () => {
    const { raw, signature } = signed();
    expect(verifySlackApplicationDecision(raw, timestamp, signature, env, now)).toEqual({ id: 'a'.repeat(64), status: 'approved', actor: 'slack:T123:U123', responseUrl });
    expect(verifySlackApplicationDecision(Buffer.concat([raw, Buffer.from(' ')]), timestamp, signature, env, now)).toBeNull();
    expect(verifySlackApplicationDecision(raw, timestamp, signature, env, now + 301_000)).toBeNull();
    expect(verifySlackApplicationDecision(raw, timestamp, signature, { ...env, SLACK_APPLICATION_APPROVERS: '' }, now)).toBeNull();
    for (const overrides of [{ team: { id: 'T999' } }, { user: { id: 'U999' } }, { actions: [{ action_id: 'other', value: 'a'.repeat(64) }] }]) {
      const bad = signed(overrides); expect(verifySlackApplicationDecision(bad.raw, timestamp, bad.signature, env, now)).toBeNull();
    }
  });
  it('uses plain-text applicant fields without arbitrary response URL or redirects', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({ status: 200, text: async () => 'ok' } as Response);
    try {
      expect(await notifyLegalApplication({ ...input, id: 'a'.repeat(64), status: 'pending', createdAt: now }, { SLACK_APPLICATION_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/TEST' })).toBe(true);
      const options = fetchMock.mock.calls[0][1]!;
      expect(options.redirect).toBe('error');
      const payload = JSON.parse(options.body as string);
      expect(payload.blocks[0].text.type).toBe('plain_text');
      expect(payload).not.toHaveProperty('response_url');
      expect(JSON.stringify(payload)).not.toContain('createdAt');
    } finally { fetchMock.mockRestore(); }
  });
  it('rejects signed callbacks with missing, cross-team, redirected or arbitrary response URLs', () => {
    for (const response_url of [undefined, 'https://evil.example/actions/T123/123/secret', 'https://hooks.slack.com.evil.example/actions/T123/123/secret',
      'http://hooks.slack.com/actions/T123/123/secret', 'https://hooks.slack.com:443/actions/T123/123/secret',
      'https://hooks.slack.com/actions/T999/123/secret', responseUrl + '?url=secret', responseUrl + '#secret',
      'https://hooks.slack.com/actions/T123/../secret', 'https://user@hooks.slack.com/actions/T123/123/secret']) {
      const value = signed({ response_url });
      expect(verifySlackApplicationDecision(value.raw, timestamp, value.signature, env, now)).toBeNull();
    }
  });
  it('acknowledges before waiting and replaces buttons with the original durable actor on retries and conflicts', async () => {
    const previous = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
    Object.assign(process.env, env);
    const clock = jest.spyOn(Date, 'now').mockReturnValue(now);
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({ status: 200 } as Response);
    const recorded = { id: 'a'.repeat(64), status: 'denied', decidedBy: 'slack:T123:U456', decidedAt: now - 1000, displayName: 'Synthetic Counsel' };
    try {
      for (const status of [200, 409]) {
        let finish!: (value: unknown) => void;
        mockDecisionRequest.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
        const signedRequest = signed();
        const req = Object.assign(Readable.from([signedRequest.raw]), { method: 'POST', query: {}, headers: {
          'content-type': 'application/x-www-form-urlencoded', 'x-slack-request-timestamp': timestamp, 'x-slack-signature': signedRequest.signature,
        } });
        let acknowledge!: () => void;
        const acknowledged = new Promise<void>(resolve => { acknowledge = resolve; });
        const res = { setHeader: jest.fn(), status: jest.fn().mockReturnThis(), end: jest.fn(() => { acknowledge(); }) };
        const pending = handler(req as any, res as any);
        await acknowledged;
        expect(res.status).toHaveBeenCalledWith(200);
        expect(fetchMock).not.toHaveBeenCalled();
        finish({ status, data: { success: status === 200, decision: recorded } });
        await pending;
        expect(mockDecisionRequest).toHaveBeenLastCalledWith('decide', { id: recorded.id, status: 'approved', actor: 'slack:T123:U123' });
        const [url, options] = fetchMock.mock.calls[0];
        expect(url).toBe(responseUrl);
        expect(options).toMatchObject({ method: 'POST', redirect: 'error' });
        expect(options?.signal).toBeDefined();
        const message = JSON.parse(options!.body as string);
        expect(message.replace_original).toBe(true);
        expect(message.blocks).toHaveLength(1);
        expect(message.blocks[0].text.type).toBe('plain_text');
        expect(message.text).toContain('Application denied. Synthetic Counsel\nRecorded by slack:T123:U456');
        expect(JSON.stringify(message)).not.toContain('U123');
        fetchMock.mockClear();
      }
    } finally {
      clock.mockRestore(); fetchMock.mockRestore();
      for (const key of Object.keys(env)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    }
  });

  it('keeps original controls when the outcome is unknown and treats Slack errors as delivery failures', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({ status: 200 } as Response);
    try {
      expect(await updateSlackApplicationDecision(responseUrl, null)).toBe(true);
      const body = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(body).toMatchObject({ replace_original: false, response_type: 'ephemeral' });
      expect(body.text).toContain('could not be confirmed');
      fetchMock.mockRejectedValueOnce(new Error('synthetic redirect or timeout'));
      expect(await updateSlackApplicationDecision(responseUrl, null)).toBe(false);
      fetchMock.mockClear();
      expect(await updateSlackApplicationDecision('https://evil.example/', null)).toBe(false);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); }
  });
  it.each(['approved', 'denied'] as const)('replaces a decided message with %s and no buttons, using only stored data', async status => {
    const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({ status: 200, text: async () => JSON.stringify({ ok: true }) } as Response);
    try {
      expect(await updateSlackApplicationMessage(responseUrl, {
        ...input, id: 'a'.repeat(64), status, createdAt: now, decidedAt: now, decidedBy: 'slack:T123:U123',
      }, env)).toBe(true);
      const options = fetchMock.mock.calls[0][1]!;
      const message = JSON.parse(options.body as string);
      expect(message.replace_original).toBe(true); expect(message.response_type).toBe('in_channel');
      expect(message.text).toContain(status === 'approved' ? 'Approved' : 'Denied');
      expect(message.blocks.some((block: any) => block.type === 'actions')).toBe(false);
      expect(message.blocks[1].text.type).toBe('plain_text');
      expect(message.blocks[2].elements[0].text).toContain('<@U123>');
      expect(options.redirect).toBe('error');
    } finally { fetchMock.mockRestore(); }
  });
  it('refuses untrusted response URLs or undecided applications before any network request', async () => {
    const fetchMock = jest.spyOn(global, 'fetch');
    const application = { ...input, id: 'a'.repeat(64), status: 'approved' as const, createdAt: now };
    try {
      for (const url of [undefined, 'http://hooks.slack.com/actions/A/B/C', 'https://untrusted.example/actions/A/B/C',
        'https://hooks.slack.com.evil.example/actions/A/B/C', 'https://hooks.slack.com/services/A/B/C',
        'https://user:pass@hooks.slack.com/actions/A/B/C', 'https://hooks.slack.com/actions/A/B/C?redirect=elsewhere',
        // Another workspace's capability, or no workspace segment at all.
        'https://hooks.slack.com/actions/T999/123/secret', 'https://hooks.slack.com/actions/A/B/C', responseUrl + '/extra']) {
        expect(await updateSlackApplicationMessage(url, application, env)).toBe(false);
      }
      expect(await updateSlackApplicationMessage(responseUrl, { ...application, status: 'pending' }, env)).toBe(false);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); }
  });
});

describe('direct firm and key decisions', () => {
  const direct = (action = 'approve', value = `v2:${combinedApplication.id}:${'d'.repeat(64)}:${keyId}`) => ({
    ...keyReview, actions: [{ action_id: `vera_application_${action}`, value }],
  });

  it('offers only Approve and Deny, bound to the displayed key and reviewed snapshot', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      expect(await notifyLegalApplication(combinedApplication, { SLACK_APPLICATION_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/TEST' })).toBe(true);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      const actions = message.blocks.find((block: any) => block.type === 'actions').elements;
      expect(actions.map((action: any) => action.text.text)).toEqual(['Approve', 'Deny']);
      expect(actions[0]).toMatchObject({ action_id: 'vera_application_approve',
        value: `v2:${combinedApplication.id}:${await applicationReviewDigest(combinedApplication)}:${keyId}` });
      expect(actions[1]).toMatchObject({ action_id: 'vera_application_deny', value: actions[0].value });
      expect(JSON.stringify(message)).toContain(`Public Key ID: ${keyId}`);
      expect(JSON.stringify(message)).not.toMatch(/Review firm and key|plain_text_input|synthetic-public-binding/);
      const changed = { ...combinedApplication, email: 'other@firm.example' };
      await notifyLegalApplication(changed, { SLACK_APPLICATION_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/TEST/TEST' });
      const nextActions = JSON.parse(fetchMock.mock.calls[1][1]!.body as string).blocks.find((block: any) => block.type === 'actions').elements;
      expect(nextActions[0].value).not.toBe(actions[0].value);
    } finally { fetchMock.mockRestore(); }
  });

  it('authorizes a direct approval with an exact key, and a denial with the snapshot digest', () => {
    expect(authorizeSlackApplicationDecision(direct(), env)).toEqual({
      id: combinedApplication.id, status: 'approved', actor: 'slack:T123:U123', reviewDigest: 'd'.repeat(64), confirmedKeyId: keyId,
    });
    expect(authorizeSlackApplicationDecision(direct('deny'), env)).toEqual({
      id: combinedApplication.id, status: 'denied', actor: 'slack:T123:U123', reviewDigest: 'd'.repeat(64),
    });
    for (const override of [{ team: { id: 'T999' } }, { user: { id: 'U999' } }, { type: 'view_submission' }]) {
      expect(authorizeSlackApplicationDecision({ ...direct(), ...override }, env)).toBeNull();
    }
    for (const value of [metadata, `v2:${combinedApplication.id}:${'d'.repeat(64)}`, `v2:${combinedApplication.id}:${'d'.repeat(64)}:${'g'.repeat(64)}`, direct().actions[0].value + ':extra']) {
      expect(authorizeSlackApplicationDecision(direct('approve', value), env)).toBeNull();
    }
  });

  it('keeps old Review clicks as refresh requests rather than approvals', async () => {
    expect(authorizeSlackApplicationDecision(keyReview, env)).toBeNull();
    expect(authorizeSlackApplicationKeyReview(keyReview, env)?.metadata).toBe(metadata);
    expect(authorizeSlackApplicationKeyReview({ ...keyReview, user: { id: 'U999' } }, env)).toBeNull();
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      expect(await refreshSlackApplicationMessage(responseUrl, combinedApplication, env)).toBe(true);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(message).toMatchObject({ replace_original: true, response_type: 'in_channel' });
      expect(message.blocks.find((block: any) => block.type === 'actions').elements.map((action: any) => action.text.text)).toEqual(['Approve', 'Deny']);
      expect(fetchMock.mock.calls[0][0]).toBe(responseUrl);
      expect(fetchMock.mock.calls[0][1]?.redirect).toBe('error');
      fetchMock.mockClear();
      expect(await refreshSlackApplicationMessage(responseUrl.replace('T123', 'T999'), combinedApplication, env)).toBe(false);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); }
  });

  it('reports backend failures privately without implying approval or removing controls', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      expect(await notifySlackApplicationDecisionFailure(responseUrl, env)).toBe(true);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(message).toMatchObject({ replace_original: false, response_type: 'ephemeral' });
      expect(message.text).toContain('could not confirm');
      fetchMock.mockClear();
      for (const url of [undefined, responseUrl.replace('T123', 'T999'), 'https://example.com', responseUrl + '?redirect=elsewhere']) {
        expect(await notifySlackApplicationDecisionFailure(url, env)).toBe(false);
      }
      expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); }
  });

  it('refreshes a denied application to its stored denial even if the key review still says pending', async () => {
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      expect(await refreshSlackApplicationMessage(responseUrl, { ...combinedApplication, status: 'denied', keyReviewStatus: 'pending' }, env)).toBe(true);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(message.text).toContain('Denied');
      expect(message.blocks.some((block: any) => block.type === 'actions')).toBe(false);
    } finally { fetchMock.mockRestore(); }
  });

  it.each(['approved', 'denied'] as const)('shows only the stored final %s result and its public key', async status => {
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      // Initial denials do not set keyReviewStatus in the stored application.
      expect(await updateSlackApplicationMessage(responseUrl, { ...combinedApplication, status,
        ...(status === 'approved' ? { keyReviewStatus: status } : {}), decidedAt: now, decidedBy: 'slack:T123:U123' }, env)).toBe(true);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(JSON.stringify(message)).toContain(keyId);
      expect(message.text).toContain(status === 'approved' ? 'Approved' : 'Denied');
      expect(message.blocks.some((block: any) => block.type === 'actions')).toBe(false);
    } finally { fetchMock.mockRestore(); }
  });
});
