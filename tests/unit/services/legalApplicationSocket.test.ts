import { EventEmitter } from 'node:events';
import { SocketModeClient } from '@slack/socket-mode';
import { LegalApplicationSocketWorker, legalApplicationSocketSettings } from '../../../src/services/legalApplicationSocket';

jest.mock('@slack/socket-mode', () => ({ SocketModeClient: jest.fn(), LogLevel: { ERROR: 'error' } }));
const env = { SLACK_APPLICATION_APP_TOKEN: 'xapp-synthetic-test', SLACK_APPLICATION_BOT_TOKEN: 'xoxb-synthetic-test', SLACK_APPLICATION_TEAM_ID: 'T123', SLACK_APPLICATION_APPROVERS: 'U123,U456' };
const body = (overrides = {}) => ({ type: 'block_actions', team: { id: 'T123' }, user: { id: 'U123' },
  actions: [{ action_id: 'vera_application_approve', value: 'a'.repeat(64) }], ...overrides });
const flush = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

describe('legal application Socket Mode transport', () => {
  let client: EventEmitter & { start: jest.Mock; disconnect: jest.Mock };
  let worker: LegalApplicationSocketWorker;
  let decide: jest.Mock, outcome: jest.Mock, status: jest.Mock, getApplication: jest.Mock;
  beforeEach(() => {
    client = Object.assign(new EventEmitter(), { start: jest.fn().mockResolvedValue({}), disconnect: jest.fn().mockResolvedValue(undefined) });
    (SocketModeClient as unknown as jest.Mock).mockImplementation(() => client);
    decide = jest.fn().mockResolvedValue(true); outcome = jest.fn(); status = jest.fn();
    getApplication = jest.fn().mockResolvedValue(null);
    worker = new LegalApplicationSocketWorker({ settings: legalApplicationSocketSettings(env)!, decide, getApplication,
      onDecision: outcome, onStatus: status });
    worker.start();
  });
  afterEach(async () => { await worker.stop(); jest.useRealTimers(); jest.clearAllMocks(); });
  const emit = (client: EventEmitter, payload: unknown, type = 'interactive') => {
    const ack = jest.fn().mockResolvedValue(undefined); client.emit('slack_event', { type, body: payload, ack }); return ack;
  };

  it('is opt-in, requires an app token and explicit workspace/reviewers, and does not require an HTTP secret', () => {
    expect(legalApplicationSocketSettings({})).toBeNull();
    expect(legalApplicationSocketSettings(env)).toBeTruthy();
    for (const override of [{ SLACK_APPLICATION_APP_TOKEN: 'xoxb-wrong-token' }, { SLACK_APPLICATION_TEAM_ID: '' },
      { SLACK_APPLICATION_APPROVERS: '' }, { SLACK_APPLICATION_APPROVERS: 'U123,*' },
      { SLACK_APPLICATION_BOT_TOKEN: undefined }, { SLACK_APPLICATION_BOT_TOKEN: '' }, { SLACK_APPLICATION_BOT_TOKEN: 'xapp-wrong-kind' }]) {
      expect(() => legalApplicationSocketSettings({ ...env, ...override })).toThrow('Invalid legal application Socket Mode configuration');
    }
  });
  const metadata = `v1:${'a'.repeat(64)}:${'b'.repeat(64)}`;
  const review = () => body({ actions: [{ action_id: 'vera_application_review_key', value: metadata }],
    trigger_id: 'synthetic-trigger', response_url: 'https://hooks.slack.com/actions/T123/B/C' });
  const application = { id: 'a'.repeat(64), status: 'pending' as const, createdAt: 1000,
    displayName: 'Example Counsel', domain: 'firm.example', email: 'test@firm.example',
    lawyerName: 'Synthetic Lawyer', jurisdiction: 'Test', registrationNumber: 'TEST',
    enrollment: { organizationId: 'a'.repeat(64), recipientKeyId: 'c'.repeat(64), bindingDocument: 'synthetic-binding' } };
  const responseUrl = 'https://hooks.slack.com/actions/T123/B/C';
  const direct = () => body({ response_url: responseUrl,
    actions: [{ action_id: 'vera_application_approve', value: `v2:${application.id}:${'b'.repeat(64)}:${application.enrollment.recipientKeyId}` }] });

  it('refreshes an older Review card into Approve and Deny without opening a modal or recording a decision', async () => {
    getApplication.mockResolvedValue(application);
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      const ack = emit(client, review());
      await worker.stop();
      expect(ack).toHaveBeenCalledWith(); expect(decide).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toBe(responseUrl);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(message.blocks.find((block: any) => block.type === 'actions').elements.map((action: any) => action.text.text)).toEqual(['Approve', 'Deny']);
      expect(JSON.stringify(message)).not.toContain('plain_text_input');
    } finally { fetchMock.mockRestore(); }
  });

  it('acknowledges before slow approval work and displays success only after the stored result is read', async () => {
    jest.useFakeTimers();
    let finish!: (value: boolean) => void;
    decide.mockImplementationOnce(() => new Promise<boolean>(resolve => { finish = resolve; }));
    getApplication.mockResolvedValue({ ...application, status: 'approved', keyReviewStatus: 'approved',
      keyReviewedBy: 'slack:T123:U123', keyReviewedAt: 2000 });
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      const ack = emit(client, direct()); await flush();
      expect(ack).toHaveBeenCalledTimes(1);
      expect(decide).toHaveBeenCalledWith({ id: application.id, status: 'approved', actor: 'slack:T123:U123',
        reviewDigest: 'b'.repeat(64), confirmedKeyId: application.enrollment.recipientKeyId });
      await jest.advanceTimersByTimeAsync(15000);
      expect(ack).toHaveBeenCalledTimes(1); expect(fetchMock).not.toHaveBeenCalled();
      expect(outcome).not.toHaveBeenCalled();
      finish(true); await worker.stop();
      expect(JSON.parse(fetchMock.mock.calls[0][1]!.body as string).text).toBe('Approved: Example Counsel');
    } finally { fetchMock.mockRestore(); }
  });

  it('replaces an already-open old modal with instructions immediately and never decides from it', async () => {
    const ack = emit(client, body({ type: 'view_submission', view: { callback_id: 'vera_application_key_confirm', private_metadata: metadata } }));
    await flush();
    expect(ack).toHaveBeenCalledWith(expect.objectContaining({ response_action: 'update', view: expect.objectContaining({ type: 'modal' }) }));
    expect(decide).not.toHaveBeenCalled(); expect(getApplication).not.toHaveBeenCalled();
    expect(ack.mock.calls[0][0].view).not.toHaveProperty('submit');
  });

  it('does not fetch applications or send responses for unauthorized review or approval clicks', async () => {
    const fetchMock = jest.spyOn(global, 'fetch');
    try {
      emit(client, { ...review(), user: { id: 'U999' } });
      emit(client, { ...direct(), team: { id: 'T999' } });
      await flush();
      expect(decide).not.toHaveBeenCalled(); expect(getApplication).not.toHaveBeenCalled(); expect(fetchMock).not.toHaveBeenCalled();
    } finally { fetchMock.mockRestore(); }
  });

  it('keeps pending controls and reports a failed backend connection without exposing diagnostics', async () => {
    decide.mockRejectedValueOnce(new Error('private-backend-url-and-secret'));
    getApplication.mockRejectedValueOnce(new Error('private-application'));
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      const ack = emit(client, direct()); await worker.stop();
      expect(ack).toHaveBeenCalledTimes(1);
      const message = JSON.parse(fetchMock.mock.calls[0][1]!.body as string);
      expect(message).toMatchObject({ replace_original: false, response_type: 'ephemeral' });
      expect(message.text).toContain('could not confirm');
      expect(JSON.stringify([message, status.mock.calls])).not.toMatch(/private-backend|private-application|secret/);
    } finally { fetchMock.mockRestore(); }
  });

  it('recovers the stored outcome after an ambiguous backend error without repeating a decision', async () => {
    decide.mockRejectedValueOnce(new Error('connection closed after commit'));
    getApplication.mockResolvedValue({ ...application, status: 'approved', keyReviewStatus: 'approved' });
    const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('ok'));
    try {
      const ack = emit(client, direct()); await worker.stop();
      expect(ack).toHaveBeenCalledTimes(1); expect(decide).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(JSON.parse(fetchMock.mock.calls[0][1]!.body as string).text).toBe('Approved: Example Counsel');
    } finally { fetchMock.mockRestore(); }
  });
  it.each(['approve', 'deny'])('acknowledges an authorized %s before persistence without calling an untrusted response URL', async action => {
    let finish!: (value: boolean) => void;
    decide.mockImplementationOnce(() => new Promise<boolean>(resolve => { finish = resolve; }));
    const fetch = jest.spyOn(global, 'fetch');
    try {
      const ack = emit(client, body({ actions: [{ action_id: `vera_application_${action}`, value: 'a'.repeat(64) }], response_url: 'https://untrusted.example/' }));
      await flush(); expect(ack).toHaveBeenCalledTimes(1);
      expect(decide).toHaveBeenCalledWith({ id: 'a'.repeat(64), status: action === 'approve' ? 'approved' : 'denied', actor: 'slack:T123:U123' });
      finish(true); await flush();
      expect(ack).toHaveBeenCalledTimes(1); expect(fetch).not.toHaveBeenCalled();
      expect(outcome).toHaveBeenCalledWith(action === 'approve' ? 'approved' : 'denied', expect.any(Object));
    } finally { fetch.mockRestore(); }
  });
  it.each([
    { team: { id: 'T999' } }, { user: { id: 'U999' } }, { user: null }, { type: 'view_submission' },
    { actions: [null] }, { actions: [] }, { actions: [{ action_id: 'vera_application_approve', value: 'not-an-id' }] },
    { actions: [{ action_id: 'unrelated_action', value: 'a'.repeat(64) }] },
  ])('rejects unauthorized or malformed payload %j without a decision', async override => {
    const ack = emit(client, body(override)); await flush();
    expect(decide).not.toHaveBeenCalled(); expect(ack).toHaveBeenCalledTimes(1);
    expect(outcome).toHaveBeenCalledWith('rejected', null);
  });
  it('acknowledges database failures and permits an explicit retry without leaking details', async () => {
    decide.mockRejectedValueOnce(new Error('secret-and-private-data'));
    const ack = emit(client, body()); await flush();
    expect(ack).toHaveBeenCalledTimes(1); expect(status).toHaveBeenCalledWith('unavailable');
    expect(JSON.stringify(status.mock.calls)).not.toContain('secret-and-private-data');
    const retry = emit(client, body()); await flush(); expect(retry).toHaveBeenCalledTimes(1);
    expect(decide).toHaveBeenCalledTimes(2);
  });
  it('acknowledges a conflicting decision without claiming approval', async () => {
    decide.mockResolvedValueOnce(false);
    const ack = emit(client, body()); await flush();
    expect(ack).toHaveBeenCalledTimes(1); expect(outcome).toHaveBeenCalledWith('conflict', expect.any(Object));
  });
  it('shows the stored approval on a stale Deny click and acknowledges before updating Slack', async () => {
    decide.mockResolvedValue(false);
    getApplication.mockResolvedValue({ id: 'a'.repeat(64), status: 'approved', createdAt: 1000, decidedAt: 2000,
      decidedBy: 'slack:T123:U456', displayName: 'Example Counsel', domain: 'firm.example', email: 'test@firm.example',
      lawyerName: 'Synthetic Lawyer', jurisdiction: 'Test', registrationNumber: 'TEST' });
    const ack = jest.fn().mockResolvedValue(undefined);
    const fetch = jest.spyOn(global, 'fetch').mockImplementation(async (_url, options) => {
      expect(ack).toHaveBeenCalledTimes(1);
      const message = JSON.parse(options!.body as string);
      expect(message.text).toBe('Approved: Example Counsel');
      expect(JSON.stringify(message)).toContain('<@U456>');
      expect(message.blocks.some((block: any) => block.type === 'actions')).toBe(false);
      return { status: 200, text: async () => 'ok' } as Response;
    });
    try {
      client.emit('slack_event', { type: 'interactive', ack, body: body({
        actions: [{ action_id: 'vera_application_deny', value: 'a'.repeat(64) }], response_url: 'https://hooks.slack.com/actions/T123/B/C' }) });
      await flush(); expect(fetch).toHaveBeenCalledTimes(1);
    } finally { fetch.mockRestore(); }
  });
  it('acknowledges unrelated events without interpreting them as decisions', async () => {
    const ack = emit(client, body(), 'events_api'); await flush();
    expect(decide).not.toHaveBeenCalled(); expect(ack).toHaveBeenCalledTimes(1);
    expect(outcome).toHaveBeenCalledWith('ignored', null);
  });
  it('reconnects after disconnect or startup failure, then cancels retry on shutdown', async () => {
    await flush(); jest.useFakeTimers();
    client.start.mockRejectedValueOnce(new Error('private-connection-url'));
    client.emit('disconnected'); await jest.advanceTimersByTimeAsync(5000);
    expect(client.start).toHaveBeenCalledTimes(2);
    await jest.advanceTimersByTimeAsync(5000); expect(client.start).toHaveBeenCalledTimes(3);
    client.emit('disconnected'); await worker.stop();
    await jest.advanceTimersByTimeAsync(10_000); expect(client.start).toHaveBeenCalledTimes(3);
  });
  it('drains an accepted decision before shutdown and stops accepting new events', async () => {
    let finish!: (value: boolean) => void;
    decide.mockImplementationOnce(() => new Promise<boolean>(resolve => { finish = resolve; }));
    const ack = emit(client, body()); await flush();
    let closed = false; const closing = worker.stop().then(() => { closed = true; });
    await flush(); expect(closed).toBe(false);
    emit(client, body()); expect(decide).toHaveBeenCalledTimes(1);
    finish(true); await closing; expect(ack).toHaveBeenCalledTimes(1);
  });
});
