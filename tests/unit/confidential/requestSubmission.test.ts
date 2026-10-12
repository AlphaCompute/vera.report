import {
  DELIVERY_UNCONFIRMED, WORKSPACE_SAVE_FAILED, sentMessage, submitAccessRequest, withRequestOutcome,
} from '../../../lib/confidential/requestSubmission';
import type { RequestOutcome } from '../../../lib/confidential/requestSubmission';

const record = { caseId: 'CASE', requestId: 'REQ', ownerPublicKey: 'KEY', summary: 'Summary', requestedAt: 1, expiresAt: 2 };

function deferred() {
  let resolve!: () => void, reject!: (error: unknown) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe('access request submission (sent only after delivery)', () => {
  it('reports nothing while delivery is in flight, then a single success', async () => {
    const events: string[] = [];
    const delivery = deferred();
    const pending = submitAccessRequest({
      caseId: 'CASE', kind: 'renewal',
      send: async beforeSend => { await beforeSend(record); events.push('sending'); await delivery.promise; },
      save: async () => { events.push('saved'); },
      describeFailure: (_caught, fallback) => fallback,
    }, {
      onRequested: request => events.push(`requested:${request.requestId}`),
      onDelivered: caseId => events.push(`delivered:${caseId}`),
      onOutcome: outcome => events.push(`outcome:${outcome.ok}`),
    });
    await new Promise(resolve => setTimeout(resolve, 0));
    // Saved in the shared list, but no caller has been told anything yet: the form stays open and busy.
    expect(events).toEqual(['saved', 'sending']);
    delivery.resolve();
    const outcome = await pending;
    expect(outcome).toEqual({ caseId: 'CASE', ok: true, message: sentMessage('renewal') });
    expect(events).toEqual(['saved', 'sending', 'requested:REQ', 'delivered:CASE', 'outcome:true']);
  });

  it('reports a delivery failure as a failure for that report (never as sent), after refreshing lists', async () => {
    const outcomes: RequestOutcome[] = [];
    const requested: string[] = [];
    const delivered = jest.fn();
    const outcome = await submitAccessRequest({
      caseId: 'CASE', kind: 'renewal',
      send: async beforeSend => { await beforeSend(record); throw new Error('network'); },
      save: async () => {}, describeFailure: (_caught, fallback) => fallback,
    }, { onRequested: request => requested.push(request.caseId), onDelivered: delivered, onOutcome: item => outcomes.push(item) });
    expect(outcome).toEqual({ caseId: 'CASE', ok: false, message: DELIVERY_UNCONFIRMED });
    expect(outcomes).toEqual([outcome]);
    expect(requested).toEqual(['CASE']);
    expect(delivered).not.toHaveBeenCalled();
  });

  it('does not send or refresh when the shared list cannot be saved', async () => {
    const sent = jest.fn(), requested = jest.fn();
    const outcome = await submitAccessRequest({
      caseId: 'CASE', kind: 'new',
      send: async beforeSend => { await beforeSend(record); sent(); },
      save: async () => { throw new Error('offline'); }, describeFailure: (_caught, fallback) => fallback,
    }, { onRequested: requested });
    expect(outcome).toEqual({ caseId: 'CASE', ok: false, message: WORKSPACE_SAVE_FAILED });
    expect(sent).not.toHaveBeenCalled();
    expect(requested).not.toHaveBeenCalled();
  });

  it('keeps failures per report until that report succeeds', () => {
    let failures: ReadonlyMap<string, string> = new Map();
    failures = withRequestOutcome(failures, { caseId: 'A', ok: false, message: 'failed A' });
    failures = withRequestOutcome(failures, { caseId: 'B', ok: false, message: 'failed B' });
    failures = withRequestOutcome(failures, { caseId: 'A', ok: true, message: 'sent' });
    expect([...failures]).toEqual([['B', 'failed B']]);
  });
});

describe('request form wiring', () => {
  const read = (path: string) => require('node:fs').readFileSync(require('node:path').join(__dirname, '../../..', path), 'utf8') as string;

  it('no caller closes a request form or shows "sent" from onRequested', () => {
    for (const path of ['components/vera/confidential/LegalReportView.tsx', 'pages/legal/index.tsx']) {
      const source = read(path);
      // onRequested only refreshes lists; closing happens on a successful outcome.
      expect(source).not.toMatch(/onRequested=\{[^}]*set(Asking|Open|Renewing|Sent)\(/);
      expect(source.match(/<RequestForm[\s\S]*?\/>/g)?.every(form => /onOutcome=\{outcome => \{ if \(outcome\.ok\)/.test(form))).toBe(true);
    }
  });

  it('shows a request failure next to the report as an alert', () => {
    expect(read('pages/legal/index.tsx')).toMatch(/function RequestFailure[\s\S]*?role="alert"/);
  });
});
