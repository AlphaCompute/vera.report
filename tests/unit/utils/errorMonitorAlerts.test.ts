import { ErrorMonitor } from '../../../src/utils/errorMonitor';

jest.mock('../../../src/services/submissionWebhook', () => ({ notifyOperationalEvent: jest.fn() }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { notifyErrorThreshold: jest.fn() } }));
jest.mock('../../../src/utils/logger', () => ({ logger: { warn: jest.fn(), info: jest.fn() } }));

const START = new Date('2026-10-02T12:00:00Z').getTime();
let consoleError: jest.SpyInstance;

function alerts(type = 'HIGH_ERROR_RATE'): any[] {
  return consoleError.mock.calls
    .filter(([line]) => line === `🚨 [ALERT] ${type}`)
    .map(([, data]) => data);
}

function requests(monitor: ErrorMonitor, count: number): void {
  for (let i = 0; i < count; i++) monitor.recordRequest();
}

beforeEach(() => {
  jest.useFakeTimers({ now: START });
  consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
  jest.clearAllMocks();
});

describe('HIGH_ERROR_RATE', () => {
  it('does not alert on a single error with no traffic', () => {
    const monitor = new ErrorMonitor();
    monitor.logError('one error');
    expect(alerts()).toHaveLength(0);
  });

  it('does not alert on 1 error in 3 requests, below the minimum sample', () => {
    const monitor = new ErrorMonitor();
    requests(monitor, 3);
    monitor.logError('one error');
    expect(alerts()).toHaveLength(0);
  });

  it('alerts when more than 10% of at least 20 requests in the window error', () => {
    const monitor = new ErrorMonitor();
    // 8 requests and 1 error every minute: 12.5%, never more than one error a minute.
    for (let minute = 0; minute < 5; minute++) {
      requests(monitor, 8);
      monitor.logError('sustained error');
      if (minute < 4) jest.advanceTimersByTime(60_000);
    }
    // Minutes 0 and 1 have only 8 and 16 requests; from minute 2 the sample is
    // large enough, and the alert repeats once per cooldown while it persists.
    expect(alerts()).toHaveLength(3);
    expect(alerts()[0]).toMatchObject({ reason: 'ratio', requests: 24, totalErrors: 3, errorRatio: '0.125' });
  });

  it('does not alert at exactly 10% or below', () => {
    const monitor = new ErrorMonitor();
    for (let minute = 0; minute < 5; minute++) {
      requests(monitor, 10);
      monitor.logError('sustained error');
      if (minute < 4) jest.advanceTimersByTime(60_000);
    }
    expect(alerts()).toHaveLength(0);
  });

  it('only counts requests inside the window', () => {
    const monitor = new ErrorMonitor();
    requests(monitor, 40);
    // Requests are counted in one-second buckets.
    jest.advanceTimersByTime(301_000);
    requests(monitor, 3);
    for (let i = 0; i < 5; i++) monitor.logError('error after traffic aged out');
    expect(alerts()).toHaveLength(0);
  });

  it('alerts on a burst of 10 errors in a minute even with no traffic', () => {
    const monitor = new ErrorMonitor();
    for (let i = 0; i < 9; i++) {
      monitor.logError('burst error');
      jest.advanceTimersByTime(5_000);
    }
    expect(alerts()).toHaveLength(0);
    monitor.logError('burst error');
    expect(alerts()).toHaveLength(1);
    expect(alerts()[0]).toMatchObject({ reason: 'burst', lastMinuteErrors: 10, requests: 0 });
  });

  it('does not treat errors spread over the window as a burst', () => {
    const monitor = new ErrorMonitor();
    // 2 errors a minute for five minutes: the old rule alerted on the first one.
    for (let i = 0; i < 10; i++) {
      monitor.logError('steady error');
      jest.advanceTimersByTime(30_000);
    }
    expect(alerts()).toHaveLength(0);
  });

  it('keeps the one-minute cooldown between alerts', () => {
    const monitor = new ErrorMonitor();
    for (let i = 0; i < 10; i++) monitor.logError('burst error');
    expect(alerts()).toHaveLength(1);
    jest.advanceTimersByTime(30_000);
    for (let i = 0; i < 10; i++) monitor.logError('burst error');
    expect(alerts()).toHaveLength(1);
    jest.advanceTimersByTime(30_000);
    monitor.logError('burst error');
    expect(alerts()).toHaveLength(2);
  });

  it('counts requests through the middleware, excluding load balancer health checks', () => {
    const monitor = new ErrorMonitor();
    const middleware = monitor.middleware();
    const next = jest.fn();
    for (let i = 0; i < 50; i++) middleware({ method: 'GET', originalUrl: '/health' }, {}, next);
    for (let i = 0; i < 19; i++) middleware({ method: 'GET', originalUrl: '/api/stats?x=1' }, {}, next);
    expect(next).toHaveBeenCalledTimes(69);
    const req: any = { method: 'GET', originalUrl: '/api/stats' };
    middleware(req, { statusCode: 500 }, next);
    req.logError('failed');
    req.logError('failed');
    req.logError('failed');
    // 3 errors in 20 counted requests is 15%; counting the 50 probes would make it 4%.
    expect(alerts()).toHaveLength(1);
    expect(alerts()[0]).toMatchObject({ reason: 'ratio', requests: 20 });
  });
});

it('still raises the critical threshold alert independently', () => {
  const monitor = new ErrorMonitor();
  for (let i = 0; i < 5; i++) monitor.logError('critical error', 'critical');
  expect(alerts('CRITICAL_ERROR_THRESHOLD')).toHaveLength(1);
  expect(alerts()).toHaveLength(0);
});
