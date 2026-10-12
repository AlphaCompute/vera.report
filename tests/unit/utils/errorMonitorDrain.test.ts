import { ErrorMonitor } from '../../../src/utils/errorMonitor';
import { notifyOperationalEvent } from '../../../src/services/submissionWebhook';
import { emailNotificationService } from '../../../src/services/emailNotification';
import { logger } from '../../../src/utils/logger';

jest.mock('../../../src/services/submissionWebhook', () => ({ notifyOperationalEvent: jest.fn() }));
jest.mock('../../../src/services/emailNotification', () => ({ emailNotificationService: { notifyErrorThreshold: jest.fn() } }));
jest.mock('../../../src/utils/logger', () => ({ logger: { warn: jest.fn(), info: jest.fn() } }));

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

afterEach(() => { jest.restoreAllMocks(); jest.clearAllMocks(); });

it.each([false, true])('drains both accepted attempts, including rejection=%s, and closes admission', async fails => {
  jest.spyOn(console, 'error').mockImplementation(() => {});
  const webhook = deferred();
  const email = deferred();
  (notifyOperationalEvent as jest.Mock).mockReturnValue(webhook.promise);
  (emailNotificationService.notifyErrorThreshold as jest.Mock).mockReturnValue(email.promise);
  const monitor = new ErrorMonitor();
  // A burst of ten errors in a minute is the smallest input that alerts.
  for (let i = 0; i < 10; i++) monitor.logError('synthetic error');
  let closed = false;
  const closing = monitor.close();
  expect(monitor.close()).toBe(closing);
  void closing.then(() => { closed = true; });
  await new Promise(resolve => setImmediate(resolve));
  expect(notifyOperationalEvent).toHaveBeenCalledTimes(1);
  expect(emailNotificationService.notifyErrorThreshold).toHaveBeenCalledTimes(1);
  expect(closed).toBe(false);
  if (fails) webhook.reject(new Error('private provider details'));
  else webhook.resolve();
  await new Promise(resolve => setImmediate(resolve));
  expect(closed).toBe(false);
  email.resolve();
  await closing;
  expect(closed).toBe(true);
  for (let i = 0; i < 5; i++) monitor.logError('post-close error', 'critical');
  await new Promise(resolve => setImmediate(resolve));
  expect(notifyOperationalEvent).toHaveBeenCalledTimes(1);
  expect(emailNotificationService.notifyErrorThreshold).toHaveBeenCalledTimes(1);
  if (fails) expect(logger.warn).toHaveBeenCalledWith('[ERROR_MONITOR] Alert notification failed');
});
