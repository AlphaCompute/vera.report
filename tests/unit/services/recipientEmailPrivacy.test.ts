jest.mock('@aws-sdk/client-sesv2', () => ({
  SESv2Client: jest.fn(),
  SendEmailCommand: jest.fn().mockImplementation(input => ({ input })),
}));
jest.mock('../../../src/utils/logger', () => ({
  logger: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
}));
import { EmailNotificationService } from '../../../src/services/emailNotification';
import { logger } from '../../../src/utils/logger';

const recipient = 'private-recipient-sentinel@example.invalid';
const subject = 'Private subject sentinel';
const body = '<a href="https://example.invalid/secret-capability-sentinel">Private body sentinel</a>';
const replyTo = 'private-reply-sentinel@example.invalid';
const sentinels = [recipient, subject, body, replyTo, 'secret-capability-sentinel', 'provider-detail-sentinel'];

function setup() {
  const service = new EmailNotificationService();
  jest.spyOn(service as any, 'initialise').mockReturnValue(true);
  jest.spyOn(service as any, 'deployEnvLabel').mockReturnValue('staging');
  const send = jest.fn().mockResolvedValue({});
  (service as any).sesClient = { send };
  (service as any).senderEmail = 'approved-sender@example.invalid';
  return { service, send };
}
function expectPrivateLogs() {
  const logged = JSON.stringify(Object.values(logger).flatMap(fn => (fn as jest.Mock).mock.calls));
  for (const sentinel of sentinels) expect(logged).not.toContain(sentinel);
}

beforeEach(() => jest.clearAllMocks());

test('provider acceptance preserves the intended message while logging only a fixed operational event', async () => {
  const { service, send } = setup();
  await expect(service.sendToRecipient(recipient, subject, body, replyTo)).resolves.toEqual({ sent: true });
  expect(send).toHaveBeenCalledTimes(1);
  expect(send.mock.calls[0][0].input).toMatchObject({
    Destination: { ToAddresses: [recipient] }, ReplyToAddresses: [replyTo],
    Content: { Simple: { Subject: { Data: '[VERA staging] ' + subject }, Body: { Html: { Data: body } } } },
  });
  expect(logger.info).toHaveBeenCalledWith('[EMAIL] Direct message accepted by provider');
  expectPrivateLogs();
});

test.each(['error', 'object', 'string'])('provider rejection as %s cannot expose recipients, subjects, capabilities or response text', async kind => {
  const { service, send } = setup();
  const detail = sentinels.join(' ');
  const error = kind === 'error' ? new Error(detail) : kind === 'object' ? { message: detail, response: body } : detail;
  send.mockRejectedValue(error);
  const result = await service.sendToRecipient(recipient, subject, body, replyTo);
  expect(result).toEqual({ sent: false, error: 'provider_failed' });
  expect(send).toHaveBeenCalledTimes(1);
  expect(logger.error).toHaveBeenCalledWith('[EMAIL] Direct message delivery failed');
  expect(logger.info).not.toHaveBeenCalled();
  expectPrivateLogs();
});

test('missing sender configuration remains a safe no-send failure', async () => {
  const { service, send } = setup();
  (service as any).initialise.mockReturnValue(false);
  await expect(service.sendToRecipient(recipient, subject, body)).resolves.toEqual({
    sent: false, error: 'SES not configured (SES_SENDER_EMAIL missing)',
  });
  expect(send).not.toHaveBeenCalled();
  expectPrivateLogs();
});
