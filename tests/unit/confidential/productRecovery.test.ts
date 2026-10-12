import { recoveryLink, recoveryQrText, takeRecoveryLink } from '../../../lib/confidential/recoveryLink';
import { encodeQr } from '../../../lib/qrCode';
import { contactProblem, suppliedContacts } from '../../../lib/reportContacts';

test('QR link keeps the recovery code in a fragment and removes it before validation', () => {
  const code = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
  const url = new URL(recoveryLink('https://vera.example', code));
  expect(url.pathname).toBe('/status'); expect(url.search).toBe('');
  const routerState = { __N: true, key: 'k1', url: '/status', as: '/status' };
  const history = { state: routerState, replaceState: jest.fn() };
  expect(takeRecoveryLink(url, history)).toBe(code);
  // Next's router state on the entry survives; only the fragment is removed.
  expect(history.replaceState).toHaveBeenCalledWith(routerState, '', '/status');
  url.hash += '&recovery=duplicate';
  expect(takeRecoveryLink(url, history)).toBe('');
});
test('a recovery link is built only for an HTTPS origin, or HTTP on a local development host', () => {
  const code = '7K3M-9QXA-R2D8-WV4N-J6TC-P1HZ-5GBE-0SKY-M8FQ-3XAW-T7VN-2CJD-H9RB-4PZE';
  for (const origin of ['http://vera.example', 'http://example.test/status', 'http://10.0.0.5:3000', 'ftp://vera.example', 'not a url']) {
    expect(() => recoveryLink(origin, code)).toThrow('Invalid recovery link');
    expect(recoveryQrText(origin, code)).toEqual({ text: code, link: false });
  }
  for (const origin of ['https://vera.report/status', 'http://localhost:3000', 'http://127.0.0.1:3000', 'http://[::1]:3000']) {
    const qr = recoveryQrText(origin, code);
    expect(qr.link).toBe(true);
    expect(new URL(qr.text).hash).toBe(`#recovery=${code}`);
  }
});
test('a legacy code whose link would overflow the QR encoder prints the code itself', () => {
  const v1 = `VERA-OWNER-1.${'a'.repeat(64)}.${'b'.repeat(64)}.${'S'.repeat(43)}`;
  expect(v1.length).toBe(186);
  const link = recoveryLink('https://vera.report/status', v1);
  expect(() => encodeQr(link, 'M')).toThrow('Text is too long for a QR code');
  const qr = recoveryQrText('https://vera.report/status', v1);
  expect(qr).toEqual({ text: v1, link: false });
  expect(() => encodeQr(qr.text, 'M')).not.toThrow();
});
test('contact form requires one valid method and preserves all supplied methods', () => {
  expect(contactProblem({ email: '', signal: '', imessage: '' })).toBeTruthy();
  const contacts = { email: 'a@example.com', signal: '+1 555 555 0100', imessage: 'b@example.com' };
  expect(contactProblem(contacts)).toBeNull(); expect(suppliedContacts(contacts)).toEqual(contacts);
  expect(contactProblem({ ...contacts, imessage: 'invalid' })).toBeTruthy();
  // Phone-shaped values need real digits, not just allowed punctuation.
  for (const value of ['.......', '( ) - - -', '+  ....  ', '12-34-56']) {
    expect(contactProblem({ email: '', signal: value, imessage: '' })).toBeTruthy();
    expect(contactProblem({ email: '', signal: '', imessage: value })).toBeTruthy();
  }
  for (const value of ['+1 (555) 555-0100', '555.555.0100', '+447700900123', '5550100']) {
    expect(contactProblem({ email: '', signal: value, imessage: '' })).toBeNull();
    expect(contactProblem({ email: '', signal: '', imessage: value })).toBeNull();
  }
});
