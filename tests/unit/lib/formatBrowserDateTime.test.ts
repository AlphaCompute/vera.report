import { formatBrowserDateTime, getBrowserTimeZone } from '../../../lib/formatBrowserDateTime';

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const instant = '2026-07-15T12:00:00Z';
const options: Intl.DateTimeFormatOptions = {
  year: 'numeric', month: 'short', day: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short',
};

function browserZone(timeZone: string) {
  Object.defineProperty(globalThis, 'window', { value: {}, configurable: true });
  const resolved = new Intl.DateTimeFormat().resolvedOptions();
  jest.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockReturnValue({ ...resolved, timeZone });
}

afterEach(() => {
  jest.restoreAllMocks();
  if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow);
  else Reflect.deleteProperty(globalThis, 'window');
});

test.each(['Europe/Lisbon', 'Asia/Tokyo', 'America/New_York'])('uses browser timezone %s including daylight saving', zone => {
  browserZone(zone);
  expect(getBrowserTimeZone()).toBe(zone);
  expect(formatBrowserDateTime(instant)).toBe(new Date(instant).toLocaleString(undefined, { ...options, timeZone: zone }));
});

test.each(['', 'invalid-zone'])('falls back to fixed EST for missing or invalid timezone: %s', zone => {
  browserZone(zone);
  expect(formatBrowserDateTime(instant)).toBe(new Date(instant).toLocaleString(undefined, { ...options, timeZone: 'Etc/GMT+5' }));
});

test('uses EST when timezone detection throws', () => {
  browserZone('Europe/Lisbon');
  jest.spyOn(Intl.DateTimeFormat.prototype, 'resolvedOptions').mockImplementation(() => { throw new Error('unavailable'); });
  expect(getBrowserTimeZone()).toBe('Etc/GMT+5');
});

test('does not use the server timezone when no browser exists', () => {
  expect(getBrowserTimeZone()).toBe('Etc/GMT+5');
});

test.each([undefined, null, '', 'not a date'])('handles absent or invalid timestamps: %s', value => {
  expect(formatBrowserDateTime(value)).toBe('—');
});
