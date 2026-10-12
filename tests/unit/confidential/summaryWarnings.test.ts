import { findIdentifyingDetails, SUMMARY_WARNING_ADVICE } from '../../../lib/confidential/summaryWarnings';
import { SUMMARY_EXAMPLES } from '../../../lib/confidential/summaryGuidance';

const kinds = (text: string) => findIdentifyingDetails(text).map(item => [item.kind, item.text]);

describe('on-device summary warnings', () => {
  test('flags each kind of identifying detail', () => {
    expect(kinds('Email me at jane.doe@example.org')).toEqual([['email', 'jane.doe@example.org']]);
    expect(kinds('Call 419-555-0144 or (212) 555 0199 or +44 20 7946 0958')).toEqual([
      ['phone', '419-555-0144'], ['phone', '(212) 555 0199'], ['phone', '+44 20 7946 0958']]);
    expect(kinds('Waste is dumped behind 1200 Riverside Drive every week')).toEqual([['address', '1200 Riverside Drive']]);
    expect(kinds('Send it to PO Box 88 or Suite 400, Dayton OH 45402')).toEqual([
      ['address', 'PO Box 88'], ['address', 'Suite 400'], ['address', 'OH 45402']]);
    expect(kinds('It happened on March 4, 2024, again on 06/12/2023, on 2023-01-09 and on 3rd of May')).toEqual([
      ['date', 'March 4, 2024'], ['date', '06/12/2023'], ['date', '2023-01-09'], ['date', '3rd of May']]);
    expect(kinds('Acme Capital LLC and Northside Clinic moved funds through PayCorp')).toEqual([
      ['company', 'Acme Capital LLC'], ['company', 'Northside Clinic'], ['company', 'PayCorp']]);
    expect(kinds('My manager Tom Reed and Dr. Alvarez approved it')).toEqual([['name', 'Tom Reed'], ['name', 'Dr. Alvarez']]);
    expect(kinds('I told my supervisor Priya about it')).toEqual([['name', 'Priya']]);
  });

  test('does not flag broad, non-identifying wording', () => {
    for (const text of [
      'A healthcare provider billed a federal program for visits that did not happen, over about a year.',
      'Between 2019-2021 an investment firm hid losses. In March the United States regulator was not told.',
      'Last March the Chief Financial Officer of a large company approved it. About 20 people may know.',
      'Several managers at a manufacturing site ignored safety rules. Seeking Legal Review.',
      'It involves about $250,000 and 40 employees in New York City.',
    ]) expect(findIdentifyingDetails(text)).toEqual([]);
  });

  test('reports each detail once, in reading order, without overlaps, and is bounded', () => {
    const text = 'Tom Reed at 12 Oak Street. Tom Reed again at tom@example.com and tom@example.com.';
    expect(kinds(text)).toEqual([['name', 'Tom Reed'], ['address', '12 Oak Street'], ['email', 'tom@example.com']]);
    const many = Array.from({ length: 40 }, (_, index) => `user${index}@example.com`).join(' ');
    expect(findIdentifyingDetails(many)).toHaveLength(12);
    expect(findIdentifyingDetails('')).toEqual([]);
    expect(findIdentifyingDetails('   ')).toEqual([]);
  });

  test('every kind has advice', () => {
    for (const kind of ['name', 'email', 'phone', 'company', 'date', 'address'] as const) {
      expect(SUMMARY_WARNING_ADVICE[kind].label).toBeTruthy();
      expect(SUMMARY_WARNING_ADVICE[kind].advice).toBeTruthy();
    }
  });

  test('the good examples pass the checks and every bad example is caught', () => {
    expect(SUMMARY_EXAMPLES).toHaveLength(3);
    for (const example of SUMMARY_EXAMPLES) {
      expect(findIdentifyingDetails(example.good)).toEqual([]);
      expect(findIdentifyingDetails(example.bad).length).toBeGreaterThan(0);
      expect(example.good.length).toBeLessThanOrEqual(600);
    }
  });
});
