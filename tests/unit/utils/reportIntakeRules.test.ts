/**
 * Unit tests for the shared intake date rule (#853).
 *
 * There was no rule at all: an incident date of 2099-12-31 was stored verbatim
 * and shown back to reviewers as a fact about the case.
 */
import { isFutureIncidentDate, maxIncidentDate, incidentDateRangeError, incidentTimeframeError, formatIncidentRange } from '../../../src/utils/reportIntakeRules';

const NOW = new Date('2026-09-18T12:00:00.000Z');

describe('isFutureIncidentDate', () => {
    it('rejects a date after today', () => {
        expect(isFutureIncidentDate('2099-12-31', NOW)).toBe(true);
        expect(isFutureIncidentDate('2026-09-19', NOW)).toBe(true);
    });

    it('accepts today and any past date', () => {
        expect(isFutureIncidentDate('2026-09-18', NOW)).toBe(false);
        expect(isFutureIncidentDate('2026-09-17', NOW)).toBe(false);
        expect(isFutureIncidentDate('1998-01-01', NOW)).toBe(false);
    });

    it('compares whole days in UTC, so a mid-day "now" does not reject today', () => {
        expect(isFutureIncidentDate('2026-09-18', new Date('2026-09-18T00:00:01.000Z'))).toBe(false);
        expect(isFutureIncidentDate('2026-09-18', new Date('2026-09-18T23:59:59.000Z'))).toBe(false);
    });

    it('leaves anything it cannot parse alone', () => {
        // The field is free text up to 100 characters and historical reports have used
        // prose through it; an unparseable entry must not become a rejection.
        expect(isFutureIncidentDate('sometime last spring', NOW)).toBe(false);
        expect(isFutureIncidentDate('', NOW)).toBe(false);
        expect(isFutureIncidentDate('not a date', NOW)).toBe(false);
    });

    it('tolerates surrounding whitespace', () => {
        expect(isFutureIncidentDate('  2099-01-01  ', NOW)).toBe(true);
    });
});

describe('maxIncidentDate', () => {
    it('is today in UTC, in the format the date input expects', () => {
        expect(maxIncidentDate(NOW)).toBe('2026-09-18');
    });

    it('never advertises a bound the validator would reject', () => {
        expect(isFutureIncidentDate(maxIncidentDate(NOW), NOW)).toBe(false);
    });
});


describe('incident date ranges', () => {
    it.each([['', ''], ['2026-09-01', '2026-09-18'], ['2026-09-18', '2026-09-18']])('accepts optional, historical and same-day ranges', (start, end) => {
        expect(incidentDateRangeError(start, end, NOW)).toBeNull();
    });
    it.each([
        ['2026-09-01', ''], ['', '2026-09-01'], ['2026-09-18', '2026-09-01'],
        ['2026-09-01', '2099-01-01'], ['2026-02-30', '2026-03-01'], ['invalid', '2026-09-18'],
    ])('rejects incomplete, reversed, future and invalid ranges', (start, end) => {
        expect(incidentDateRangeError(start, end, NOW)).not.toBeNull();
    });
    it('serializes both dates for storage and validates both at intake', () => {
        expect(formatIncidentRange('2026-09-01', '2026-09-18')).toBe('2026-09-01 to 2026-09-18');
        expect(incidentTimeframeError('2026-09-01 to 2026-09-18', NOW)).toBeNull();
        expect(incidentTimeframeError('2026-09-01 to 2099-01-01', NOW)).not.toBeNull();
        expect(incidentTimeframeError('2026-09-18 to 2026-09-01', NOW)).not.toBeNull();
        expect(incidentTimeframeError('2026-09-18 to ', NOW)).not.toBeNull();
    });
    it('preserves historical single dates and descriptive bot entries', () => {
        expect(incidentTimeframeError('2026-09-01', NOW)).toBeNull();
        expect(incidentTimeframeError('last spring', NOW)).toBeNull();
    });
});
