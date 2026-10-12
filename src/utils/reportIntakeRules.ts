/**
 * Content rules the intake enforces on a report, shared by the HTTP route, the
 * website wizard and API so validation stays consistent.
 *
 * The server route is the enforcement point; the wizard applies the same rules
 * only so the reporter finds out before losing a step, never instead.
 */

/**
 * Today in UTC as `YYYY-MM-DD`, the latest incident date the intake accepts.
 *
 * UTC rather than the server's local zone: a reporter west of UTC can sit on
 * yesterday's date while the server has already rolled over, and rejecting
 * their own "today" reads as a broken form. Erring a few hours late costs
 * nothing; the rule is here to catch 2099, not to police the boundary.
 */
export function maxIncidentDate(now: Date = new Date()): string {
    return now.toISOString().slice(0, 10);
}

/**
 * True when `value` names a day after today (UTC).
 *
 * Anything this cannot parse as a date is left alone — the field is free text
 * up to 100 characters and historical reports have used prose, so
 * this must not turn an unparseable entry into a rejection.
 */
export function isFutureIncidentDate(value: string, now: Date = new Date()): boolean {
    const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value.trim());
    if (!match) return false;
    const [, year, month, day] = match;
    const parsed = Date.UTC(Number(year), Number(month) - 1, Number(day));
    if (Number.isNaN(parsed)) return false;
    const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    return parsed > today;
}

/** Validate the website's optional, inclusive incident range. */
export function incidentDateRangeError(start: string, end: string, now: Date = new Date()): string | null {
    if (!start && !end) return null;
    if (!start || !end) return 'Choose both a start date and an end date, or leave both blank.';
    const validDay = (value: string): boolean => {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
        const parsed = new Date(`${value}T00:00:00.000Z`);
        return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
    };
    if (!validDay(start) || !validDay(end)) return 'Enter valid start and end dates.';
    if (start > end) return 'End date must be on or after the start date.';
    if (isFutureIncidentDate(start, now) || isFutureIncidentDate(end, now)) return 'Incident dates cannot be in the future.';
    return null;
}

/** Keep the existing text field compatible with historical single dates and bot prose. */
export function incidentTimeframeError(value: string, now: Date = new Date()): string | null {
    const range = /^(\d{4}-\d{2}-\d{2})\s+to(?:\s+(.*))?$/.exec(value.trim());
    if (range) return incidentDateRangeError(range[1], range[2] || '', now);
    return isFutureIncidentDate(value, now) ? 'Date of incident cannot be in the future.' : null;
}

export function formatIncidentRange(start: string, end: string): string {
    return start && end ? `${start} to ${end}` : '';
}
