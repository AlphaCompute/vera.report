/** US-only MVP intake choices; historical jurisdictions remain valid in stored reports. */
export const JURISDICTION_CHOICES = [
    { value: 'us', label: 'United States' },
];
export const URGENCY_CHOICES = ['low', 'medium', 'high', 'critical'].map((value) => ({
    value,
    label: value[0].toUpperCase() + value.slice(1),
}));
