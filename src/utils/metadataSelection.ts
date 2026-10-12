/** Legacy selection maps cannot opt accepted image formats out of sanitization.
 * Parse only a small boolean map, and never expose JSON parser errors containing
 * reporter-controlled values in application logs or API responses. */
export function parseMetadataSelection(raw: unknown): Record<string, boolean> {
  if (raw === undefined || raw === '') return {};
  const invalid = () => new Error('stripSelection must be a JSON object of boolean values.');
  if (typeof raw !== 'string' || raw.length > 16_384) throw invalid();
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw invalid(); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
  const entries = Object.entries(value);
  if (entries.length > 128 || entries.some(([key, selected]) => key.length > 256 || typeof selected !== 'boolean')) throw invalid();
  return value as Record<string, boolean>;
}
