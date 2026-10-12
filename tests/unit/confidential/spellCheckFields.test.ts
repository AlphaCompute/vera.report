import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * Chrome Enhanced spell check and Edge's Microsoft Editor send the contents of
 * spell-checked fields to a cloud service. Every free-text field on the
 * confidential pages must opt out, so a new field cannot regress this. Password
 * fields are never spell-checked by browsers, and choice inputs hold no text.
 * Public organization profile fields are listed
 * explicitly below.
 */
const ROOT = path.resolve(__dirname, '../../..');
const DIRECTORIES = ['components/vera/confidential', 'pages/legal'];
const NON_TEXT_TYPES = new Set(['checkbox', 'radio', 'file', 'hidden', 'submit', 'button', 'password']);
const PUBLIC_FIELDS = [
  // Public jurisdiction in the organization's signed profile.
  { file: 'components/vera/confidential/FirmOnboarding.tsx', marker: 'value={draft.jurisdiction}' },
];

const sources = (dir: string): string[] => readdirSync(path.join(ROOT, dir)).flatMap(name => {
  const relative = path.join(dir, name);
  if (statSync(path.join(ROOT, relative)).isDirectory()) return sources(relative);
  return /\.tsx$/.test(name) ? [relative] : [];
});

/** Returns each JSX <input>/<textarea> opening tag, skipping `>` inside braces and `=>`. */
const fieldTags = (source: string) => {
  const tags: { tag: string; line: number }[] = [];
  for (const match of source.matchAll(/<(textarea|input)\b/g)) {
    let depth = 0;
    let end = match.index! + match[0].length;
    for (; end < source.length; end++) {
      const char = source[end];
      if (char === '{') depth++;
      else if (char === '}') depth--;
      else if (char === '>' && depth === 0 && source[end - 1] !== '=') break;
    }
    tags.push({ tag: source.slice(match.index, end + 1), line: source.slice(0, match.index).split('\n').length });
  }
  return tags;
};

describe('confidential free-text fields', () => {
  const files = DIRECTORIES.flatMap(sources);

  test('the scan finds the confidential forms', () => {
    expect(files).toEqual(expect.arrayContaining([
      path.join('components/vera/confidential', 'FirmRequests.tsx'),
      path.join('components/vera/confidential', 'SummaryComposer.tsx'),
      path.join('pages/legal', 'join.tsx'),
    ]));
  });

  test('every text field opts out of browser spell check, except listed public profile fields', () => {
    const missing: string[] = [];
    let checked = 0;
    for (const file of files) {
      for (const { tag, line } of fieldTags(readFileSync(path.join(ROOT, file), 'utf8'))) {
        const type = tag.match(/\btype=["'{]["']?(\w+)/)?.[1] ?? 'text';
        if (tag.startsWith('<input') && NON_TEXT_TYPES.has(type)) continue;
        if (PUBLIC_FIELDS.some(field => path.normalize(field.file) === file && tag.includes(field.marker))) continue;
        checked++;
        if (!tag.includes('spellCheck={false}')) missing.push(`${file}:${line}`);
      }
    }
    expect(checked).toBeGreaterThan(5);
    expect(missing).toEqual([]);
  });

  test('the public profile allowlist still points at real fields', () => {
    for (const field of PUBLIC_FIELDS) expect(readFileSync(path.join(ROOT, field.file), 'utf8')).toContain(field.marker);
  });
});
