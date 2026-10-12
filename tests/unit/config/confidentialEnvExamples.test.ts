/**
 * The env example files are the operator's and local developer's list of what
 * confidential reports and legal organizations need. They must name every
 * setting the code reads, document the explicit legacy option, and, once
 * uncommented, satisfy the startup checks (confidentialServerConfigurationError).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { LEGACY_SECRET_VARIABLES, confidentialServerConfigurationError } from '../../../src/confidentialServer';
import { confidentialCasesConfigurationError } from '../../../src/utils/confidentialConfiguration';

const ROOT = join(__dirname, '../../..');
const read = (file: string) => readFileSync(join(ROOT, file), 'utf8');
const FILES = ['.env.example', '.env.frontend.example', '.env.backend.example'];
const CONFIDENTIAL_NAME = /^(?:CONFIDENTIAL_|NEXT_PUBLIC_CONFIDENTIAL_|NEXT_PUBLIC_LEGAL_AUTH0_|NEXT_PUBLIC_ONBOARDING_AUTH0_)/;

type Assignment = { name: string; value: string; commented: boolean };
function assignments(text: string): Assignment[] {
  return text.split('\n').flatMap(line => {
    const match = /^(#\s*)?([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    // A commented line is a disabled assignment only when its value has no spaces (not prose).
    if (!match || (match[1] && /\s/.test(match[3].trim()))) return [];
    return [{ name: match[2], value: match[3].trim(), commented: Boolean(match[1]) }];
  });
}
/** The "── Confidential ..." section, up to the next section header or EOF. */
function confidentialSection(text: string): Assignment[] {
  const lines = text.split('\n');
  const start = lines.findIndex(line => /^# ── Confidential/.test(line));
  expect(start).toBeGreaterThanOrEqual(0);
  const end = lines.findIndex((line, index) => index > start && /^# ── /.test(line));
  return assignments(lines.slice(start, end < 0 ? undefined : end).join('\n'));
}
const uncommented = (section: Assignment[]) => Object.fromEntries(section.map(({ name, value }) => [name, value]));
const active = (file: string) => Object.fromEntries(assignments(read(file)).filter(a => !a.commented).map(a => [a.name, a.value]));

/** Every confidential/legal variable the application reads from its environment. */
function variablesReadByCode(): string[] {
  const names = new Set<string>();
  const visit = (path: string) => {
    for (const entry of readdirSync(path)) {
      const full = join(path, entry);
      if (statSync(full).isDirectory()) { visit(full); continue; }
      if (!/\.(?:ts|tsx|js|cjs)$/.test(entry) || /\.test\./.test(entry)) continue;
      const source = readFileSync(full, 'utf8');
      for (const match of source.matchAll(/\benv\.([A-Z][A-Z0-9_]*)|\benv\[['"]([A-Z][A-Z0-9_]*)['"]\]|requireHeaderSecret\(['"]([A-Z0-9_]+)['"]/g)) {
        const name = match[1] ?? match[2] ?? match[3];
        if (CONFIDENTIAL_NAME.test(name)) names.add(name);
      }
    }
  };
  for (const dir of ['src', 'lib', 'pages', 'components']) visit(join(ROOT, dir));
  for (const source of [read('next.config.js')]) {
    for (const match of source.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)) if (CONFIDENTIAL_NAME.test(match[1])) names.add(match[1]);
  }
  return [...names].sort();
}

describe('confidential env examples', () => {
  const frontend = confidentialSection(read('.env.frontend.example'));
  const backend = confidentialSection(read('.env.backend.example'));
  const overview = confidentialSection(read('.env.example'));

  it('document every confidential and legal setting the code reads', () => {
    const names = variablesReadByCode();
    // Guard the scan itself: these are known reads.
    expect(names).toEqual(expect.arrayContaining(['CONFIDENTIAL_CASES_ENABLED', 'CONFIDENTIAL_ADMIN_SECRET',
      'CONFIDENTIAL_BACKEND_URL', 'CONFIDENTIAL_MONGODB_URI', 'NEXT_PUBLIC_CONFIDENTIAL_CASES', 'NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN']));
    const documented = new Set([...frontend, ...backend].map(a => a.name));
    expect(names.filter(name => !documented.has(name))).toEqual([]);
  });

  it('list the issue-named settings in the top-level example too', () => {
    const names = new Set(overview.map(a => a.name));
    for (const name of ['CONFIDENTIAL_CASES_ENABLED', 'CONFIDENTIAL_INTAKE_REQUIRED', 'CONFIDENTIAL_MONGODB_URI',
      'CONFIDENTIAL_MONGODB_DB_NAME', 'CONFIDENTIAL_ADMIN_SECRET', 'CONFIDENTIAL_BACKEND_URL', 'CONFIDENTIAL_RELEASE_MANIFEST_FILE',
      'CONFIDENTIAL_LEGAL_IDENTITY_FILE', 'NEXT_PUBLIC_CONFIDENTIAL_CASES', 'NEXT_PUBLIC_LEGAL_AUTH0_CLIENT_ID',
      'NEXT_PUBLIC_ONBOARDING_AUTH0_CLIENT_ID']) expect(names).toContain(name);
  });

  it('leave deployment settings commented and document the explicit legacy option', () => {
    for (const file of FILES) {
      expect(Object.keys(active(file)).filter(name => CONFIDENTIAL_NAME.test(name))).toEqual([]);
      for (const a of confidentialSection(read(file))) expect(a.commented).toBe(true);
    }
    // Operators can explicitly select legacy mode and keep the backend disabled.
    for (const section of [frontend, backend, overview]) {
      const values = uncommented(section);
      if ('CONFIDENTIAL_CASES_ENABLED' in values) expect(values.CONFIDENTIAL_CASES_ENABLED).toBe('false');
      if ('NEXT_PUBLIC_CONFIDENTIAL_CASES' in values) expect(values.NEXT_PUBLIC_CONFIDENTIAL_CASES).toBe('0');
    }
  });

  it('uncommented, the backend section satisfies the confidential-only task checks without legacy secrets', () => {
    const taskEnv: NodeJS.ProcessEnv = { ...uncommented(backend), RUN_MODE: 'confidential', CONFIDENTIAL_CASES_ENABLED: 'true', NODE_ENV: 'development' };
    expect(Object.keys(uncommented(backend)).filter(name => (LEGACY_SECRET_VARIABLES as readonly string[]).includes(name))).toEqual([]);
    expect(confidentialServerConfigurationError(taskEnv)).toBeUndefined();
    expect(taskEnv.CONFIDENTIAL_ADMIN_SECRET!.length).toBeGreaterThanOrEqual(32);
    // And the task cannot simply load the legacy backend file: it holds legacy secrets.
    expect(confidentialServerConfigurationError({ ...active('.env.backend.example'), ...taskEnv }))
      .toMatch(/^Legacy configuration must not reach the confidential-only process/);
  });

  it('name exactly the legacy secrets the task refuses', () => {
    const text = read('.env.backend.example');
    const listed = /NONE of the legacy\s*# secrets is present \(([^)]*)\)/.exec(text)?.[1];
    expect(listed).toBeDefined();
    const names = listed!.split(/[,\s#]+/).filter(Boolean);
    expect(names.sort()).toEqual([...LEGACY_SECRET_VARIABLES].sort());
  });

  it('use a confidential database name different from the legacy one', () => {
    const legacyDb = active('.env.backend.example').MONGODB_DB_NAME;
    for (const section of [backend, overview]) expect(uncommented(section).CONFIDENTIAL_MONGODB_DB_NAME).not.toBe(legacyDb);
    expect(active('.env.example').MONGODB_DB_NAME).toBe(legacyDb);
  });

  it('uncommented, the shared local layout passes the legacy API check', () => {
    const env = { ...active('.env.backend.example'), ...uncommented(backend), CONFIDENTIAL_CASES_ENABLED: 'true', NODE_ENV: 'development' };
    expect(confidentialCasesConfigurationError(env)).toBeUndefined();
  });

  it('pair the frontend admin secret with the backend one', () => {
    expect(uncommented(frontend)).toHaveProperty('CONFIDENTIAL_BACKEND_URL');
    expect(uncommented(frontend)).toHaveProperty('CONFIDENTIAL_ADMIN_SECRET');
    expect(read('.env.frontend.example')).toMatch(/at least 32 characters/);
  });
});
