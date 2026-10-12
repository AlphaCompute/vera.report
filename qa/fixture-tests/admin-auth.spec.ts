import { test, expect } from '@playwright/test';
import { createServer } from 'node:http';
import { type AddressInfo } from 'node:net';
import { loginAsAdminViaUniversalLogin } from '../support/admin-auth';

const previous = { email: process.env.QA_ADMIN_EMAIL, password: process.env.QA_ADMIN_PASSWORD };
test.beforeEach(() => {
  process.env.QA_ADMIN_EMAIL = 'synthetic@example.test';
  process.env.QA_ADMIN_PASSWORD = 'synthetic-password';
});
test.afterEach(() => {
  for (const [key, value] of [['QA_ADMIN_EMAIL', previous.email], ['QA_ADMIN_PASSWORD', previous.password]]) {
    if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
  }
});

for (const scenario of ['direct', 'consent', 'denied-api', 'wrong-origin', 'string-role', 'wrong-role', 'wrong-account'] as const) {
  test(`fresh login: ${scenario}`, async ({ page }) => {
    const visited: string[] = [];
    let baseURL: string;
    const server = createServer((request, response) => {
      const url = new URL(request.url!, baseURL);
      visited.push(url.pathname);
      if (url.pathname === '/api/admin/me') {
        response.writeHead(scenario === 'denied-api' ? 403 : 200, { 'content-type': 'application/json' });
        response.end(JSON.stringify({
          email: scenario === 'wrong-account' ? 'another@example.test' : 'synthetic@example.test',
          roles: scenario === 'string-role' ? 'not-admin' : scenario === 'wrong-role' ? ['viewer'] : ['admin'],
        }));
        return;
      }
      response.setHeader('content-type', 'text/html');
      if (url.pathname === '/auth/login') {
        response.end('<form action="/password"><input name="username"><button>Continue</button></form>');
      } else if (url.pathname === '/password') {
        const next = scenario === 'consent' ? '/consent' : scenario === 'wrong-origin' ? `${baseURL.replace('127.0.0.1', 'localhost')}/legal/organizations` : '/legal/organizations';
        response.end(`<form action="${next}"><input type="password" name="password"><button>Log in</button></form>`);
      } else if (url.pathname === '/consent') {
        response.end('<form action="/legal/organizations"><button>Authorize</button></form>');
      } else {
        response.end('Synthetic admin page');
      }
    });
    await new Promise<void>(resolve => server.listen(0, resolve));
    baseURL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      if (['denied-api', 'wrong-origin', 'string-role', 'wrong-role', 'wrong-account'].includes(scenario)) {
        await expect(loginAsAdminViaUniversalLogin(page, baseURL)).rejects.toThrow();
        if (scenario === 'wrong-origin') expect(visited).not.toContain('/api/admin/me');
        else expect(visited).toContain('/api/admin/me');
      } else {
        await loginAsAdminViaUniversalLogin(page, baseURL);
        expect(visited).toContain('/password');
        expect(visited).toContain('/api/admin/me');
        if (scenario === 'consent') expect(visited).toContain('/consent');
        expect(new URL(page.url()).origin).toBe(baseURL);
      }
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });
}

test('missing credentials fail rather than skip', async ({ page, baseURL }) => {
  delete process.env.QA_ADMIN_PASSWORD;
  await expect(loginAsAdminViaUniversalLogin(page, baseURL!)).rejects.toThrow('are required');
  expect(page.url()).toBe('about:blank');
});
