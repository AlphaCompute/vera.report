// Preloaded only by the local browser harness, including Next's child workers.
// Exercise real server authorization against synthetic provider responses.
if (process.env.AUTH0_DOMAIN !== 'synthetic.invalid' || process.env.AUTH0_MGMT_CLIENT_SECRET !== 'synthetic-browser-test') {
  throw new Error('The admin browser provider fixture requires synthetic credentials');
}
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, options) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  // Signed Slack callback fixture: never let the browser suite send a real Slack request.
  if (url.origin === 'https://hooks.slack.com') {
    if (url.href === 'https://hooks.slack.com/actions/TTEST/TEST/SYNTHETIC' && options?.method === 'POST') return new Response('ok');
    throw new Error('Unexpected Slack request in synthetic browser fixture');
  }
  if (url.origin !== 'https://synthetic.invalid') return originalFetch(input, options);
  const method = options?.method || (input instanceof Request ? input.method : 'GET');
  if (url.pathname === '/oauth/token' && method === 'POST') {
    return Response.json({ access_token: 'synthetic-provider-token', expires_in: 3600, token_type: 'Bearer' });
  }
  const headers = new Headers(options?.headers || (input instanceof Request ? input.headers : undefined));
  if (headers.get('authorization') !== 'Bearer synthetic-provider-token') {
    return Response.json({ error: 'Unauthorized synthetic request' }, { status: 401 });
  }
  if (url.pathname === '/api/v2/users/synthetic-admin' && method === 'GET') {
    return Response.json({ user_id: 'synthetic-admin', email: 'qa@example.org', email_verified: true, blocked: false });
  }
  if (url.pathname === '/api/v2/users/synthetic-admin/roles' && method === 'GET') {
    return Response.json([{ name: 'admin' }]);
  }
  throw new Error(`Unexpected synthetic provider request: ${method} ${url.pathname}`);
};
