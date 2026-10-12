import type { NextApiRequest, NextApiResponse } from 'next';
import {
    currentAdminAuthorization,
    invalidateAdminAuthorization,
    ADMIN_AUTHORIZATION_TTL_MS,
} from '../../../lib/currentAdminAuthorization';
import { clearTokenCache } from '../../../lib/auth0Management';
import { withRoleAuth } from '../../../lib/authMiddleware';

const mockSession = {
    user: {
        sub: 'auth0|synthetic',
        email: 'admin@example.org',
        email_verified: true,
        org_id: 'org_test',
        'https://vera.app/roles': ['admin'],
    },
};
jest.mock('../../../lib/auth0', () => ({
    auth0: {
        getSession: async () => mockSession,
        withApiAuthRequired: (handler: unknown) => handler,
    },
}));

const originalEnv = { ...process.env };
const originalFetch = global.fetch;
let now: number;
let providerUser: Record<string, unknown>;
let providerRoles: string[];
let providerStatus: number;
let membershipStatus: number;

beforeEach(() => {
    process.env = {
        ...originalEnv,
        AUTH0_DOMAIN: 'synthetic.auth0.com',
        AUTH0_MGMT_CLIENT_ID: 'synthetic-client',
        AUTH0_MGMT_CLIENT_SECRET: 'synthetic-secret',
        TENANT_ORG_ID: 'org_test',
    };
    delete process.env.AUTH0_ORG_SCOPED_ADMIN;
    invalidateAdminAuthorization();
    clearTokenCache();
    now = Date.now();
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    providerUser = {
        user_id: mockSession.user.sub,
        email: mockSession.user.email,
        email_verified: true,
        blocked: false,
    };
    providerRoles = ['admin'];
    providerStatus = 200;
    membershipStatus = 200;
    global.fetch = jest.fn(async (input) => {
        const url = new URL(String(input));
        if (url.pathname === '/oauth/token')
            return new Response(JSON.stringify({ access_token: 'synthetic-token', expires_in: 3600 }));
        if (providerStatus !== 200) return new Response('{}', { status: providerStatus });
        if (url.pathname === '/api/v2/users/auth0%7Csynthetic') return new Response(JSON.stringify(providerUser));
        if (url.pathname === '/api/v2/organizations/org_test/members/auth0%7Csynthetic/roles')
            return new Response(JSON.stringify(providerRoles.map((name) => ({ name }))), { status: membershipStatus });
        throw new Error('Unexpected authorization endpoint');
    });
});
afterEach(() => {
    invalidateAdminAuthorization();
    clearTokenCache();
    jest.restoreAllMocks();
    global.fetch = originalFetch;
    process.env = { ...originalEnv };
});

async function call() {
    const handler = jest.fn();
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis(), setHeader: jest.fn() };
    await withRoleAuth('admin', handler)({} as NextApiRequest, res as unknown as NextApiResponse);
    return { handler, res };
}

it.each(['role', 'blocked', 'deleted', 'email', 'unverified'])(
    'rejects %s revocation while the old session cookie remains valid',
    async (change) => {
        expect((await call()).handler).toHaveBeenCalledTimes(1);
        if (change === 'role') providerRoles = [];
        if (change === 'blocked') providerUser.blocked = true;
        if (change === 'deleted') providerStatus = 404;
        if (change === 'email') providerUser.email = 'outside@example.invalid';
        if (change === 'unverified') providerUser.email_verified = false;
        now += ADMIN_AUTHORIZATION_TTL_MS + 1;
        const denied = await call();
        expect(denied.res.status).toHaveBeenCalledWith(403);
        expect(denied.handler).not.toHaveBeenCalled();
    },
);

it('fails closed after cache expiry on provider outage without reusing cookie roles', async () => {
    expect((await call()).handler).toHaveBeenCalled();
    providerStatus = 503;
    now += ADMIN_AUTHORIZATION_TTL_MS + 1;
    const denied = await call();
    expect(denied.res.status).toHaveBeenCalledWith(503);
    expect(denied.res.setHeader).toHaveBeenCalledWith('Retry-After', '30');
    expect(denied.handler).not.toHaveBeenCalled();
});

it('does not refresh the authorization lifetime when the dashboard polls', async () => {
    await call();
    const calls = jest.mocked(global.fetch).mock.calls.length;
    for (let i = 0; i < 2; i++) {
        now += 10_000;
        await call();
    }
    expect(jest.mocked(global.fetch).mock.calls).toHaveLength(calls);
    providerRoles = ['employee'];
    now += 10_001;
    expect((await call()).handler).not.toHaveBeenCalled();
});

it('invalidates a cached user immediately for local account mutations', async () => {
    await call();
    providerRoles = [];
    invalidateAdminAuthorization(mockSession.user.sub);
    expect((await call()).handler).not.toHaveBeenCalled();
});

it('coalesces simultaneous checks without using tenant-global roles', async () => {
    const checks = await Promise.all(Array.from({ length: 8 }, () => currentAdminAuthorization(mockSession.user)));
    expect(checks.every((check) => check?.roles.includes('admin'))).toBe(true);
    expect(jest.mocked(global.fetch).mock.calls).toHaveLength(3);
});

it('never falls back to global roles when organization scoping is disabled', async () => {
    process.env.AUTH0_ORG_SCOPED_ADMIN = 'false';
    expect((await call()).handler).not.toHaveBeenCalled();
    expect(global.fetch).not.toHaveBeenCalled();
});

it('denies a removed organization member even when the user profile and cookie survive', async () => {
    await call();
    membershipStatus = 404;
    now += ADMIN_AUTHORIZATION_TTL_MS + 1;
    const denied = await call();
    expect(denied.handler).not.toHaveBeenCalled();
    expect(denied.res.status).toHaveBeenCalledWith(503);
});

it('does not accept a provider result that arrives after its authorization window', async () => {
    const fetchProvider = jest.mocked(global.fetch).getMockImplementation()!;
    jest.mocked(global.fetch).mockImplementation(async (input, init) => {
        const result = await fetchProvider(input, init);
        if (String(input).includes('/users/')) now += ADMIN_AUTHORIZATION_TTL_MS + 1;
        return result;
    });
    await expect(currentAdminAuthorization(mockSession.user)).rejects.toThrow('Current authorization unavailable');
});
