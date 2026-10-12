import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { auth0 } from './lib/auth0';

const AUTH0_CONFIGURED =
    typeof process.env.AUTH0_DOMAIN === 'string' &&
    process.env.AUTH0_DOMAIN.length > 0 &&
    typeof process.env.APP_BASE_URL === 'string' &&
    process.env.APP_BASE_URL.length > 0;

export async function middleware(request: NextRequest) {
    if (request.nextUrl.pathname.startsWith('/auth/') && !AUTH0_CONFIGURED) {
        return NextResponse.json(
            { error: 'Auth0 not configured. Set AUTH0_DOMAIN, APP_BASE_URL, and other Auth0 env vars.' },
            { status: 503 }
        );
    }

    // Auth0 SDK v4 requires middleware on all routes that need session access
    return await auth0.middleware(request);
}

export const config = {
    matcher: ['/auth/:path*', '/api/admin/:path*'],
};
