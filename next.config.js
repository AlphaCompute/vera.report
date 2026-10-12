const { legalPortalHeaderRules } = require('./lib/privatePageHeaders');

// Refuse an enabled build without a release. Runtime participant verification
// validates canonical bytes, measurement pins and owner approval before sending.
if (process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '0' &&
    !process.env.NEXT_PUBLIC_CONFIDENTIAL_RELEASE_MANIFEST?.trim()) {
  throw new Error('Confidential frontend requires a release manifest');
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  // The development badge can cover mobile controls during browser tests.
  devIndicators: process.env.CI ? false : undefined,
  poweredByHeader: false, // don't advertise x-powered-by: Next.js (#454)

  // Expected wrong-recipient failures must not become a development overlay.
  // Keep normal app errors and all OpenPGP verification failures intact.
  webpack(config, { dev, isServer }) {
    if (dev && !isServer) config.module.rules.push({
      test: /[\\/]node_modules[\\/]openpgp[\\/]dist[\\/]openpgp(?:\.min)?\.m?js$/,
      use: [require.resolve('./scripts/loaders/openpgp-browser-debug.cjs')],
    });
    return config;
  },
  turbopack: {
    rules: {
      'openpgp*.mjs': {
        condition: { all: ['development', 'browser', { path: /node_modules\/openpgp\/dist\/openpgp(?:\.min)?\.mjs$/ }] },
        loaders: [require.resolve('./scripts/loaders/openpgp-browser-debug.cjs')],
      },
    },
  },

  // Proxy API calls to Express backend in development only
  async rewrites() {
    if (process.env.NODE_ENV === 'production') {
      return [];
    }
    // Development only. The local browser test stack (qa/e2e) runs the
    // confidential-only API on a free loopback port and has no legacy backend:
    // send only /api/confidential there and let every other /api path reach the
    // Next routes, as in production (where no rewrite exists at all).
    const confidentialOrigin = process.env.VERA_DEV_CONFIDENTIAL_API_ORIGIN || '';
    if (/^http:\/\/(?:localhost|127\.0\.0\.1):\d{2,5}$/.test(confidentialOrigin)) {
      return [{ source: '/api/confidential/:path*', destination: `${confidentialOrigin}/api/confidential/:path*` }];
    }
    if (process.env.NEXT_PUBLIC_CONFIDENTIAL_CASES !== '0') {
      const backend = process.env.CONFIDENTIAL_BACKEND_URL || process.env.BACKEND_URL || 'http://localhost:3001';
      // Keep the legacy submit route in Next so it rejects plaintext before forwarding.
      return [{ source: '/api/confidential/:path*', destination: `${backend}/api/confidential/:path*` }];
    }
    return [
      {
        source: '/api/:path((?!eliza|debug-eliza|auth|admin|whistleblower/evidence|whistleblower/reward-contact).*)',
        destination: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/:path*`,
      },
    ];
  },

  // Same-origin framing policy for the website.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          // Framing is controlled by the CSP frame-ancestors below. X-Frame-Options
          // No blanket `Access-Control-Allow-Origin: *`: the frontend is same-origin
          // with its API, so cross-origin reads are not granted by default.
          {
            key: 'Content-Security-Policy',
            value: "frame-ancestors 'self'",
          },
          // Never let a browser sniff a response into an executable type.
          { key: 'X-Content-Type-Options', value: 'nosniff' },
        ],
      },
      // Private legal portal: private-page headers (no referrer, private no-store,
      // noindex), so report and invitation URLs do not leak via Referer and report
      // pages are not cached. Its strict nonce CSP is set per request in
      // pages/_document.tsx, replacing the site-wide one.
      ...legalPortalHeaderRules(process.env.NODE_ENV !== 'production'),
    ];
  },

  // Environment variables
  env: {
    NEXT_PUBLIC_APP_URL: 'https://vera.report',
  },
};

module.exports = nextConfig;
