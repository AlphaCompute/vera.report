import Document, { Html, Head, Main, NextScript, DocumentContext, DocumentInitialProps } from 'next/document';
import crypto from 'node:crypto';
import { PRIVATE_PAGE_HEADERS } from '../lib/privatePageHeaders';
import { isStrictPage, strictPageHeaders } from '@/lib/confidential/strictPageHeaders';

export default class VeraDocument extends Document<DocumentInitialProps & { nonce?: string }> {
  static async getInitialProps(ctx: DocumentContext) {
    const props = await Document.getInitialProps(ctx);
    if (!ctx.req || !ctx.res || !isStrictPage(ctx.req.url)) return props;
    const nonce = crypto.randomBytes(24).toString('base64');
    const headers = strictPageHeaders(ctx.req.url, nonce, process.env.NODE_ENV !== 'production',
      [process.env.NEXT_PUBLIC_LEGAL_AUTH0_DOMAIN, process.env.NEXT_PUBLIC_ONBOARDING_AUTH0_DOMAIN]);
    for (const [name, value] of Object.entries(headers)) ctx.res.setHeader(name, value);
    // Private-page headers beyond the CSP: nosniff, no framing, noindex, COOP, permissions.
    for (const [key, value] of Object.entries(PRIVATE_PAGE_HEADERS)) ctx.res.setHeader(key, value);
    return { ...props, nonce };
  }
  render() {
    return <Html lang="en">
      <Head nonce={this.props.nonce}>
        {this.props.__NEXT_DATA__.page === '/' && <>
          <style>{`[data-site-loader]:not([data-hydrated]){display:none}html[data-vera-intro-pending] [data-site-loader]{display:flex}html[data-vera-intro-pending] [data-homepage]{visibility:hidden}html[data-vera-intro-pending] body{overflow:hidden}`}</style>
          {/* A failed bundle must reveal the public page; late hydration must not replay the intro. */}
          <script dangerouslySetInnerHTML={{ __html: `document.documentElement.setAttribute('data-vera-intro-pending','');setTimeout(function(){if(document.documentElement.hasAttribute('data-vera-intro-pending')){if(!location.hash)window.scrollTo({top:0,behavior:'instant'});document.documentElement.removeAttribute('data-vera-intro-pending')}},5000);` }} />
        </>}
        <meta name="referrer" content="no-referrer" />
        <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <link rel="shortcut icon" href="/favicon.ico" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/site.webmanifest" />
        <meta name="theme-color" content="#FAFAF9" />
      </Head>
      <body style={{ backgroundColor: '#FAFAF9' }}><Main /><NextScript nonce={this.props.nonce} /></body>
    </Html>;
  }
}
