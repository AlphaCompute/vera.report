import { BEFORE_PRIVATE_DOCUMENT_NAVIGATION } from '@/lib/useReceiptNavigationGuard';
import { installBrowserTelemetry } from '../lib/browserTelemetry';
import type { AppProps } from 'next/app';
import { useEffect, memo } from 'react';
import dynamic from 'next/dynamic';
import { useRouter } from 'next/router';
import { Auth0Provider } from '@auth0/nextjs-auth0/client';
import { Toaster } from '@/components/ui/sonner';
import { requiresDocumentNavigation } from '../lib/privatePageHeaders';
import '../styles/globals.css';

const FaultyTerminal = dynamic(() => import('@/components/ui/FaultyTerminal'), {
    ssr: false,
    loading: () => <div className="fixed inset-0 bg-[#0a0a0b]" />,
});

const PersistentBackground = memo(function PersistentBackground() {
    return (
        <div className="fixed inset-0 -z-20 overflow-hidden">
            <FaultyTerminal
                scale={1.5}
                gridMul={[2, 1]}
                digitSize={1.2}
                timeScale={0.5}
                scanlineIntensity={0.5}
                glitchAmount={1}
                flickerAmount={1}
                noiseAmp={1}
                curvature={0.1}
                tint="#0a1628"
                mouseReact
                mouseStrength={0.5}
                pageLoadAnimation
                brightness={0.6}
            />
        </div>
    );
});

// These pages paint over the whole background, so the WebGL animation is never
// seen there, yet it renders every frame and slows the in-browser encryption on
// devices without a strong GPU (a staging submit went from 33 s to 3 s without it).
const OPAQUE_PAGES = /^\/(?:$|report(?:\/|$)|status(?:\/|$)|legal(?:\/|$)|terms$|privacy$)/;
const opaquePage = (pathname: string) => OPAQUE_PAGES.test(pathname);

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter();
  useEffect(() => installBrowserTelemetry(), []);

  // Private pages (/report, /status, /legal) get their CSP and headers only on a
  // document load; a client-side transition would keep the current page's
  // weaker headers. Load a fresh document when entering one of those families.
  useEffect(() => {
    const enterPrivateDocument = (url: string) => {
      if (requiresDocumentNavigation(window.location.pathname, url)) {
        const allowed = window.dispatchEvent(new CustomEvent(BEFORE_PRIVATE_DOCUMENT_NAVIGATION, {
          cancelable: true, detail: { url },
        }));
        if (allowed) window.location.assign(url);
        // Abort the soft transition synchronously: the destination must never
        // mount under the previous document's weaker CSP while navigation waits.
        const cancelled = Object.assign(new Error('Document navigation required'), { cancelled: true });
        router.events.emit('routeChangeError', cancelled, url, { shallow: false });
        throw cancelled;
      }
    };
    router.events.on('routeChangeStart', enterPrivateDocument);
    return () => router.events.off('routeChangeStart', enterPrivateDocument);
  }, [router.events]);

  useEffect(() => {
    // Light mode primary — ensure no dark class on load
    if (typeof document !== 'undefined') {
      document.documentElement.classList.remove('dark');
    }
  }, []);


  return (
    <Auth0Provider>
      {!opaquePage(router.pathname) && <PersistentBackground />}
      <Toaster />
      <Component {...pageProps} />
    </Auth0Provider>
  );
}
