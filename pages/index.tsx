import { EntrySequence } from '@/components/vera/EntrySequence';
import { PolicyDialog } from '@/components/vera/PolicyDialog';
import { SiteLoader } from '@/components/vera/SiteLoader';
import { ArrowRight, ContactRound, Eye, FileLock2, ImageOff, KeyRound, Laptop, Search } from 'lucide-react';
import { motion, useScroll, useTransform, type MotionValue } from 'motion/react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react';
import { VeraReportLogo } from '../components/vera/VeraReportLogo';
import { RisingEdgeMarks } from '../components/vera/RisingEdgeMarks';
import edgeStyles from '../components/vera/RisingEdgeMarks.module.css';
import { usePrefersReducedMotion } from '../hooks/usePrefersReducedMotion';
import { confidentialCasesEnabled } from '@/lib/confidential/config';
import { entryCopy } from '@/lib/confidential/entryCopy';
import styles from '../styles/Homepage.module.css';

// Keep the legacy build's privacy disclosures separate from confidential intake.
const CONFIDENTIAL = confidentialCasesEnabled();
const COPY = entryCopy(confidentialCasesEnabled());
const FEATURES = [
    {
        icon: FileLock2,
        title: 'Encrypted before you send',
        text: 'Your browser encrypts your full report, your evidence, and your contact details on your device. VERA receives them only in encrypted form.',
    },
    {
        icon: KeyRound,
        title: 'Only you give access',
        text: 'A legal organization cannot read your private report until you give it access. An access request does not give access. You also select which evidence it can see.',
    },
    {
        icon: ContactRound,
        title: 'Your contact details stay separate',
        text: 'Access to your report does not give access to your contact details. You decide whether to share them with an organization, and you can stop that access later. VERA cannot take back details an organization has already seen.',
    },
];
const CHECKS = [
    {
        icon: Eye,
        title: 'Keep your summary general.',
        text: 'Your summary is unencrypted and visible on Vera to approved legal organizations, even before you give access.',
    },
    {
        icon: ImageOff,
        title: 'Remove hidden details from your files.',
        text: 'Examples are photo location and document author. VERA does not remove them for you.',
    },
    {
        icon: Search,
        title: 'Read your report as a stranger would.',
        text: 'Leave out details that only you know, if you do not want to be identified.',
    },
    {
        icon: Laptop,
        title: 'Use your own device.',
        text: "Use a personal phone or computer, not a work device, and avoid your employer's Wifi or VPN. Use a contact method that is not related to your job.",
    },
];
const SPECS = [
    [
        'Service check',
        'Your browser checks the VERA service before establishing its confidential connection. If verification fails, it does not switch to sending private contents unencrypted.',
    ],
    ['Separate keys', 'Each private part of your report has its own random 256-bit content key.'],
    ['File details', 'File names, file types, and exact file sizes are encrypted.'],
    ['Change detection', 'Signatures and SHA-256 hashes detect changes to stored data.'],
    ['Release approval', 'A new backend release needs your approval to process your report’s protected data.'],
    ['Recovery code', 'Your browser makes the code from a random 256-bit secret. VERA does not receive the secret.'],
];
const FAQS = [
    [
        'Who can read my report?',
        'You can read your report with your recovery credentials. Legal organizations can read the parts you give them access to. An access request does not give access. VERA and legal organizations on VERA can see your short summary.',
    ],
    [
        'Can an organization find out who I am?',
        'Access to your report does not give access to your contact details. Your report and your evidence can still identify you, so check them before you send.',
    ],
    [
        'What if I lose my recovery code?',
        'VERA cannot reset it. Save your recovery code or download the recovery file, and keep it in a safe place. Without a saved recovery method or saved device access, you lose access to your report.',
    ],
    [
        'Do I need an account?',
        'No. You report from your browser. You must add one or more contact methods, and your browser encrypts them.',
    ],
    [
        'Can I close my report?',
        'Yes. Closing hides your summary from the directory and stops organizational access through VERA. You can still open your report with your recovery code. Closing does not delete it or recall copies already shared. VERA cannot remove copies that an organization already has.',
    ],
];

function EdgeTicks({ white = false }: { white?: boolean }) {
    return (
        <div
            aria-hidden="true"
            className={edgeStyles.staticMarks + ' ' + styles.edgeTicks}
            style={{ color: white ? '#fff' : '#000' }}
        >
            <span />
            <span />
        </div>
    );
}

// Preserve the original scroll-driven stripe transition and reduced-motion fallback.
const STRIPE_ROWS = [
    { y: 72.6719, width: 8.25 },
    { y: 63.6817, width: 7.5 },
    { y: 54.6914, width: 6.75 },
    { y: 45.7012, width: 6 },
    { y: 36.711, width: 5.25 },
    { y: 27.7207, width: 4.5 },
    { y: 18.7305, width: 3 },
    { y: 9.7403, width: 2.25 },
    { y: 0.75, width: 1.5 },
];
function StripeRow({
    y,
    width,
    progress,
    flip,
}: {
    y: number;
    width: number;
    progress: MotionValue<number>;
    flip: boolean;
}) {
    const offsetY = useTransform(progress, (p) => (72.6719 - y) * (flip ? p : 1 - p));
    return (
        <motion.path
            d={'M0 ' + y + 'L1728 ' + y}
            stroke="black"
            strokeWidth={width}
            strokeMiterlimit="10"
            style={{ y: offsetY }}
        />
    );
}
function StripeDivider({ reducedMotion, flip = false }: { reducedMotion: boolean; flip?: boolean }) {
    const containerRef = useRef<HTMLDivElement>(null);
    const { scrollYProgress } = useScroll({
        target: containerRef,
        offset: flip ? ['start 0.6', 'start 0.05'] : ['start end', 'start 0.35'],
    });
    return (
        <div
            ref={containerRef}
            aria-hidden="true"
            data-edge-pattern=""
            className={styles.stripes + (flip ? ' ' + styles.stripesDown : '')}
        >
            <svg viewBox="0 0 1728 76.7969" preserveAspectRatio="none" fill="none">
                {STRIPE_ROWS.map((row) =>
                    reducedMotion ? (
                        <path
                            key={row.width}
                            d={'M0 ' + row.y + 'L1728 ' + row.y}
                            stroke="black"
                            strokeWidth={row.width}
                            strokeMiterlimit="10"
                        />
                    ) : (
                        <StripeRow key={row.width} {...row} progress={scrollYProgress} flip={flip} />
                    ),
                )}
            </svg>
        </div>
    );
}

function ReportActions({
    heroAction,
    closingAction,
}: {
    heroAction: RefObject<HTMLAnchorElement | null>;
    closingAction: RefObject<HTMLAnchorElement | null>;
}) {
    const reducedMotion = usePrefersReducedMotion();
    const [atHeroActions, setAtHeroActions] = useState(true);
    const [atClosingActions, setAtClosingActions] = useState(false);
    const [focused, setFocused] = useState(false);
    useEffect(() => {
        const update = () => {
            // The hero already shows both actions, so the dock waits until they scroll away.
            setAtHeroActions(!!heroAction.current && heroAction.current.getBoundingClientRect().bottom > 0);
            // Check position even when a jump skips over the closing buttons entirely.
            setAtClosingActions(!!closingAction.current && closingAction.current.getBoundingClientRect().top < window.innerHeight - 96);
        };
        update();
        window.addEventListener('scroll', update, { passive: true });
        window.addEventListener('resize', update);
        return () => {
            window.removeEventListener('scroll', update);
            window.removeEventListener('resize', update);
        };
    }, [heroAction, closingAction]);
    const hidden = (atHeroActions || atClosingActions) && !focused;
    return (
        <motion.nav aria-label="Primary" className={styles.reportActions} data-hidden={hidden}
            inert={hidden} aria-hidden={hidden ? true : undefined}
            initial={false} animate={{ opacity: hidden ? 0 : 1, y: hidden ? 24 : 0 }}
            transition={{ duration: reducedMotion ? 0 : 0.35, ease: [0.22, 1, 0.36, 1] }}
            onFocusCapture={() => setFocused(true)}
            onBlurCapture={event => { if (!event.currentTarget.contains(event.relatedTarget)) setFocused(false); }}>
            <a href="/report">Start a report</a>
            <a href="/status">Open your report</a>
        </motion.nav>
    );
}

// The loader reveals the hero, unless the URL targets a section of the page.
function resetScroll() {
    if (!location.hash) window.scrollTo({ top: 0, behavior: 'instant' });
}

export default function Landing() {
    const reducedMotion = usePrefersReducedMotion();
    const heroAction = useRef<HTMLAnchorElement>(null);
    const closingAction = useRef<HTMLAnchorElement>(null);
    const router = useRouter();
    const [loading, setLoading] = useState(router.pathname === '/');
    const [hydrated, setHydrated] = useState(false);
    useEffect(() => {
        setHydrated(true);
        const pending = router.pathname === '/' && document.documentElement.hasAttribute('data-vera-intro-pending');
        setLoading(pending);
        if (!pending) return;
        const restoration = history.scrollRestoration;
        history.scrollRestoration = 'manual';
        resetScroll();
        return () => { history.scrollRestoration = restoration; };
    }, [router.pathname]);
    useLayoutEffect(() => {
        if (!loading || !hydrated) return;
        document.documentElement.removeAttribute('data-vera-intro-pending');
        const overflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        return () => { document.body.style.overflow = overflow; };
    }, [loading, hydrated]);
    return (
        <EntrySequence homepage fallbackFocusRef={closingAction}>
            <Head>
                <title>{`VERA Report | ${CONFIDENTIAL ? 'Confidential whistleblower reporting' : 'Whistleblower reporting'}`}</title>
                <meta name="description" content={COPY.metaDescription} />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
            </Head>
            <noscript><style>{'[data-site-loader]{display:none}'}</style></noscript>
            {loading && <SiteLoader hydrated={hydrated} onHide={resetScroll} onComplete={() => setLoading(false)} />}
            <div data-homepage className={styles.page} inert={loading && hydrated} aria-hidden={loading && hydrated ? true : undefined}>
                <a className={styles.skip} href="#main-content">
                    Skip to main content
                </a>
                <RisingEdgeMarks />
                <ReportActions heroAction={heroAction} closingAction={closingAction} />
                <main id="main-content">
                    <section className={styles.hero} data-edge-tone="black" aria-labelledby="hero-title">
                        <header className={styles.top}>
                            <a href="/" aria-label="VERA Report home" className={styles.logo}>
                                <VeraReportLogo style={{ width: '100%', height: 'auto' }} />
                            </a>
                        </header>
                        <div className={styles.heroContent}>
                            <p className={styles.badge}>
                                {CONFIDENTIAL ? 'Confidential whistleblower reporting' : 'Whistleblower reporting'}
                            </p>
                            <h1 id="hero-title">
                                {CONFIDENTIAL ? (
                                    <>
                                        <span>Say what you saw.</span>
                                        <span>Keep the key.</span>
                                    </>
                                ) : (
                                    <>
                                        <span>Report what</span>
                                        <span>happened.</span>
                                    </>
                                )}
                            </h1>
                            <p className={styles.byline}>
                                {CONFIDENTIAL
                                    ? 'A way to report fraud and misconduct. Your browser encrypts your full report before upload. Legal organizations can open it only with your permission.'
                                    : COPY.heroFollow}
                            </p>
                            <a className={styles.cta} href="/report">
                                Start a report <ArrowRight size={22} aria-hidden="true" />
                            </a>
                            <p className={styles.micro}>No account. Nothing to download. Guided step by step.</p>
                            <div className={styles.returning}>
                                <p>Already sent a report?</p>
                                <a ref={heroAction} className={styles.ghost} href="/status">
                                    Open your report
                                </a>
                            </div>
                        </div>
                        <EdgeTicks />
                        <StripeDivider reducedMotion={reducedMotion} />
                    </section>

                    <section
                        className={styles.ink + ' ' + styles.handles}
                        data-edge-tone="white"
                        aria-labelledby="handles-title"
                    >
                        <div className={styles.wrap}>
                            <h2 id="handles-title">How VERA handles your report</h2>
                            <p>
                                {CONFIDENTIAL
                                    ? 'You report fraud or misconduct from your browser, without an account. Your full report is encrypted before it leaves your device. You decide which legal organizations can read it.'
                                    : COPY.handlingReview}
                            </p>
                        </div>
                        <EdgeTicks white />
                    </section>
                    <StripeDivider reducedMotion={reducedMotion} flip />

                    <section className={styles.cards} data-edge-tone="black" aria-label="How your report is protected">
                        <div className={styles.wrap + ' ' + styles.grid}>
                            {CONFIDENTIAL
                                ? FEATURES.map(({ icon: Icon, title, text }) => (
                                      <article className={styles.card} key={title}>
                                          <div className={styles.icon} aria-hidden="true">
                                              <Icon />
                                          </div>
                                          <h3>{title}</h3>
                                          <p>{text}</p>
                                      </article>
                                  ))
                                : COPY.features.map((feature) => (
                                      <article className={styles.card} key={feature.title}>
                                          <div className={styles.icon} aria-hidden="true">
                                              <img src={feature.icon} alt="" />
                                          </div>
                                          <h3>{feature.title}</h3>
                                          <p>{feature.desc}</p>
                                      </article>
                                  ))}
                        </div>
                    </section>

                    {CONFIDENTIAL && (
                        <>
                            <section className={styles.section} data-edge-tone="black" aria-labelledby="flow-title">
                                <div className={styles.wrap}>
                                    <div className={styles.head}>
                                        <h2 id="flow-title">What happens when you report</h2>
                                        <p>You can do every step in your browser.</p>
                                    </div>
                                    <div className={styles.flow}>
                                        <div className={styles.stage}>
                                            <h3>You write it.</h3>
                                            <p>
                                                Describe the fraud or misconduct that you saw, and attach your evidence.
                                                It is not necessary to create an account or install an app.
                                            </p>
                                        </div>
                                        <div className={styles.stage}>
                                            <h3>Your browser locks it.</h3>
                                            <p>
                                                Your browser encrypts your full report, your evidence, and your contact
                                                details. Then it gives you a recovery code. VERA does not receive the
                                                code and cannot reset it.
                                            </p>
                                        </div>
                                        <div className={styles.stage}>
                                            <h3>You decide who opens it.</h3>
                                            <p>
                                                Give a legal organization access to your report, to selected evidence,
                                                or to both. Select 30 days, 90 days, one year, or until you stop it.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </section>

                            <section
                                className={styles.section + ' ' + styles.band}
                                data-edge-tone="black"
                                aria-labelledby="band-title"
                            >
                                <div className={styles.wrap + ' ' + styles.split}>
                                    <h2 id="band-title">
                                        <span>Change your mind.</span>
                                        <span>Change their access.</span>
                                    </h2>
                                    <div className={styles.body}>
                                        <p>You can stop an organization’s access to your report through VERA.</p>
                                        <p className={styles.quiet}>
                                            VERA cannot remove copies that the organization already has.
                                        </p>
                                        <p>You can add evidence later and decide which organizations can see it.</p>
                                    </div>
                                </div>
                            </section>

                            <section
                                className={styles.section + ' ' + styles.protect}
                                data-edge-tone="black"
                                aria-labelledby="protect-title"
                            >
                                <div className={styles.wrap + ' ' + styles.split}>
                                    <div className={styles.intro}>
                                        <h2 id="protect-title">Protect yourself before you send</h2>
                                        <p className={styles.lede}>
                                            Encryption protects your report. A few checks can help protect you.
                                        </p>
                                    </div>
                                    <ul className={styles.checks}>
                                        {CHECKS.map(({ icon: Icon, title, text }) => (
                                            <li key={title}>
                                                <div className={styles.icon} aria-hidden="true">
                                                    <Icon />
                                                </div>
                                                <div>
                                                    <h3>{title}</h3>
                                                    <p>{text}</p>
                                                </div>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            </section>
                        </>
                    )}

                    <StripeDivider reducedMotion={reducedMotion} />
                    <div className={styles.ink} data-edge-tone="white">
                        {CONFIDENTIAL && (
                            <>
                                <section className={styles.tech} aria-labelledby="tech-title">
                                    <div className={styles.wrap}>
                                        <div className={styles.head}>
                                            <h2 id="tech-title">Checked. Signed. Encrypted.</h2>
                                            <p>These are the technical facts behind your protection.</p>
                                        </div>
                                        <dl className={styles.specs}>
                                            {SPECS.map(([title, text]) => (
                                                <div key={title}>
                                                    <dt>{title}</dt>
                                                    <dd>{text}</dd>
                                                </div>
                                            ))}
                                        </dl>
                                    </div>
                                    <EdgeTicks white />
                                </section>

                                <section className={styles.faqSection} aria-labelledby="faq-title">
                                    <div className={styles.wrap}>
                                        <div className={styles.head}>
                                            <h2 id="faq-title">Straight answers</h2>
                                        </div>
                                        <div className={styles.faq}>
                                            {FAQS.map(([question, answer]) => (
                                                <details key={question}>
                                                    <summary>{question}</summary>
                                                    <p>{answer}</p>
                                                </details>
                                            ))}
                                        </div>
                                    </div>
                                </section>
                            </>
                        )}

                        <section className={styles.close} aria-labelledby="close-title">
                            <div className={styles.wrap}>
                                <h2 id="close-title">
                                    {CONFIDENTIAL ? (
                                        <>
                                            <span>Your report.</span>
                                            <span>Your key.</span>
                                            <span>Your call.</span>
                                        </>
                                    ) : (
                                        'Ready to file a report?'
                                    )}
                                </h2>
                                <p className={styles.byline}>
                                    {CONFIDENTIAL ? (
                                        'Report fraud or misconduct from your browser. An account is not necessary.'
                                    ) : (
                                        <>
                                            {COPY.ctaReview} {COPY.ctaKeep}
                                        </>
                                    )}
                                </p>
                                <a ref={closingAction} className={styles.cta} href="/report">
                                    Start a report <ArrowRight size={22} aria-hidden="true" />
                                </a>
                                <div className={styles.returning}>
                                    <p>Already sent a report?</p>
                                    <a className={styles.ghost} href="/status">
                                        Open your report
                                    </a>
                                </div>
                            </div>
                        </section>
                    </div>
                </main>

                <footer className={styles.ink + ' ' + styles.footer} data-edge-tone="white">
                    <div className={styles.footerTop}>
                        <a href="/" aria-label="VERA Report home" className={styles.logo}>
                            <VeraReportLogo style={{ width: '100%', height: 'auto' }} />
                        </a>
                        <p>© 2026 Vera Report</p>
                    </div>
                    <div className={styles.empowered}>
                        <p>Empowered by</p>
                        <a href="https://alphacompute.ai" target="_blank" rel="noreferrer noopener">
                            <img src="/redesign/alpha-compute-logo.svg" alt="Alpha Compute" />
                        </a>
                    </div>
                    <div className={styles.footerLegal}>
                        <p>
                            VERA is not a law firm and does not give legal advice. A VERA report is not a complaint or
                            tip filed with any government agency. If a deadline or your legal rights matter to you,
                            speak with a lawyer or the relevant agency promptly.
                        </p>
                        <nav aria-label="Legal">
                            <PolicyDialog policy="terms">Terms of Service</PolicyDialog>
                            <span aria-hidden="true">|</span>
                            <PolicyDialog policy="privacy">Privacy Notice</PolicyDialog>
                        </nav>
                    </div>
                    <EdgeTicks white />
                </footer>
            </div>
        </EntrySequence>
    );
}
