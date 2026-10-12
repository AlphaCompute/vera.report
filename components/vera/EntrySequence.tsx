import * as Dialog from '@radix-ui/react-dialog';
import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';
import { confidentialCasesEnabled } from '@/lib/confidential/config';
import { entryCopy } from '@/lib/confidential/entryCopy';
import styles from './EntrySequence.module.css';
import { PolicyDialog } from './PolicyDialog';

type Stage = 'welcome' | 'before' | 'ready';

// Build-time flag, so server and client render the same copy.
const COPY = entryCopy(confidentialCasesEnabled());

type ReportingAuthority = { label: string; href: string; reward?: boolean };

const RESOURCES: ReportingAuthority[] = [
    { label: 'OSHA · whistleblower retaliation', href: 'https://www.whistleblowers.gov/' },
    {
        label: 'SEC · securities',
        href: 'https://www.sec.gov/enforcement-litigation/whistleblower-program',
        reward: true,
    },
    { label: 'OSC · federal employees', href: 'https://www.osc.gov/' },
    { label: 'EEOC · discrimination / retaliation', href: 'https://www.eeoc.gov/filing-charge-discrimination' },
    {
        label: 'CFTC · commodities / crypto',
        href: 'https://www.cftc.gov/LearnAndProtect/whistlebloweralerts',
        reward: true,
    },
    { label: 'IRS · tax fraud', href: 'https://www.irs.gov/compliance/whistleblower-office', reward: true },
    { label: 'DOJ · government fraud / FCA', href: 'https://www.justice.gov/civil/report-fraud', reward: true },
    { label: 'DOJ · antitrust / cartels', href: 'https://www.justice.gov/atr/whistleblower-rewards', reward: true },
];
const MORE_RESOURCES: ReportingAuthority[] = [
    { label: 'FinCEN · money laundering / sanctions', href: 'https://www.fincen.gov/whistleblower-program' },
    {
        label: 'NHTSA · vehicle safety',
        href: 'https://www.nhtsa.gov/laws-regulations/whistleblower-program',
        reward: true,
    },
    { label: 'HHS OIG · healthcare / Medicare / Medicaid', href: 'https://oig.hhs.gov/fraud/report-fraud/' },
    { label: 'GAO FraudNet · federal funds / waste / abuse', href: 'https://www.gao.gov/about/what-gao-does/fraud' },
    { label: 'Inspectors General · agency fraud / misconduct', href: 'https://www.oversight.gov/hotline' },
    { label: 'EPA · environmental violations', href: 'https://www.epa.gov/report-violation' },
    { label: 'DOT OIG · transportation', href: 'https://www.oig.dot.gov/hotline' },
    { label: 'CPSC · consumer-product safety', href: 'https://www.saferproducts.gov/' },
];

function AuthorityLinks({ authorities }: { authorities: ReportingAuthority[] }) {
    return (
        <div className={styles.resourceLinks}>
            {authorities.map(({ label, href, reward }) => (
                <a key={href} href={href} target="_blank" rel="noopener noreferrer">
                    <span className={styles.resourceName}>
                        {label}
                        {reward && <span className={styles.rewardBadge}>$ REWARD PROGRAM</span>}
                    </span>
                    <span aria-hidden="true">↗</span>
                    <span className="sr-only"> (opens in a new tab)</span>
                </a>
            ))}
        </div>
    );
}

/** Introduction after a homepage reporting action. Continue loads a private document. */
export function EntrySequence({ homepage, children, fallbackFocusRef }: {
    homepage: boolean;
    children: ReactNode;
    fallbackFocusRef?: RefObject<HTMLElement | null>;
}) {
    const [stage, setStage] = useState<Stage>('ready');
    const [sensitiveConsent, setSensitiveConsent] = useState(false);
    const [atEnd, setAtEnd] = useState(false);
    const [scrollThumb, setScrollThumb] = useState({ height: 100, top: 0 });
    const headingRef = useRef<HTMLHeadingElement>(null);
    const readingRef = useRef<HTMLDivElement>(null);
    const dialogOpen = stage === 'welcome' || stage === 'before';

    const triggerRef = useRef<HTMLElement | null>(null);
    useEffect(() => {
        if (!homepage) {
            setStage('ready');
            return;
        }
        const open = (event: MouseEvent) => {
            // Leave new-tab and other modified clicks to the browser.
            if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
            const link = (event.target as Element)?.closest<HTMLAnchorElement>('a[href]');
            if (!link) return;
            const url = new URL(link.href, window.location.href);
            if (url.origin !== window.location.origin || url.pathname.replace(/\/$/, '') !== '/report') return;
            event.preventDefault();
            event.stopPropagation();
            triggerRef.current = link;
            setSensitiveConsent(false);
            setStage('before');
        };
        document.addEventListener('click', open, true);
        return () => document.removeEventListener('click', open, true);
    }, [homepage]);
    const cancel = () => {
        setSensitiveConsent(false);
        setStage('ready');
        requestAnimationFrame(() => {
            const trigger = triggerRef.current;
            trigger?.focus();
            // The scrolling dock may become inert while the notice has focus.
            if (trigger && document.activeElement !== trigger) {
                fallbackFocusRef?.current?.focus({ preventScroll: true });
            }
        });
    };

    const updateScroll = useCallback(() => {
        const content = readingRef.current;
        if (!content) return;
        setAtEnd(content.scrollHeight - content.clientHeight - content.scrollTop < 8);
        setScrollThumb({
            height: (content.clientHeight / content.scrollHeight) * 100,
            top: (content.scrollTop / content.scrollHeight) * 100,
        });
    }, []);

    useEffect(() => {
        if (!dialogOpen) return;
        headingRef.current?.focus({ preventScroll: true });
        if (stage === 'before') {
            const content = readingRef.current;
            if (!content) return;
            content.scrollTop = 0;
            updateScroll();
            const observer = new ResizeObserver(updateScroll);
            observer.observe(content);
            return () => observer.disconnect();
        }
    }, [stage, dialogOpen, updateScroll]);

    useEffect(() => {
        if (stage === 'ready') return;
        const previousOverflow = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        return () => {
            document.body.style.overflow = previousOverflow;
        };
    }, [stage]);

    const finish = () => {
        if (!sensitiveConsent) return;
        window.location.assign('/report');
    };

    return (
        <>
            <div inert={stage !== 'ready'} aria-hidden={stage !== 'ready' ? true : undefined}>
                {children}
            </div>

            <Dialog.Root open={dialogOpen}>
                <Dialog.Portal>
                    <Dialog.Overlay className={styles.backdrop} />
                    <Dialog.Content
                        className={`${styles.panel} ${stage === 'before' ? styles.readingPanel : styles.welcomePanel}`}
                        onOpenAutoFocus={(event) => {
                            event.preventDefault();
                            headingRef.current?.focus({ preventScroll: true });
                        }}
                        onCloseAutoFocus={(event) => event.preventDefault()}
                        onInteractOutside={(event) => event.preventDefault()}
                        onEscapeKeyDown={(event) => {
                            // A policy popup handles Escape while focus is inside that dialog.
                            if (
                                (event.target as Element).closest('[role="dialog"]') !==
                                headingRef.current?.closest('[role="dialog"]')
                            )
                                return;
                            event.preventDefault();
                            cancel();
                        }}
                    >
                        <header className={styles.header}>
                            <span>VERA REPORT</span>
                            <span className={styles.step}>{stage === 'before' ? 'BEFORE YOU SEND' : '01 / 01'}</span>
                        </header>

                        {stage === 'welcome' ? (
                            <div className={styles.welcomeBody}>
                                <p className={styles.badge}>WHISTLEBLOWING PLATFORM</p>
                                <Dialog.Title ref={headingRef} tabIndex={-1} className={styles.welcomeTitle}>
                                    Report misconduct.
                                </Dialog.Title>
                                <Dialog.Description className={styles.welcomeDescription}>
                                    {COPY.welcomeDescription}
                                </Dialog.Description>
                                <div className={styles.welcomeActions}>
                                    <button
                                        type="button"
                                        className={styles.primaryButton}
                                        onClick={() => setStage('before')}
                                    >
                                        OKAY <span aria-hidden="true">→</span>
                                    </button>
                                    <a href="/status" className={styles.statusLink}>
                                        <span>ALREADY FILED?</span> CHECK STATUS <span aria-hidden="true">↗</span>
                                    </a>
                                </div>
                            </div>
                        ) : (
                            <>
                                <div className={styles.readingArea}>
                                    <div
                                        ref={readingRef}
                                        className={styles.readingContent}
                                        role="region"
                                        aria-label="Before you send information"
                                        tabIndex={0}
                                        onScroll={updateScroll}
                                    >
                                        <p className={styles.eyebrow}>Notice</p>
                                        <Dialog.Title ref={headingRef} tabIndex={-1} className={styles.readingTitle}>
                                            Before you continue
                                        </Dialog.Title>
                                        <Dialog.Description className={styles.readingDescription}>
                                            Speaking up can matter. Before you send a report, know who can read it, what
                                            you control, and where to check your rights.
                                        </Dialog.Description>
                                        <section className={styles.answer}>
                                            <h3>Who sees it</h3>
                                            <p>{COPY.whoSeesIt}</p>
                                        </section>
                                        <section className={styles.answer}>
                                            <h3>What you share</h3>
                                            <p>{COPY.whatYouShare}</p>
                                        </section>
                                        <section className={styles.answer}>
                                            <h3>Your rights</h3>
                                            <p>
                                                Protections and deadlines depend on the issue and your location, and
                                                some deadlines are 30 days or fewer. A VERA report is not a complaint,
                                                tip or claim filed with any government agency, and giving a legal
                                                organization access does not by itself make it your lawyer. If a
                                                deadline, retaliation, or legal protection matters to you, speak with a
                                                lawyer or the relevant agency promptly. Do not wait for a response
                                                through VERA.
                                            </p>
                                        </section>
                                        <section className={styles.resources} aria-labelledby="entry-resources-title">
                                            <h3 id="entry-resources-title" className={styles.eyebrow}>
                                                OFFICIAL U.S. STARTING POINTS
                                            </h3>
                                            <AuthorityLinks authorities={RESOURCES} />
                                            <p className={styles.resourceNote}>
                                                Reward programs have eligibility rules. Reporting through VERA does not
                                                submit a tip or reward claim to an agency. VERA is not affiliated with
                                                any government agency.
                                            </p>
                                            <details className={styles.moreResources} onToggle={updateScroll}>
                                                <summary>More reporting authorities</summary>
                                                <AuthorityLinks authorities={MORE_RESOURCES} />
                                                <p className={styles.resourceNote}>
                                                    FinCEN says it will begin processing and paying awards after its
                                                    implementing regulation is finalized. Check its program page for
                                                    updates.
                                                </p>
                                            </details>
                                        </section>
                                    </div>
                                    <div className={styles.scrollRail} aria-hidden="true">
                                        <span
                                            style={{ height: `${scrollThumb.height}%`, top: `${scrollThumb.top}%` }}
                                        />
                                    </div>
                                    {!atEnd && (
                                        <span className={styles.scrollHint} aria-hidden="true">
                                            SCROLL ↓
                                        </span>
                                    )}
                                </div>
                                <footer className={styles.footer}>
                                    <div className={styles.consent}>
                                        <label className={styles.consentChoice}>
                                            <input
                                                type="checkbox"
                                                checked={sensitiveConsent}
                                                onChange={(event) => setSensitiveConsent(event.target.checked)}
                                            />
                                            <span>
                                                I consent to VERA processing my sensitive personal information, if I
                                                include it, to receive, store, and share my report as I direct.
                                            </span>
                                        </label>
                                        <p>
                                            By selecting &quot;Agree and continue,&quot; you agree to the{' '}
                                            <PolicyDialog policy="terms">VERA Terms of Service</PolicyDialog> and
                                            acknowledge the <PolicyDialog policy="privacy">Privacy Notice</PolicyDialog>
                                            .
                                        </p>
                                    </div>
                                    <div className={styles.footerActions}>
                                        <button type="button" className={styles.secondaryButton} onClick={cancel}>
                                            Cancel
                                        </button>
                                        <button
                                            type="button"
                                            className={styles.primaryButton}
                                            disabled={!sensitiveConsent}
                                            onClick={finish}
                                        >
                                            Agree and continue <span aria-hidden="true">→</span>
                                        </button>
                                    </div>
                                </footer>
                            </>
                        )}
                    </Dialog.Content>
                </Dialog.Portal>
            </Dialog.Root>
        </>
    );
}
