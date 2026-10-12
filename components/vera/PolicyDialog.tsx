import * as Dialog from '@radix-ui/react-dialog';
import Head from 'next/head';
import { useRef, useState, type ReactNode } from 'react';
import policies from '@/lib/policyCopy.json';
import entryStyles from './EntrySequence.module.css';
import styles from './PolicyDialog.module.css';

export function PolicyDialog({
    policy,
    children,
    defaultOpen = false,
    onClose,
}: {
    policy: keyof typeof policies;
    children?: ReactNode;
    defaultOpen?: boolean;
    onClose?: () => void;
}) {
    const [open, setOpen] = useState(defaultOpen);
    const heading = useRef<HTMLHeadingElement>(null);
    const copy = policies[policy];
    const changeOpen = (next: boolean) => {
        setOpen(next);
        if (!next) onClose?.();
    };

    return (
        <Dialog.Root open={open} onOpenChange={changeOpen}>
            {children && <Dialog.Trigger className={styles.trigger}>{children}</Dialog.Trigger>}
            {open && (
                <Head>
                    <title>{`${copy.title} | VERA Report`}</title>
                    <meta name="robots" content="noindex, nofollow" />
                </Head>
            )}
            <Dialog.Portal>
                <Dialog.Overlay className={`${entryStyles.backdrop} ${styles.backdrop}`} />
                <Dialog.Content
                    className={`${entryStyles.panel} ${entryStyles.readingPanel} ${styles.panel}`}
                    aria-describedby={undefined}
                    onOpenAutoFocus={(event) => {
                        event.preventDefault();
                        heading.current?.focus();
                    }}
                    onEscapeKeyDown={(event) => {
                        // Handle Escape in the focused content, not an underlying dialog's document listener.
                        event.preventDefault();
                    }}
                    onKeyDown={(event) => {
                        if (event.key === 'Escape') {
                            event.preventDefault();
                            event.stopPropagation();
                            changeOpen(false);
                        }
                    }}
                >
                    <header className={entryStyles.header}>
                        <span>VERA REPORT</span>
                        <span className={entryStyles.step}>LEGAL</span>
                    </header>
                    <div className={entryStyles.readingArea}>
                        <div
                            className={`${entryStyles.readingContent} ${styles.copy}`}
                            role="region"
                            aria-label={copy.title}
                            tabIndex={0}
                        >
                            <Dialog.Title ref={heading} tabIndex={-1} className={entryStyles.readingTitle}>
                                {copy.title}
                            </Dialog.Title>
                            <p className={styles.date}>{copy.date}</p>
                            {copy.introduction.map((text) => (
                                <p key={text}>{text}</p>
                            ))}
                            {copy.sections.map(({ title, paragraphs }) => (
                                <section key={title}>
                                    <h3>{title}</h3>
                                    {paragraphs.map((text) => (
                                        <p key={text}>{text}</p>
                                    ))}
                                </section>
                            ))}
                        </div>
                    </div>
                    <footer className={entryStyles.footer}>
                        <Dialog.Close className={entryStyles.secondaryButton}>Close</Dialog.Close>
                    </footer>
                </Dialog.Content>
            </Dialog.Portal>
        </Dialog.Root>
    );
}
