import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { VeraReportLogo } from './VeraReportLogo';
import { usePrefersReducedMotion } from '../../hooks/usePrefersReducedMotion';
import styles from './SiteLoader.module.css';

const HOLD_DURATION_MS = 1800;
const FADE_OUT_DURATION = 0.35;
const EASE_HEAVY: [number, number, number, number] = [0.08, 0.82, 0.17, 1];

export function SiteLoader({ hydrated, onHide, onComplete }: { hydrated: boolean; onHide?: () => void; onComplete?: () => void }) {
  const [visible, setVisible] = useState(true);
  const reducedMotion = usePrefersReducedMotion();
  const onHideRef = useRef(onHide);
  onHideRef.current = onHide;

  useEffect(() => {
    const t = setTimeout(() => {
      // Still fully opaque here, so anything onHide changes is not seen.
      onHideRef.current?.();
      setVisible(false);
    }, HOLD_DURATION_MS);
    return () => clearTimeout(t);
  }, []);

  return (
    <AnimatePresence mode="wait" onExitComplete={() => {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('vera:loader-hidden'));
      }
      onComplete?.();
    }}>
      {visible && (
        <motion.div
          key="loader"
          data-site-loader
          data-hydrated={hydrated ? true : undefined}
          role="status"
          aria-label="Loading VERA"
          className="fixed inset-0 z-[100] flex items-center justify-center"
          style={{ backgroundColor: 'var(--vera-paper)' }}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: reducedMotion ? 0 : FADE_OUT_DURATION, ease: EASE_HEAVY }}
        >
          <div className={styles.logo + ' w-[min(90vw,200px)]'}>
            <VeraReportLogo style={{ color: 'var(--vera-ink)', width: '100%', height: 'auto', display: 'block' }} />
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
