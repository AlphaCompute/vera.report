import { memo, useEffect, type CSSProperties } from 'react';
import styles from './TypewriterText.module.css';

interface TypewriterTextProps {
  text: string;
  messageId: string;
  animate: boolean;
  onComplete: (messageId: string) => void;
}

const GLYPH_REVEAL_MS = 140;

/** Reserve the final line wrapping and animate glyphs without updating React every frame. */
export const TypewriterText = memo(function TypewriterText({ text, messageId, animate, onComplete }: TypewriterTextProps) {
  const characterCount = Array.from(text.trimEnd()).length;
  const staggerMs = Math.min(18, 1250 / Math.max(1, characterCount - 1));
  const durationMs = (characterCount - 1) * staggerMs + GLYPH_REVEAL_MS;

  useEffect(() => {
    if (!animate) return;
    const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
    const finishWithoutMotion = () => {
      if (preference.matches || document.hidden) onComplete(messageId);
    };
    finishWithoutMotion();
    preference.addEventListener('change', finishWithoutMotion);
    document.addEventListener('visibilitychange', finishWithoutMotion);
    // Safety net if a browser drops animationend or suppresses animations.
    const timer = window.setTimeout(() => onComplete(messageId), durationMs + 200);
    return () => {
      window.clearTimeout(timer);
      preference.removeEventListener('change', finishWithoutMotion);
      document.removeEventListener('visibilitychange', finishWithoutMotion);
    };
  }, [animate, durationMs, messageId, onComplete]);

  let offset = 0;
  return (
    <span className={styles.text} data-typing={animate}>
      {/* Read the complete question, never individual animated letters. The report
          page announces new questions through its own persistent live region. */}
      <span className="sr-only">{text}</span>
      <span aria-hidden="true" onAnimationEnd={(event) => {
        if (animate && (event.target as HTMLElement).dataset.lastGlyph === 'true') onComplete(messageId);
      }}>
        {text.split(/(\s+)/).map((token, tokenIndex) => {
          const characters = Array.from(token);
          const start = offset;
          offset += characters.length;
          if (/^\s+$/.test(token)) return token;
          return (
            <span className={styles.word} key={tokenIndex}>
              {characters.map((character, index) => (
                <span
                  key={index}
                  className={styles.glyph}
                  data-last-glyph={start + index === characterCount - 1 ? 'true' : undefined}
                  style={{ '--glyph-delay': `${(start + index) * staggerMs}ms`, '--glyph-duration': `${GLYPH_REVEAL_MS}ms` } as CSSProperties}
                >{character}</span>
              ))}
            </span>
          );
        })}
      </span>
    </span>
  );
});
