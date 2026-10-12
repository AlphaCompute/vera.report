import { useId, type ReactNode } from 'react';
import styles from './WorkspaceBoard.module.css';

/** Presentation only: columns reflect verified state; moving a card never grants access. */
export function WorkspaceBoard({ children, label, three = false }: { children: ReactNode; label: string; three?: boolean }) {
  return <div className={`${styles.board} ${three ? styles.three : ''}`} role="group" aria-label={label}>{children}</div>;
}

export function BoardLane({ title, description, count, tone = 'neutral', children }: {
  title: string; description: string; count: number; tone?: 'neutral' | 'waiting' | 'shared' | 'attention'; children: ReactNode;
}) {
  const id = useId();
  return <section className={styles.lane} data-tone={tone} aria-labelledby={id}>
    <header className={styles.laneHeader}>
      <div><h2 id={id}>{title}</h2><span className={styles.count} aria-label={`${count} items`}>{count}</span></div>
      <p>{description}</p>
    </header>
    <div className={styles.laneBody}>{children}</div>
  </section>;
}

export function BoardEmpty({ children }: { children: ReactNode }) {
  return <p className={styles.empty}>{children}</p>;
}
