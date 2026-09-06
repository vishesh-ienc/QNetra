import type { ReactNode } from 'react';
import styles from './Section.module.css';

interface SectionProps {
  /** Small uppercase kicker naming the conceptual area. */
  eyebrow?: string;
  title?: string;
  /** The question this section answers, in plain language. */
  lede?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  /** Adds a hairline above the section to separate conceptual areas. */
  divided?: boolean;
  id?: string;
}

export function Section({
  eyebrow,
  title,
  lede,
  actions,
  children,
  divided = true,
  id,
}: SectionProps) {
  return (
    <section className={`${styles.section} ${divided ? styles.divided : ''}`} id={id}>
      {(eyebrow || title || lede || actions) && (
        <header className={styles.header}>
          <div className={styles.heading}>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            {title && <h2 className={styles.title}>{title}</h2>}
            {lede && <p className={styles.lede}>{lede}</p>}
          </div>
          {actions && <div className={styles.actions}>{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}
