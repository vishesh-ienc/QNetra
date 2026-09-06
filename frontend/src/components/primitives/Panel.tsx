import type { ReactNode } from 'react';
import styles from './Panel.module.css';

interface PanelProps {
  title?: ReactNode;
  eyebrow?: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  /** `flush` removes body padding — use for tables that own their own spacing. */
  flush?: boolean;
  tone?: 'default' | 'sunken';
  className?: string;
}

export function Panel({
  title,
  eyebrow,
  description,
  actions,
  children,
  flush = false,
  tone = 'default',
  className = '',
}: PanelProps) {
  return (
    <div className={`${styles.panel} ${styles[tone]} ${className}`}>
      {(title || eyebrow || actions) && (
        <header className={styles.header}>
          <div className={styles.heading}>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            {title && <h3 className={styles.title}>{title}</h3>}
            {description && <p className={styles.description}>{description}</p>}
          </div>
          {actions && <div className={styles.actions}>{actions}</div>}
        </header>
      )}
      <div className={flush ? styles.bodyFlush : styles.body}>{children}</div>
    </div>
  );
}
