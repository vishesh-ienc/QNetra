import type { ReactNode } from 'react';
import type { SeverityTone } from '../../lib/labels';
import styles from './Stat.module.css';

interface StatProps {
  label: string;
  value: ReactNode;
  unit?: string;
  hint?: ReactNode;
  tone?: SeverityTone;
  size?: 'md' | 'lg';
  href?: string;
}

/**
 * A single figure with its label. Deliberately not a card — statistics sit in
 * open content and are separated by rules, not boxes.
 */
export function Stat({ label, value, unit, hint, tone, size = 'md', href }: StatProps) {
  const content = (
    <>
      <p className={styles.label}>{label}</p>
      <p className={`${styles.value} numeric`} data-sev={tone}>
        {value}
        {unit && <span className={styles.unit}>{unit}</span>}
      </p>
      {hint && <p className={styles.hint}>{hint}</p>}
    </>
  );

  const className = `${styles.stat} ${styles[size]} ${tone ? styles.toned : ''}`;

  if (href) {
    return (
      <a className={`${className} ${styles.linked}`} href={href}>
        {content}
      </a>
    );
  }
  return <div className={className}>{content}</div>;
}

export function StatRow({ children }: { children: ReactNode }) {
  return <div className={styles.row}>{children}</div>;
}
