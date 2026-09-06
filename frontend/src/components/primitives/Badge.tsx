import type { ReactNode } from 'react';
import type { SeverityTone } from '../../lib/labels';
import styles from './Badge.module.css';

interface BadgeProps {
  tone?: SeverityTone;
  variant?: 'solid' | 'quiet' | 'outline' | 'dot';
  size?: 'sm' | 'md';
  children: ReactNode;
  title?: string;
}

export function Badge({
  tone = 'UNKNOWN',
  variant = 'quiet',
  size = 'md',
  children,
  title,
}: BadgeProps) {
  return (
    <span
      className={`${styles.badge} ${styles[variant]} ${styles[size]}`}
      data-sev={tone}
      title={title}
    >
      {variant === 'dot' && <i className={styles.dotMark} aria-hidden="true" />}
      {children}
    </span>
  );
}
