import type { ReactNode } from 'react';
import { ApiError, NotImplementedByBackendError } from '../../api/client';
import styles from './States.module.css';

/* --- Empty ---------------------------------------------------------------- */

interface EmptyStateProps {
  title: string;
  /** Say precisely what happened. "Nothing found" and "not run yet" are different. */
  description?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}

export function EmptyState({ title, description, action, compact }: EmptyStateProps) {
  return (
    <div className={`${styles.state} ${compact ? styles.compact : ''}`}>
      <p className={styles.title}>{title}</p>
      {description && <p className={styles.description}>{description}</p>}
      {action && <div className={styles.action}>{action}</div>}
    </div>
  );
}

/* --- Error ---------------------------------------------------------------- */

interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  compact?: boolean;
}

export function ErrorState({ error, onRetry, compact }: ErrorStateProps) {
  const isApiError = error instanceof ApiError;
  const unavailable = error instanceof NotImplementedByBackendError;
  const message =
    error instanceof Error ? error.message : 'An unexpected error occurred.';

  return (
    <div
      className={`${styles.state} ${styles.error} ${compact ? styles.compact : ''}`}
      data-sev={unavailable ? 'UNKNOWN' : 'CRITICAL'}
    >
      <p className={styles.title}>
        {unavailable ? 'Not available from the backend yet' : 'Could not load this data'}
      </p>
      <p className={styles.description}>{message}</p>
      {isApiError && !unavailable && (
        <p className={`${styles.code} mono`}>{error.code}</p>
      )}
      {onRetry && !unavailable && (
        <div className={styles.action}>
          <button type="button" className={styles.retry} onClick={onRetry}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}

/* --- Unavailable ----------------------------------------------------------- */

/**
 * Used where the product intends to show something the pipeline does not compute.
 * Never replaced by a placeholder number.
 */
export function Unavailable({
  label,
  reason,
}: {
  label: string;
  reason: ReactNode;
}) {
  return (
    <div className={styles.unavailable}>
      <p className={styles.unavailableLabel}>{label}</p>
      <p className={styles.description}>{reason}</p>
    </div>
  );
}

/* --- Skeletons ------------------------------------------------------------- */

export function Skeleton({ width = '100%', height = 16 }: { width?: string; height?: number }) {
  return <span className={styles.skeleton} style={{ width, height }} />;
}

export function SkeletonRows({ rows = 6, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div className={styles.skeletonTable} aria-hidden="true">
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div className={styles.skeletonRow} key={rowIndex}>
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <Skeleton
              key={columnIndex}
              width={columnIndex === 0 ? '22%' : `${12 + ((rowIndex + columnIndex) % 4) * 6}%`}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonBlock({ height = 120 }: { height?: number }) {
  return <div className={styles.skeletonBlock} style={{ height }} aria-hidden="true" />;
}
