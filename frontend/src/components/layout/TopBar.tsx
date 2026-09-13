import { Link } from 'react-router-dom';
import { API_MODE } from '../../api/client';
import { useScanContext } from '../../state/useScanContext';
import { Badge } from '../primitives';
import styles from './TopBar.module.css';

const STATUS_TONE = {
  COMPLETED: 'SAFE',
  PARTIAL: 'MEDIUM',
  RUNNING: 'ACCENT',
  QUEUED: 'UNKNOWN',
  FAILED: 'CRITICAL',
  CANCELLED: 'UNKNOWN',
} as const;

export function TopBar({ onOpenNav }: { onOpenNav: () => void }) {
  const { scan, scans } = useScanContext();

  return (
    <header className={styles.bar}>
      <button
        type="button"
        className={styles.navToggle}
        onClick={onOpenNav}
        aria-label="Open navigation"
      >
        <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
          <rect x="2" y="5" width="16" height="1.5" rx="0.75" fill="currentColor" />
          <rect x="2" y="9.25" width="16" height="1.5" rx="0.75" fill="currentColor" />
          <rect x="2" y="13.5" width="10" height="1.5" rx="0.75" fill="currentColor" />
        </svg>
      </button>

      <div className={styles.context}>
        {scan ? (
          <div className={styles.scanContext}>
            <span className={styles.activeLabel}>Active</span>
            <span className={styles.scanName} title={scan.target.path || scan.name || scan.scan_id}>
              {scan.name ?? scan.target.name ?? scan.scan_id.slice(0, 12)}
            </span>
            <Badge tone={STATUS_TONE[scan.status] ?? 'UNKNOWN'} variant="dot" size="sm">
              {scan.status.toLowerCase()}
            </Badge>
            <Link
              to="/history"
              className={styles.historyLink}
              title="View all scans in session history"
            >
              History{scans.length > 1 ? ` (${scans.length})` : ''}
            </Link>
          </div>
        ) : (
          <Link to="/scan" className={styles.ctaLink}>
            <svg viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true">
              <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
              <path d="M5 8h6M8 5v6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            Start a scan
          </Link>
        )}
      </div>

      <div className={styles.meta}>
        {API_MODE === 'mock' && (
          <span
            className={styles.sourceChip}
            title={
              'The QNetra API service (backend/) is not running. This session is reading a ' +
              'dataset produced by running the real QNetra pipeline over the repository sample targets.'
            }
          >
            Offline dataset
          </span>
        )}
      </div>
    </header>
  );
}
