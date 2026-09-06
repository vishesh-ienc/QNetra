import { API_MODE } from '../../api/client';
import { formatDateTime, formatNumber } from '../../lib/format';
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
  const { scan, scans, scanId, setScanId } = useScanContext();

  return (
    <header className={styles.bar}>
      <button
        type="button"
        className={styles.navToggle}
        onClick={onOpenNav}
        aria-label="Open navigation"
      >
        ☰
      </button>

      <div className={styles.context}>
        {scan ? (
          <>
            {scans.length > 1 ? (
              <label className={styles.scanSelect}>
                <span className="visually-hidden">Active scan</span>
                <select
                  value={scanId ?? ''}
                  onChange={(event) => setScanId(event.target.value)}
                >
                  {scans.map((option) => (
                    <option key={option.scan_id} value={option.scan_id}>
                      {option.name ?? option.target.name ?? option.scan_id}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <p className={styles.scanName}>{scan.name ?? scan.target.name ?? 'Scan'}</p>
            )}
            <span className={`${styles.target} mono`} title={scan.target.path}>
              {scan.target.path}
            </span>
            <Badge tone={STATUS_TONE[scan.status] ?? 'UNKNOWN'} variant="dot">
              {scan.status.toLowerCase()}
            </Badge>
          </>
        ) : (
          <p className={styles.scanName}>No scan selected</p>
        )}
      </div>

      <div className={styles.meta}>
        {scan && (
          <>
            <span className={styles.metaItem}>
              <span className="numeric">{formatNumber(scan.progress.raw_findings_count)}</span>{' '}
              findings
            </span>
            <span className={styles.metaDivider} aria-hidden="true" />
            <span className={styles.metaItem}>
              <span className="numeric">{formatNumber(scan.progress.assets_count)}</span> assets
            </span>
            <span className={styles.metaDivider} aria-hidden="true" />
            <span className={styles.metaItem} title={`Completed ${formatDateTime(scan.completed_at)}`}>
              {formatDateTime(scan.completed_at)}
            </span>
          </>
        )}
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
