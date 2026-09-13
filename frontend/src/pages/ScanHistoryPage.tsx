import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { formatDateTime, formatDuration, formatNumber, NOT_AVAILABLE } from '../lib/format';
import { severityTone } from '../lib/labels';
import { Badge, PageHeader } from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import type { Scan, ScanStatus } from '../api/types';
import styles from './ScanHistoryPage.module.css';

/* -------------------------------------------------------------------------- */
/* Status configuration                                                       */
/* -------------------------------------------------------------------------- */

const STATUS_LABEL: Record<ScanStatus, string> = {
  COMPLETED: 'Completed',
  PARTIAL:   'Partial',
  FAILED:    'Failed',
  RUNNING:   'Running',
  QUEUED:    'Queued',
  CANCELLED: 'Cancelled',
};

const STATUS_TONE: Record<ScanStatus, string> = {
  COMPLETED: 'SAFE',
  PARTIAL:   'MEDIUM',
  FAILED:    'CRITICAL',
  RUNNING:   'ACCENT',
  QUEUED:    'UNKNOWN',
  CANCELLED: 'UNKNOWN',
} as const;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** Best display name for a scan: user-supplied name → target name → scan ID. */
function scanDisplayName(scan: Scan): string {
  return scan.name ?? scan.target.name ?? scan.scan_id.slice(0, 8);
}

/** Coerce an unknown risk severity to a valid tone key. */
function riskTone(severity: string | undefined): string {
  if (!severity) return 'UNKNOWN';
  return severity in severityTone ? severity : 'UNKNOWN';
}

/* -------------------------------------------------------------------------- */
/* ScanHistoryPage                                                             */
/* -------------------------------------------------------------------------- */

export function ScanHistoryPage() {
  const { scans, scanId, setScanId, isLoading } = useScanContext();
  const navigate = useNavigate();

  // Newest first — backend already returns them in this order, but sort
  // client-side as a safety net in case the list order changes.
  const sorted = useMemo(
    () =>
      [...scans].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      ),
    [scans],
  );

  function handleOpen(scan: Scan) {
    setScanId(scan.scan_id);
    if (scan.status === 'RUNNING' || scan.status === 'QUEUED') {
      navigate('/scan');
    } else {
      navigate('/');
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Scan"
        title="Scan history"
        lede="All scans from the current session. Select any scan to restore its full analysis — no re-upload required."
      />

      {/* Persistence notice */}
      <div className={styles.notice} role="note">
        <span className={styles.noticeIcon} aria-hidden="true">ℹ</span>
        <p className={styles.noticeText}>
          Scans are held in-process memory. History is preserved while QNetra is running, but is
          lost when the backend restarts.
        </p>
      </div>

      {/* Loading */}
      {isLoading && scans.length === 0 && (
        <div className={styles.loading} aria-busy="true">
          Loading scan history…
        </div>
      )}

      {/* Empty */}
      {!isLoading && scans.length === 0 && (
        <div className={styles.empty}>
          <p className={styles.emptyTitle}>No scans yet</p>
          <p className={styles.emptyDesc}>
            Run a scan to see its history here. Results will appear immediately after the pipeline
            completes.
          </p>
          <button
            type="button"
            className={styles.emptyAction}
            onClick={() => navigate('/scan')}
          >
            Start a scan
          </button>
        </div>
      )}

      {/* Scan list */}
      {sorted.length > 0 && (
        <div className={styles.list}>
          {sorted.map((scan) => (
            <ScanRow
              key={scan.scan_id}
              scan={scan}
              isActive={scan.scan_id === scanId}
              onOpen={() => handleOpen(scan)}
            />
          ))}
        </div>
      )}
    </>
  );
}

/* -------------------------------------------------------------------------- */
/* ScanRow                                                                    */
/* -------------------------------------------------------------------------- */

function ScanRow({
  scan,
  isActive,
  onOpen,
}: {
  scan: Scan;
  isActive: boolean;
  onOpen: () => void;
}) {
  const isRunning  = scan.status === 'RUNNING' || scan.status === 'QUEUED';
  const isFailed   = scan.status === 'FAILED' || scan.status === 'CANCELLED';
  const isPartial  = scan.status === 'PARTIAL';

  const findingsCount = scan.progress.raw_findings_count ?? null;
  const assetsCount   = scan.progress.assets_count ?? null;

  // Risk data comes from the scan summary — only present post-analysis
  const riskScore    = (scan as Scan & { overall_risk_score?: number }).overall_risk_score;
  const riskSeverity = (scan as Scan & { overall_severity?: string }).overall_severity;

  return (
    <article
      className={`${styles.row} ${isActive ? styles.rowActive : ''} ${isFailed ? styles.rowFailed : ''}`}
      aria-current={isActive ? 'true' : undefined}
    >
      {/* Active indicator strip */}
      {isActive && <span className={styles.activeStrip} aria-hidden="true" />}

      {/* Main content */}
      <div className={styles.rowMain}>

        {/* Identity */}
        <div className={styles.rowIdentity}>
          <div className={styles.rowTitle}>
            <span className={styles.rowName}>{scanDisplayName(scan)}</span>
            {isActive && (
              <span className={styles.activePill}>Current</span>
            )}
          </div>
          <span className={`${styles.rowId} mono`} title={scan.scan_id}>
            {scan.scan_id.slice(0, 16)}…
          </span>
        </div>

        {/* Status + time */}
        <div className={styles.rowStatus}>
          <Badge tone={STATUS_TONE[scan.status] as Parameters<typeof Badge>[0]['tone']} variant="dot">
            {STATUS_LABEL[scan.status]}
          </Badge>
          <span className={styles.rowTime}>{formatDateTime(scan.created_at)}</span>
          {scan.duration_seconds != null && (
            <span className={styles.rowDuration}>{formatDuration(scan.duration_seconds)}</span>
          )}
          {isRunning && !scan.duration_seconds && (
            <span className={`${styles.rowDuration} ${styles.rowDurationLive}`}>
              <span className={styles.liveDot} aria-hidden="true" />
              Running
            </span>
          )}
        </div>

        {/* Metrics */}
        <div className={styles.rowMetrics}>
          <Metric
            label="Findings"
            value={findingsCount !== null ? formatNumber(findingsCount) : isRunning ? '…' : NOT_AVAILABLE}
            dimmed={findingsCount === null && !isRunning}
          />
          <Metric
            label="Assets"
            value={assetsCount !== null ? formatNumber(assetsCount) : isRunning ? '…' : NOT_AVAILABLE}
            dimmed={assetsCount === null && !isRunning}
          />
          {riskScore !== undefined && riskSeverity ? (
            <div className={styles.metric}>
              <span className={styles.metricLabel}>Risk</span>
              <span className={styles.metricValue}>
                <Badge tone={riskTone(riskSeverity) as Parameters<typeof Badge>[0]['tone']} size="sm">
                  {riskSeverity}
                </Badge>
                <span className="numeric">{Number(riskScore).toFixed(1)}</span>
              </span>
            </div>
          ) : (
            <Metric
              label="Risk"
              value={isFailed ? 'N/A' : isRunning ? '…' : NOT_AVAILABLE}
              dimmed={!isRunning && !isFailed}
            />
          )}
        </div>

        {/* Errors/warnings on failed */}
        {(isFailed || isPartial) && scan.errors.length > 0 && (
          <p className={styles.rowError}>{scan.errors[0]}</p>
        )}
        {isPartial && scan.warnings.length > 0 && (
          <p className={styles.rowWarning}>{scan.warnings[0]}</p>
        )}
      </div>

      {/* Action */}
      <div className={styles.rowAction}>
        <button
          type="button"
          className={`${styles.openBtn} ${isActive ? styles.openBtnActive : ''}`}
          onClick={onOpen}
          aria-label={`Open scan ${scanDisplayName(scan)}`}
        >
          {isActive
            ? 'Viewing'
            : isRunning
              ? 'View Progress'
              : 'View Results'}
        </button>
      </div>
    </article>
  );
}

/* -------------------------------------------------------------------------- */
/* Metric — compact key/value cell                                            */
/* -------------------------------------------------------------------------- */

function Metric({
  label,
  value,
  dimmed,
}: {
  label: string;
  value: string;
  dimmed?: boolean;
}) {
  return (
    <div className={styles.metric}>
      <span className={styles.metricLabel}>{label}</span>
      <span className={`${styles.metricValue} ${dimmed ? styles.metricDimmed : ''}`}>
        {value}
      </span>
    </div>
  );
}
