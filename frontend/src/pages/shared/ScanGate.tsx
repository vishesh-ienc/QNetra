/**
 * ScanGate — result-availability awareness component.
 *
 * Replaces the generic `<NoScanState scanRunning />` guard on every
 * result-dependent page. Instead of a single undifferentiated "not ready"
 * message, it tells the user:
 *   WHY    — which stage this page needs
 *   WHAT   — what QNetra is currently doing
 *   WHEN   — a coarse estimate of when this page will become available
 *
 * Usage:
 *   <ScanGate requiredStage="RISK_ANALYSIS" pageName="Risk" icon="⚖">
 *     <YourPageContent />
 *   </ScanGate>
 *
 * The gate is transparent (renders children) once results are available.
 */

import { type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useScanContext } from '../../state/useScanContext';
import { EmptyState, ErrorState, PageHeader, SkeletonBlock } from '../../components/primitives';
import { stageActivity, stageLabel } from '../../lib/labels';
import type { PipelineStage } from '../../api/types';
import styles from './ScanGate.module.css';

/* -------------------------------------------------------------------------- */
/* Pipeline ordering — used to determine whether a stage has passed           */
/* -------------------------------------------------------------------------- */

const STAGE_ORDER: PipelineStage[] = [
  'QUEUED',
  'DISCOVERY',
  'NORMALIZATION',
  'CLASSIFICATION',
  'RISK_ANALYSIS',
  'MOSCA_ANALYSIS',
  'PQC_ANALYSIS',
  'CBOM',
  'COMPLETED',
];

function stageIndex(stage: PipelineStage | string): number {
  const idx = STAGE_ORDER.indexOf(stage as PipelineStage);
  return idx === -1 ? 0 : idx;
}

/**
 * Returns true if data for `requiredStage` is already in the scan progress
 * stages array as COMPLETED.
 */
function stageCompleted(stages: { name: string; status: string }[], stage: PipelineStage): boolean {
  return stages.some((s) => s.name === stage && s.status === 'COMPLETED');
}

/* -------------------------------------------------------------------------- */
/* Human-readable stage descriptions for the "this page needs" line           */
/* -------------------------------------------------------------------------- */

const STAGE_NEED_LABEL: Partial<Record<PipelineStage, string>> = {
  DISCOVERY:     'cryptographic evidence discovery',
  NORMALIZATION: 'asset normalization',
  CLASSIFICATION:'asset classification',
  RISK_ANALYSIS: 'risk assessment',
  MOSCA_ANALYSIS:'Mosca / HNDL analysis',
  PQC_ANALYSIS:  'PQC migration analysis',
  CBOM:          'CBOM generation',
  COMPLETED:     'full pipeline completion',
};

/* -------------------------------------------------------------------------- */
/* Elapsed timer (shared with ScanPage — duplicated to avoid coupling)        */
/* -------------------------------------------------------------------------- */

import { useEffect, useState } from 'react';

function useElapsedTimer(startedAt: string | null): string | null {
  const [elapsed, setElapsed] = useState<number | null>(null);
  useEffect(() => {
    if (!startedAt) { setElapsed(null); return; }
    const startMs = new Date(startedAt).getTime();
    if (isNaN(startMs)) { setElapsed(null); return; }
    const tick = () => setElapsed(Math.floor((Date.now() - startMs) / 1000));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);
  if (elapsed === null) return null;
  const m = Math.floor(elapsed / 60);
  const s = elapsed % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

/* -------------------------------------------------------------------------- */
/* Props                                                                       */
/* -------------------------------------------------------------------------- */

export interface ScanGateProps {
  /**
   * The pipeline stage that must have completed (or be running) before this
   * page has meaningful data. The gate becomes transparent (renders children)
   * once `hasResults` is true — this prop is used only to drive the
   * contextual "waiting" state message.
   */
  requiredStage: PipelineStage;
  /** Display name for this page, e.g. "Risk" — shown in the waiting state. */
  pageName: string;
  /**
   * Content to render once results are available. The gate is completely
   * transparent when `hasResults` is true — it renders nothing of its own.
   */
  children: ReactNode;
}

/* -------------------------------------------------------------------------- */
/* Component                                                                   */
/* -------------------------------------------------------------------------- */

export function ScanGate({ requiredStage, pageName, children }: ScanGateProps) {
  const { scanId, scan, isLoading, error, refetch, hasResults } = useScanContext();
  const elapsed = useElapsedTimer(
    scan?.status === 'RUNNING' || scan?.status === 'QUEUED'
      ? (scan?.started_at ?? null)
      : null,
  );

  /* ── Loading ─────────────────────────────────────────────────────────── */
  if (isLoading && !scan) {
    return (
      <>
        <PageHeader eyebrow="QNetra" title="Loading…" lede="Reading scan state from the API." />
        <SkeletonBlock height={280} />
      </>
    );
  }

  /* ── API error ──────────────────────────────────────────────────────── */
  if (error && !scan) {
    return (
      <>
        <PageHeader
          eyebrow="QNetra"
          title="Unavailable"
          lede="The application could not reach the analysis API."
        />
        <ErrorState error={error} onRetry={refetch} />
      </>
    );
  }

  /* ── No scan at all ─────────────────────────────────────────────────── */
  if (!scanId || !scan) {
    return (
      <>
        <PageHeader
          eyebrow="QNetra"
          title="No scan selected"
          lede="QNetra analyses a target and turns what it finds into a cryptographic inventory, a risk assessment, and a migration plan."
        />
        <EmptyState
          title="Nothing to show yet"
          description="No scan has been run for this instance. Upload an artifact to begin."
          action={<Link to="/scan">Start a scan →</Link>}
        />
      </>
    );
  }

  /* ── Scan failed / cancelled ────────────────────────────────────────── */
  if (scan.status === 'FAILED' || scan.status === 'CANCELLED') {
    return (
      <div className={styles.gate}>
        <div className={styles.gateIcon} data-tone="failed" aria-hidden="true">✕</div>
        <div className={styles.gateBody}>
          <p className={styles.gateEyebrow}>{pageName}</p>
          <h1 className={styles.gateTitle}>Analysis did not complete</h1>
          <p className={styles.gateDescription}>
            The scan pipeline stopped before producing results for this page.
            {scan.errors.length > 0 && (
              <> Recorded error: <span className={styles.gateCode}>{scan.errors[0]}</span></>
            )}
          </p>
          <div className={styles.gateActions}>
            <Link to="/scan" className={styles.gateLink}>View scan details →</Link>
          </div>
        </div>
      </div>
    );
  }

  /* ── Results available — render content transparently ──────────────── */
  if (hasResults) {
    return <>{children}</>;
  }

  /* ── Scan is running or queued — rich contextual waiting state ──────── */
  const isRunning      = scan.status === 'RUNNING' || scan.status === 'QUEUED';
  const currentStage   = scan.current_stage;
  const stages         = scan.progress.stages;

  // Has the required stage already completed even while scan is overall RUNNING?
  const requiredDone   = stageCompleted(stages, requiredStage);
  // Is the required stage currently active?
  const requiredActive = currentStage === requiredStage && isRunning;
  // Has the pipeline not yet reached the required stage?
  const requiredPending = !requiredDone && !requiredActive && stageIndex(currentStage) < stageIndex(requiredStage);

  // Determine which stage is currently blocking
  const blockingStage  = currentStage;
  const blockingLabel  = stageLabel[blockingStage] ?? blockingStage;

  // Stages remaining before the required stage completes
  const stagesRemaining = STAGE_ORDER.slice(
    stageIndex(currentStage),
    stageIndex(requiredStage) + 1,
  ).length;

  return (
    <div className={styles.gate}>
      <div
        className={styles.gateIcon}
        data-tone={requiredActive ? 'active' : 'pending'}
        aria-hidden="true"
      >
        {requiredActive ? '●' : '○'}
      </div>
      <div className={styles.gateBody}>
        <p className={styles.gateEyebrow}>{pageName}</p>

        <h1 className={styles.gateTitle}>
          {requiredActive
            ? `${stageLabel[requiredStage] ?? pageName} in progress`
            : requiredDone
              ? 'Results will appear shortly'
              : `Waiting for ${STAGE_NEED_LABEL[requiredStage] ?? blockingLabel}`}
        </h1>

        <p className={styles.gateDescription}>
          {requiredActive
            ? stageActivity[requiredStage]
            : requiredPending
              ? `QNetra is currently running ${blockingLabel.toLowerCase()}. ${pageName} will become available after ${STAGE_NEED_LABEL[requiredStage] ?? 'the required stages'} complete.`
              : 'QNetra is finalising results. This page will update automatically when the pipeline completes.'}
        </p>

        {/* Current blocking stage */}
        {isRunning && !requiredActive && (
          <div className={styles.gateCurrent}>
            <span className={styles.gateCurrentLabel}>Currently running</span>
            <span className={styles.gateCurrentStage}>
              <span className={styles.gateCurrentPulse} aria-hidden="true" />
              {blockingLabel}
            </span>
            {stageActivity[blockingStage] && (
              <span className={styles.gateCurrentActivity}>
                {stageActivity[blockingStage]}
              </span>
            )}
          </div>
        )}

        {/* Elapsed + ETA */}
        <div className={styles.gateMeta}>
          {elapsed !== null && (
            <span className={styles.gateMetaItem}>
              <span className={styles.gateMetaLabel}>Elapsed</span>
              <span className={`${styles.gateMetaValue} mono`}>{elapsed}</span>
            </span>
          )}
          <span className={styles.gateMetaItem}>
            <span className={styles.gateMetaLabel}>Estimated availability</span>
            <span className={styles.gateMetaValue}>
              {stagesRemaining <= 1
                ? 'Available shortly'
                : 'Usually within a minute'}
            </span>
          </span>
          {scan.name && (
            <span className={styles.gateMetaItem}>
              <span className={styles.gateMetaLabel}>Scan</span>
              <span className={`${styles.gateMetaValue} mono`}>{scan.name}</span>
            </span>
          )}
        </div>

        <div className={styles.gateActions}>
          <Link to="/scan" className={styles.gateLink}>View scan progress →</Link>
        </div>
      </div>
    </div>
  );
}
