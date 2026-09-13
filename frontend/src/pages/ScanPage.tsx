import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_MODE } from '../api/client';
import { api } from '../api/endpoints';
import type { PipelineStage, ScanStage, StageStatus } from '../api/types';
import { formatDuration, formatNumber } from '../lib/format';
import {
  stageActivity,
  stageLabel,
  stageOutcomeSummary,
} from '../lib/labels';
import {
  Button,
  ErrorState,
} from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import styles from './ScanPage.module.css';

/* -------------------------------------------------------------------------- */
/* Constants                                                                   */
/* -------------------------------------------------------------------------- */

const STAGE_GLYPH: Record<StageStatus, string> = {
  COMPLETED: '✓',
  RUNNING:   '●',
  WAITING:   '○',
  SKIPPED:   '–',
  FAILED:    '✕',
};

/** Human-readable pending text per stage — shown for WAITING stages. */
const STAGE_PENDING_AFTER: Partial<Record<PipelineStage, string>> = {
  NORMALIZATION: 'Available after discovery completes.',
  CLASSIFICATION:'Available after normalization completes.',
  RISK_ANALYSIS: 'Available after classification completes.',
  MOSCA_ANALYSIS:'Available after risk assessment completes.',
  PQC_ANALYSIS:  'Available after risk and Mosca analysis complete.',
  CBOM:          'Available after classification completes.',
  COMPLETED:     '',
};

const SUPPORTED_FORMATS = [
  {
    title: 'Source Repositories',
    description: 'ZIP archives of source code. Analyzes AST and APIs in Python, TypeScript/JavaScript, Java, and C/C++.',
    badge: '.zip, .tar.gz',
    icon: (
      <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <polyline points="16 18 22 12 16 6" />
        <polyline points="8 6 2 12 8 18" />
      </svg>
    ),
  },
  {
    title: 'Compiled Binaries',
    description: 'Statically analyzes symbol tables (via LIEF) and cryptographic string constants in executables and shared libraries.',
    badge: 'ELF, PE, .exe, .so, .dll',
    icon: (
      <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="4" y="4" width="16" height="16" rx="2" />
        <rect x="9" y="9" width="6" height="6" />
        <line x1="9" y1="1" x2="9" y2="4" />
        <line x1="15" y1="1" x2="15" y2="4" />
        <line x1="9" y1="20" x2="9" y2="23" />
        <line x1="15" y1="20" x2="15" y2="23" />
        <line x1="20" y1="9" x2="23" y2="9" />
        <line x1="20" y1="14" x2="23" y2="14" />
        <line x1="1" y1="9" x2="4" y2="9" />
        <line x1="1" y1="14" x2="4" y2="14" />
      </svg>
    ),
  },
  {
    title: 'Container Filesystems',
    description: 'Extracted container root filesystems to inspect OS shared libraries, package registries (dpkg, pip, npm), and certs.',
    badge: 'Extracted rootfs, .zip',
    icon: (
      <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
        <line x1="12" y1="22.08" x2="12" y2="12" />
      </svg>
    ),
  },
  {
    title: 'Certs & Configurations',
    description: 'X.509 public certificates, PEM blocks, TLS server configs, and cryptographic parameter manifests.',
    badge: '.pem, .crt, .key, .conf',
    icon: (
      <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
  },
];

/* -------------------------------------------------------------------------- */
/* Elapsed timer hook                                                          */
/* -------------------------------------------------------------------------- */

function useElapsedTimer(startedAt: string | null): string | null {
  const [elapsed, setElapsed] = useState<number | null>(null);

  useEffect(() => {
    if (!startedAt) {
      setElapsed(null);
      return;
    }
    const startMs = new Date(startedAt).getTime();
    if (isNaN(startMs)) {
      setElapsed(null);
      return;
    }

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
/* Main component                                                              */
/* -------------------------------------------------------------------------- */

export function ScanPage() {
  const { scan, refetch, setScanId } = useScanContext();
  const navigate = useNavigate();

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [startError, setStartError] = useState<unknown>(null);
  const [starting, setStarting] = useState(false);
  const [dataShelfLifeYears, setDataShelfLifeYears] = useState(10);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Derive scan states
  const isQueued    = scan?.status === 'QUEUED';
  const isRunning   = scan?.status === 'RUNNING';
  const isCompleted = scan?.status === 'COMPLETED';
  const isPartial   = scan?.status === 'PARTIAL';
  const isFailed    = scan?.status === 'FAILED' || scan?.status === 'CANCELLED';
  const isActive    = isRunning || isQueued;
  const hasResults  = isCompleted || isPartial;

  // Elapsed timer — only ticks during active scanning
  const elapsed = useElapsedTimer(isActive ? (scan?.started_at ?? null) : null);

  // Auto-redirect on completion to Cryptographic Posture
  const redirectedRef = useRef(false);
  useEffect(() => {
    if (!hasResults || redirectedRef.current) return;
    redirectedRef.current = true;
    const id = setTimeout(() => navigate('/'), 500);
    return () => clearTimeout(id);
  }, [hasResults, navigate]);

  // Scroll to top when entering scanning state
  const wasActive = useRef(false);
  useEffect(() => {
    if (isActive && !wasActive.current) {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    wasActive.current = isActive;
  }, [isActive]);

  // Upload handlers
  const onDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) {
      setFile(dropped);
      setStartError(null);
    }
  }, []);

  const startScan = useCallback(async () => {
    if (!file) return;
    setStarting(true);
    setStartError(null);
    redirectedRef.current = false;
    try {
      const artifact = await api.uploadArtifact(file, file.name);
      const created = await api.createScan({
        name: file.name,
        artifact_id: artifact.artifact_id,
        mosca_params: { data_shelf_life_years_x: dataShelfLifeYears },
      });
      setScanId(created.scan_id);
      refetch();
      setFile(null);
    } catch (caught) {
      setStartError(caught);
    } finally {
      setStarting(false);
    }
  }, [file, dataShelfLifeYears, setScanId, refetch]);

  /* ── BRANCH B: SCANNING TAKEOVER ─────────────────────────────────────── */
  if (isActive && scan) {
    const p = scan.progress;
    const filesScanned    = p.files_scanned;
    const rawFindings     = p.raw_findings_count;
    const assetsCount     = p.assets_count;

    const currentStage = scan.current_stage;
    const activeLabel  = stageLabel[currentStage] ?? currentStage;

    return (
      <div className={styles.scanningLayout}>
        <div className={styles.scanningHeader}>
          <div className={styles.scanningEyebrow}>
            <span className={styles.scanningPulse} aria-hidden="true" />
            Scan in progress
          </div>
          <h1 className={styles.scanningTitle}>
            {scan.name ?? scan.target.name ?? 'Analyzing target'}
          </h1>
          <div className={styles.scanningTagline}>
            <span>{activeLabel} — {stageActivity[currentStage] ?? 'Processing…'}</span>
            {elapsed !== null && (
              <span className={styles.elapsedBadge} aria-label="Elapsed time">
                {elapsed}
              </span>
            )}
          </div>
          <p className={styles.etaNote}>
            Usually completes in under a minute.
          </p>
        </div>

        {(filesScanned != null || rawFindings != null || assetsCount != null) && (
          <div className={styles.liveCounters} role="status" aria-live="polite" aria-atomic="false">
            {filesScanned != null && filesScanned > 0 && (
              <div className={styles.liveCounter}>
                <span className={`${styles.liveCounterValue} numeric`}>
                  {formatNumber(filesScanned)}
                </span>
                <span className={styles.liveCounterLabel}>Files scanned</span>
              </div>
            )}
            {rawFindings != null && rawFindings > 0 && (
              <div className={styles.liveCounter}>
                <span className={`${styles.liveCounterValue} numeric`}>
                  {formatNumber(rawFindings)}
                </span>
                <span className={styles.liveCounterLabel}>Findings</span>
              </div>
            )}
            {assetsCount != null && assetsCount > 0 && (
              <div className={styles.liveCounter}>
                <span className={`${styles.liveCounterValue} numeric`}>
                  {formatNumber(assetsCount)}
                </span>
                <span className={styles.liveCounterLabel}>Assets</span>
              </div>
            )}
          </div>
        )}

        <ol className={styles.timeline} aria-label="Pipeline stages">
          {scan.progress.stages.map((stage: ScanStage) => {
            const outcome = stage.status === 'COMPLETED'
              ? stageOutcomeSummary(stage.name, p)
              : null;
            const pendingText = stage.status === 'WAITING'
              ? (STAGE_PENDING_AFTER[stage.name] ?? null)
              : null;
            const activityText = stage.status === 'RUNNING'
              ? (stageActivity[stage.name] ?? null)
              : null;

            return (
              <li
                className={styles.timelineItem}
                key={stage.name}
                data-status={stage.status}
              >
                <span className={styles.timelineDot} aria-hidden="true">
                  {STAGE_GLYPH[stage.status]}
                </span>
                <div className={styles.timelineStageRow}>
                  <span className={styles.timelineStageName}>
                    {stageLabel[stage.name] ?? stage.name}
                  </span>
                  <span className={styles.timelineStageStatus}>
                    {stage.status.toLowerCase()}
                  </span>
                </div>
                {activityText && (
                  <p className={styles.timelineActivity}>{activityText}</p>
                )}
                {outcome && (
                  <p className={styles.timelineOutcome}>↳ {outcome}</p>
                )}
                {pendingText && (
                  <p className={styles.timelinePending}>{pendingText}</p>
                )}
              </li>
            );
          })}
        </ol>
      </div>
    );
  }

  /* ── BRANCH C: FAILURE STATE ──────────────────────────────────────────── */
  if (isFailed && scan) {
    return (
      <div className={styles.failureLayout}>
        <div className={styles.failureHeader}>
          <div className={styles.failureIcon} aria-hidden="true">✕</div>
          <div className={styles.failureBody}>
            <p className={styles.failureEyebrow}>Scan failed</p>
            <h1 className={styles.failureTitle}>
              {scan.name ?? scan.target.name ?? 'Scan'}
            </h1>
            {scan.duration_seconds != null && (
              <p className={styles.failureMeta}>
                Stopped after {formatDuration(scan.duration_seconds)}
              </p>
            )}
            {scan.errors.length > 0 && (
              <ul className={styles.failureErrors}>
                {scan.errors.map((msg) => (
                  <li key={msg}>{msg}</li>
                ))}
              </ul>
            )}
            <div className={styles.failureActions}>
              <button
                type="button"
                className={styles.failureCta}
                onClick={() => {
                  setScanId(null);
                  redirectedRef.current = false;
                }}
              >
                Start a new scan
              </button>
            </div>
          </div>
        </div>

        <div className={styles.singleScanSection}>
          <UploadZone
            file={file}
            dragging={dragging}
            starting={starting}
            startError={startError}
            showAdvanced={showAdvanced}
            dataShelfLifeYears={dataShelfLifeYears}
            inputRef={inputRef}
            onDrop={onDrop}
            onDragOver={() => setDragging(true)}
            onDragLeave={() => setDragging(false)}
            onFileChange={(f) => { setFile(f); setStartError(null); }}
            onFileRemove={() => setFile(null)}
            onStart={startScan}
            onToggleAdvanced={() => setShowAdvanced(v => !v)}
            onShelfLifeChange={setDataShelfLifeYears}
          />
        </div>
      </div>
    );
  }

  /* ── BRANCH A: IDLE — SINGLE UNIFIED SCAN SECTION ───────────────────── */
  return (
    <div className={styles.singleScanSection}>
      <div className={styles.scanHeader}>
        <h1 className={styles.scanTitle}>Start Cryptographic Scan</h1>
        <p className={styles.scanSubtitle}>
          Upload an artifact to discover all cryptographic primitives, evaluate quantum risk, and generate PQC migration intelligence.
        </p>
      </div>

      <UploadZone
        file={file}
        dragging={dragging}
        starting={starting}
        startError={startError}
        showAdvanced={showAdvanced}
        dataShelfLifeYears={dataShelfLifeYears}
        inputRef={inputRef}
        onDrop={onDrop}
        onDragOver={() => setDragging(true)}
        onDragLeave={() => setDragging(false)}
        onFileChange={(f) => { setFile(f); setStartError(null); }}
        onFileRemove={() => setFile(null)}
        onStart={startScan}
        onToggleAdvanced={() => setShowAdvanced(v => !v)}
        onShelfLifeChange={setDataShelfLifeYears}
      />

      {/* Informational Section: Supported targets and file formats */}
      <div className={styles.supportedSection}>
        <p className={styles.supportedHeading}>Supported Target Types &amp; Formats</p>
        <div className={styles.supportedFormats}>
          {SUPPORTED_FORMATS.map((item) => (
            <div key={item.title} className={styles.supportedFormatCard}>
              <div className={styles.supportedFormatIcon}>
                {item.icon}
              </div>
              <div className={styles.supportedFormatContent}>
                <p className={styles.supportedFormatTitle}>{item.title}</p>
                <p className={styles.supportedFormatDesc}>{item.description}</p>
                <span className={styles.supportedFormatBadge}>{item.badge}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* UploadZone                                                                 */
/* -------------------------------------------------------------------------- */

interface UploadZoneProps {
  file: File | null;
  dragging: boolean;
  starting: boolean;
  startError: unknown;
  showAdvanced: boolean;
  dataShelfLifeYears: number;
  inputRef: React.RefObject<HTMLInputElement | null>;
  onDrop: (e: React.DragEvent) => void;
  onDragOver: () => void;
  onDragLeave: () => void;
  onFileChange: (f: File) => void;
  onFileRemove: () => void;
  onStart: () => void;
  onToggleAdvanced: () => void;
  onShelfLifeChange: (n: number) => void;
}

function UploadZone({
  file,
  dragging,
  starting,
  startError,
  showAdvanced,
  dataShelfLifeYears,
  inputRef,
  onDrop,
  onDragOver,
  onDragLeave,
  onFileChange,
  onFileRemove,
  onStart,
  onToggleAdvanced,
  onShelfLifeChange,
}: UploadZoneProps) {
  return (
    <div className={styles.uploadCard}>
      <div
        className={`${styles.dropzone} ${dragging ? styles.dropzoneActive : ''} ${API_MODE === 'mock' ? styles.dropzoneMock : ''}`}
        onDragOver={(e) => { e.preventDefault(); onDragOver(); }}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => {
          if (!file && API_MODE !== 'mock') {
            inputRef.current?.click();
          }
        }}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if ((e.key === 'Enter' || e.key === ' ') && !file && API_MODE !== 'mock') {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
      >
        <input
          ref={inputRef}
          type="file"
          className="visually-hidden"
          onChange={(e) => {
            const selected = e.target.files?.[0];
            if (selected) onFileChange(selected);
          }}
        />

        {file ? (
          <div className={styles.selectedState} onClick={(e) => e.stopPropagation()}>
            <div className={styles.selectedFile}>
              <div className={styles.selectedFileIcon} aria-hidden="true">
                <svg viewBox="0 0 20 20" width="18" height="18" fill="none">
                  <path d="M5 3h7l4 4v10a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
                  <path d="M12 3v4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
              <div className={styles.selectedFileMeta}>
                <p className={`${styles.selectedFileName} mono`}>{file.name}</p>
                <p className={styles.selectedFileInfo}>
                  <span className="numeric">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
                  {file.type && <><span aria-hidden="true"> · </span>{file.type}</>}
                </p>
              </div>
              <button
                type="button"
                className={styles.removeFile}
                onClick={onFileRemove}
                aria-label="Remove file"
              >
                ✕
              </button>
            </div>

            {/* Optional advanced settings */}
            <div className={styles.advancedToggle}>
              <button
                type="button"
                className={styles.advancedToggleBtn}
                onClick={onToggleAdvanced}
                aria-expanded={showAdvanced}
              >
                <svg
                  viewBox="0 0 12 12"
                  width="10"
                  height="10"
                  fill="none"
                  aria-hidden="true"
                  className={`${styles.advancedChevron} ${showAdvanced ? styles.advancedChevronOpen : ''}`}
                >
                  <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Advanced options
              </button>
              {showAdvanced && (
                <div className={styles.advancedPanel}>
                  <label className={styles.advancedField}>
                    <div className={styles.advancedFieldLabel}>
                      <span>Data shelf life (X, years)</span>
                      <span className={styles.advancedFieldHint}>
                        How long this data must stay confidential — feeds Mosca assessment ($X + Y &gt; Z$).
                      </span>
                    </div>
                    <input
                      type="number"
                      min={1}
                      max={50}
                      value={dataShelfLifeYears}
                      onChange={(e) => onShelfLifeChange(Number(e.target.value) || 1)}
                      className={styles.advancedInput}
                    />
                  </label>
                </div>
              )}
            </div>

            <div className={styles.selectedActions}>
              <Button variant="primary" onClick={onStart} disabled={starting || API_MODE === 'mock'}>
                {starting ? 'Starting…' : 'Start Scan'}
              </Button>
              <Button variant="ghost" onClick={onFileRemove}>
                Choose a different file
              </Button>
            </div>
          </div>
        ) : (
          <div className={styles.emptyDropzone}>
            <div className={styles.dropzoneIcon} aria-hidden="true">
              <svg viewBox="0 0 48 48" width="48" height="48" fill="none">
                <circle cx="24" cy="24" r="22" stroke="currentColor" strokeWidth="1.5" opacity="0.3" />
                <path d="M24 15v14M24 15l-5 5M24 15l5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                <path d="M15 35h18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </div>
            <p className={styles.dropTitle}>Drop file here to start scan</p>
            <p className={styles.dropSubtitle}>or click to browse from device (ZIP, ELF, PE, or configurations)</p>
            {API_MODE === 'mock' && (
              <p className={styles.mockBadge}>
                Offline dataset — upload disabled
              </p>
            )}
          </div>
        )}
      </div>

      {startError !== null && (
        <div className={styles.startError}>
          <ErrorState error={startError} compact />
        </div>
      )}
    </div>
  );
}
