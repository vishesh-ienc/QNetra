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
  ACQUISITION:   'Available after repository cloning starts.',
  DISCOVERY:     'Available after acquisition completes.',
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
    title: 'Public GitHub Repositories',
    description: 'Direct shallow-clone scanning of public GitHub repositories for cryptographic libraries, algorithms, and post-quantum readiness.',
    badge: 'git clone --depth 1',
    icon: (
      <svg viewBox="0 0 16 16" width="20" height="20" fill="currentColor" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
      </svg>
    ),
  },
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
/* GitHub URL helper                                                          */
/* -------------------------------------------------------------------------- */

function parseGitHubUrl(url: string): { valid: boolean; owner?: string; repo?: string; message?: string } {
  const trimmed = url.trim();
  if (!trimmed) {
    return { valid: false };
  }
  let clean = trimmed;
  if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
    clean = 'https://' + clean;
  }
  try {
    const parsed = new URL(clean);
    const host = parsed.hostname.toLowerCase();
    if (host !== 'github.com' && host !== 'www.github.com') {
      return { valid: false, message: 'Enter a valid public GitHub repository URL (only github.com is supported).' };
    }
    const path = parsed.pathname.replace(/^\/+|\/+$/g, '');
    const parts = path.split('/');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { valid: false, message: 'Enter a valid public GitHub repository URL (format: https://github.com/organization/repository).' };
    }
    const owner = parts[0];
    let repo = parts[1];
    if (repo.endsWith('.git')) {
      repo = repo.slice(0, -4);
    }
    if (repo === '.' || repo === '..' || repo.startsWith('-')) {
      return { valid: false, message: `Enter a valid public GitHub repository URL (invalid repository name "${repo}").` };
    }
    return { valid: true, owner, repo };
  } catch {
    return { valid: false, message: 'Enter a valid public GitHub repository URL.' };
  }
}

/* -------------------------------------------------------------------------- */
/* Main component                                                              */
/* -------------------------------------------------------------------------- */

export function ScanPage() {
  const { scan, refetch, setScanId } = useScanContext();
  const navigate = useNavigate();

  const [sourceMode, setSourceMode] = useState<'upload' | 'github'>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [githubUrl, setGithubUrl] = useState('');
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
    const id = setTimeout(() => navigate('/posture'), 500);
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
        source_type: 'UPLOAD',
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

  const startGitHubScan = useCallback(async () => {
    const parsed = parseGitHubUrl(githubUrl);
    if (!parsed.valid) return;
    setStarting(true);
    setStartError(null);
    redirectedRef.current = false;
    try {
      const created = await api.createScan({
        name: `${parsed.owner}/${parsed.repo}`,
        source_type: 'GITHUB',
        repository_url: githubUrl.trim(),
        mosca_params: { data_shelf_life_years_x: dataShelfLifeYears },
      });
      setScanId(created.scan_id);
      refetch();
    } catch (caught) {
      setStartError(caught);
    } finally {
      setStarting(false);
    }
  }, [githubUrl, dataShelfLifeYears, setScanId, refetch]);

  /* ── BRANCH B: SCANNING TAKEOVER ─────────────────────────────────────── */
  if (isActive && scan) {
    const p = scan.progress;
    const filesScanned    = p.files_scanned;
    const rawFindings     = p.raw_findings_count;
    const assetsCount     = p.assets_count;

    const currentStage = scan.current_stage;
    const activeLabel  = stageLabel[currentStage] ?? currentStage;

    // Dynamic stage transition phrasing per prompt specifications
    const isAcquisitionComplete = scan.progress.stages.find((s) => s.name === 'ACQUISITION')?.status === 'COMPLETED';
    let dynamicActivity = stageActivity[currentStage] ?? 'Processing…';
    if (scan.source_type === 'GITHUB') {
      if (currentStage === 'ACQUISITION') {
        dynamicActivity = 'Acquiring repository from GitHub…';
      } else if (currentStage === 'DISCOVERY' && (filesScanned ?? 0) > 0) {
        dynamicActivity = `Analyzing cryptographic usage across source files (${filesScanned} files analyzed)…`;
      } else if (currentStage === 'DISCOVERY' && isAcquisitionComplete) {
        dynamicActivity = 'Repository acquired. Starting cryptographic discovery…';
      } else if (currentStage === 'DISCOVERY') {
        dynamicActivity = 'Discovering cryptographic usage…';
      }
    }

    return (
      <div className={styles.scanningLayout}>
        <div className={styles.scanningHeader}>
          <div className={styles.scanningEyebrow}>
            <span className={styles.scanningPulse} aria-hidden="true" />
            Scan in progress
            {scan.source_type === 'GITHUB' && (
              <span className={styles.sourceTag}>GitHub Repository</span>
            )}
          </div>
          <h1 className={styles.scanningTitle}>
            {scan.name ?? scan.target.name ?? 'Analyzing target'}
          </h1>
          {scan.source_url && (
            <div className={styles.scanningSourceUrl}>
              <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor" aria-hidden="true">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
              <span className="mono">{scan.source_url}</span>
            </div>
          )}
          <div className={styles.scanningTagline}>
            <span>{activeLabel} — {dynamicActivity}</span>
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

        {/* Technical repository metadata grid */}
        <div className={styles.scanMetaGrid} role="region" aria-label="Repository Information">
          <div className={styles.scanMetaItem}>
            <span className={styles.scanMetaLabel}>Repository</span>
            <span className={`${styles.scanMetaValue} mono`}>
              {scan.target.name ?? scan.name ?? 'Target'}
            </span>
          </div>
          <div className={styles.scanMetaItem}>
            <span className={styles.scanMetaLabel}>Source</span>
            <span className={styles.scanMetaValue}>
              {scan.source_type === 'GITHUB' ? 'Public GitHub repository' : 'Uploaded files'}
            </span>
          </div>
          <div className={styles.scanMetaItem}>
            <span className={styles.scanMetaLabel}>Status</span>
            <span className={styles.scanMetaValue}>
              <span className={styles.scanningPulse} aria-hidden="true" />
              Scanning
            </span>
          </div>
          <div className={styles.scanMetaItem}>
            <span className={styles.scanMetaLabel}>Current stage</span>
            <span className={styles.scanMetaValue}>
              {activeLabel}
            </span>
          </div>
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
            {(p.lines_analyzed ?? 0) > 0 && (
              <div className={styles.liveCounter}>
                <span className={`${styles.liveCounterValue} numeric`}>
                  {formatNumber(p.lines_analyzed!)}
                </span>
                <span className={styles.liveCounterLabel}>Lines analyzed</span>
              </div>
            )}
          </div>
        )}

        {/* Partial scan notice — shown as soon as is_partial is set (large repos) */}
        {(scan.is_partial || p.is_partial) && (
          <div className={styles.partialBanner} role="note" aria-label="Partial scan notice">
            <span className={styles.partialBannerIcon} aria-hidden="true">⚡</span>
            <div className={styles.partialBannerText}>
              <span className={styles.partialBannerTitle}>Priority-first scan</span>
              <span className={styles.partialBannerReason}>
                {scan.partial_reason || p.partial_reason ||
                  'This repository is large — QNetra is analyzing the highest-priority cryptographic files first to stay within the interactive scan budget.'}
              </span>
            </div>
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
          <div className={styles.sourceSelector}>
            <span className={styles.sourceSelectorLabel}>Choose scan source</span>
            <div className={styles.sourceToggle} role="tablist" aria-label="Scan source type">
              <button
                type="button"
                role="tab"
                aria-selected={sourceMode === 'upload'}
                className={`${styles.sourceToggleBtn} ${sourceMode === 'upload' ? styles.sourceToggleBtnActive : ''}`}
                onClick={() => { setSourceMode('upload'); setStartError(null); }}
              >
                <span className={styles.sourceToggleIcon} aria-hidden="true">
                  <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M2.5 10.5v2a1 1 0 001 1h9a1 1 0 001-1v-2M8 2.5v7.5M5 5.5l3-3 3 3" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </span>
                Upload Files
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={sourceMode === 'github'}
                className={`${styles.sourceToggleBtn} ${sourceMode === 'github' ? styles.sourceToggleBtnActive : ''}`}
                onClick={() => { setSourceMode('github'); setStartError(null); }}
              >
                <span className={styles.sourceToggleIcon} aria-hidden="true">
                  <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                  </svg>
                </span>
                GitHub Repository
              </button>
            </div>
          </div>
          <div className={styles.sourceDivider} />

          {sourceMode === 'upload' ? (
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
          ) : (
            <GitHubZone
              url={githubUrl}
              starting={starting}
              startError={startError}
              showAdvanced={showAdvanced}
              dataShelfLifeYears={dataShelfLifeYears}
              onUrlChange={(u) => { setGithubUrl(u); setStartError(null); }}
              onStart={startGitHubScan}
              onToggleAdvanced={() => setShowAdvanced(v => !v)}
              onShelfLifeChange={setDataShelfLifeYears}
            />
          )}
        </div>
      </div>
    );
  }

  /* ── BRANCH A: IDLE — SINGLE UNIFIED SCAN SECTION ───────────────────── */
  return (
    <div className={styles.singleScanSection}>
      <div className={styles.scanHeader}>
        <p className={styles.scanEyebrow}>Scan</p>
        <h1 className={styles.scanTitle}>New Scan</h1>
        <p className={styles.scanSubtitle}>
          Scan a publicly accessible GitHub repository or uploaded files for cryptographic usage and quantum exposure.
        </p>
      </div>

      <div className={styles.sourceSelector}>
        <span className={styles.sourceSelectorLabel}>Choose scan source</span>
        <div className={styles.sourceToggle} role="tablist" aria-label="Scan source type">
          <button
            type="button"
            role="tab"
            aria-selected={sourceMode === 'upload'}
            className={`${styles.sourceToggleBtn} ${sourceMode === 'upload' ? styles.sourceToggleBtnActive : ''}`}
            onClick={() => { setSourceMode('upload'); setStartError(null); }}
          >
            <span className={styles.sourceToggleIcon} aria-hidden="true">
              <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M2.5 10.5v2a1 1 0 001 1h9a1 1 0 001-1v-2M8 2.5v7.5M5 5.5l3-3 3 3" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </span>
            Upload Files
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={sourceMode === 'github'}
            className={`${styles.sourceToggleBtn} ${sourceMode === 'github' ? styles.sourceToggleBtnActive : ''}`}
            onClick={() => { setSourceMode('github'); setStartError(null); }}
          >
            <span className={styles.sourceToggleIcon} aria-hidden="true">
              <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
            </span>
            GitHub Repository
          </button>
        </div>
      </div>
      <div className={styles.sourceDivider} />

      {sourceMode === 'upload' ? (
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
      ) : (
        <GitHubZone
          url={githubUrl}
          starting={starting}
          startError={startError}
          showAdvanced={showAdvanced}
          dataShelfLifeYears={dataShelfLifeYears}
          onUrlChange={(u) => { setGithubUrl(u); setStartError(null); }}
          onStart={startGitHubScan}
          onToggleAdvanced={() => setShowAdvanced(v => !v)}
          onShelfLifeChange={setDataShelfLifeYears}
        />
      )}

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

/* -------------------------------------------------------------------------- */
/* GitHubZone                                                                 */
/* -------------------------------------------------------------------------- */

interface GitHubZoneProps {
  url: string;
  starting: boolean;
  startError: unknown;
  showAdvanced: boolean;
  dataShelfLifeYears: number;
  onUrlChange: (url: string) => void;
  onStart: () => void;
  onToggleAdvanced: () => void;
  onShelfLifeChange: (n: number) => void;
}

function GitHubZone({
  url,
  starting,
  startError,
  showAdvanced,
  dataShelfLifeYears,
  onUrlChange,
  onStart,
  onToggleAdvanced,
  onShelfLifeChange,
}: GitHubZoneProps) {
  const parsed = parseGitHubUrl(url);
  const isInputFilled = url.trim().length > 0;
  const canStart = parsed.valid && !starting && API_MODE !== 'mock';

  return (
    <div className={styles.uploadCard}>
      <div className={styles.githubCard}>
        <div className={styles.githubHeader}>
          <div className={styles.githubIconBadge} aria-hidden="true">
            <svg viewBox="0 0 16 16" width="22" height="22" fill="currentColor">
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
            </svg>
          </div>
          <div className={styles.githubHeaderText}>
            <p className={styles.githubTitle}>GitHub Repository</p>
            <p className={styles.githubSubtitle}>
              Scan a publicly accessible GitHub repository for cryptographic usage and quantum exposure.
            </p>
          </div>
        </div>

        <div className={styles.githubInputGroup}>
          <label htmlFor="github-repo-url" className={styles.githubInputLabel}>
            Repository URL
          </label>
          <div className={styles.githubInputWrapper}>
            <input
              id="github-repo-url"
              type="url"
              value={url}
              onChange={(e) => onUrlChange(e.target.value)}
              placeholder="https://github.com/organization/repository"
              className={styles.githubInput}
              autoFocus
              autoComplete="off"
              spellCheck="false"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && canStart) {
                  e.preventDefault();
                  onStart();
                }
              }}
            />
          </div>
          <div className={styles.githubValidation}>
            {isInputFilled && parsed.valid && (
              <span className={styles.githubValidationValid}>
                ✓ Ready to scan {parsed.owner}/{parsed.repo}
              </span>
            )}
            {isInputFilled && !parsed.valid && (
              <span className={styles.githubValidationError}>
                {parsed.message ?? 'Enter a valid public GitHub repository URL.'}
              </span>
            )}
          </div>
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

        <div className={styles.githubNotice}>
          <strong>Public Repositories Only:</strong> Only public GitHub repositories are supported. QNetra shallow-clones (<code className="mono">--depth 1</code>) the default branch directly on the backend. No authentication credentials, private repositories, or write permissions are required or supported.
        </div>

        <div className={styles.githubActions}>
          <Button variant="primary" onClick={onStart} disabled={!canStart}>
            {starting ? 'Acquiring & Starting…' : 'Scan Repository'}
          </Button>
          {url && (
            <Button variant="ghost" onClick={() => onUrlChange('')} disabled={starting}>
              Clear
            </Button>
          )}
        </div>
      </div>

      {startError !== null && (
        <div className={styles.startError}>
          <ErrorState error={startError} compact />
        </div>
      )}
    </div>
  );
}

