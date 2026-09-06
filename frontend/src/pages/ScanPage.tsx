import { useCallback, useRef, useState } from 'react';
import { API_MODE } from '../api/client';
import { api } from '../api/endpoints';
import type { ScanStage, StageStatus } from '../api/types';
import { formatDateTime, formatDuration, formatNumber, formatPercent } from '../lib/format';
import {
  confidenceLevelLabel,
  primitiveLabel,
  stageLabel,
  stageQuestion,
} from '../lib/labels';
import type { PrimitiveType } from '../api/types';
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  PageHeader,
  Panel,
  Section,
  Stat,
  StatRow,
} from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import styles from './ScanPage.module.css';

const STAGE_TONE: Record<StageStatus, string> = {
  COMPLETED: 'SAFE',
  RUNNING: 'ACCENT',
  WAITING: 'UNKNOWN',
  SKIPPED: 'UNKNOWN',
  FAILED: 'CRITICAL',
};

const STAGE_GLYPH: Record<StageStatus, string> = {
  COMPLETED: '✓',
  RUNNING: '●',
  WAITING: '○',
  SKIPPED: '–',
  FAILED: '✕',
};

export function ScanPage() {
  const { scan, isLoading, error, refetch, setScanId } = useScanContext();
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [startError, setStartError] = useState<unknown>(null);
  const [starting, setStarting] = useState(false);
  const [dataShelfLifeYears, setDataShelfLifeYears] = useState(10);
  const inputRef = useRef<HTMLInputElement>(null);

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
    try {
      // The real contract: upload the artifact, then create a scan against it.
      // Where the API service is not running this rejects with a clear reason
      // rather than simulating a scan that never happened.
      const artifact = await api.uploadArtifact(file, file.name);
      const created = await api.createScan({
        name: file.name,
        artifact_id: artifact.artifact_id,
        mosca_params: { data_shelf_life_years_x: dataShelfLifeYears },
      });
      setScanId(created.scan_id);
      setFile(null);
    } catch (caught) {
      setStartError(caught);
    } finally {
      setStarting(false);
    }
  }, [file, dataShelfLifeYears, setScanId]);

  return (
    <>
      <PageHeader
        eyebrow="Pipeline"
        title="Scan"
        lede="A scan is one pass of the QNetra pipeline over one target: discover the evidence, normalize it into assets, classify them, then assess risk, timing and migration. Each stage below is a separate engine, and every later stage consumes only what the earlier ones produced."
        meta={scan && <span>Run {formatDateTime(scan.completed_at ?? scan.created_at)}</span>}
      />

      {/* --- New scan ------------------------------------------------------- */}
      <Section divided={false} eyebrow="New analysis" title="Scan a target">
        <div
          className={`${styles.dropzone} ${dragging ? styles.dropzoneActive : ''}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <input
            ref={inputRef}
            type="file"
            className="visually-hidden"
            onChange={(event) => {
              const selected = event.target.files?.[0];
              if (selected) {
                setFile(selected);
                setStartError(null);
              }
            }}
          />
          {file ? (
            <div className={styles.selection}>
              <p className={styles.selectionName}>{file.name}</p>
              <p className={styles.selectionMeta}>
                <span className="numeric">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
                <span aria-hidden="true"> · </span>
                {file.type || 'unknown type'}
              </p>
              <label className={styles.shelfLife}>
                <span className={styles.shelfLifeLabel}>
                  Data shelf life (X, years)
                  <span className={styles.shelfLifeHint}>
                    How long this data must stay confidential — feeds the Mosca
                    assessment (X + Y &gt; Z). Change it any time from the Mosca page.
                  </span>
                </span>
                <input
                  type="number"
                  min={1}
                  max={50}
                  value={dataShelfLifeYears}
                  onChange={(event) => setDataShelfLifeYears(Number(event.target.value) || 1)}
                  className={styles.shelfLifeInput}
                />
              </label>
              <div className={styles.selectionActions}>
                <Button variant="primary" onClick={startScan} disabled={starting}>
                  {starting ? 'Starting…' : 'Start scan'}
                </Button>
                <Button variant="ghost" onClick={() => setFile(null)}>
                  Choose a different file
                </Button>
              </div>
            </div>
          ) : (
            <>
              <p className={styles.dropTitle}>Drop a repository archive, binary, or container filesystem</p>
              <p className={styles.dropCopy}>
                Folders are uploaded as a <span className="mono">.zip</span>. QNetra reads the
                target — it never executes anything it finds.
              </p>
              <Button onClick={() => inputRef.current?.click()}>Select a file</Button>
            </>
          )}
        </div>

        {startError !== null && (
          <div className={styles.startError}>
            <ErrorState error={startError} compact />
          </div>
        )}

        {API_MODE === 'mock' && (
          <p className={styles.modeNote}>
            This session is set to <span className="mono">VITE_API_MODE=mock</span>, so it reads a
            pre-generated offline dataset instead of a live backend and cannot start a new scan.
            Set <span className="mono">VITE_API_MODE=live</span> and start the API with{' '}
            <span className="mono">uvicorn backend.main:app --reload --port 8000</span> to scan a
            real target.
          </p>
        )}
      </Section>

      {/* --- Current scan --------------------------------------------------- */}
      {isLoading && <Section eyebrow="Run" title="Loading">{null}</Section>}
      {error && (
        <Section eyebrow="Run" title="Scan state unavailable">
          <ErrorState error={error} onRetry={refetch} />
        </Section>
      )}

      {!isLoading && !scan && (
        <Section eyebrow="Run" title="No scan on record">
          <EmptyState
            title="Nothing has been analysed yet"
            description="Once a scan completes, the pipeline stages and their outputs appear here."
          />
        </Section>
      )}

      {scan && (
        <>
          <Section
            eyebrow="Run"
            title={scan.name ?? 'Current scan'}
            lede={
              <>
                Target <span className="mono">{scan.target.path}</span>, analysed as a{' '}
                {scan.target.target_type.toLowerCase()}.
              </>
            }
            actions={
              <Badge
                tone={
                  scan.status === 'COMPLETED'
                    ? 'SAFE'
                    : scan.status === 'FAILED'
                      ? 'CRITICAL'
                      : scan.status === 'PARTIAL'
                        ? 'MEDIUM'
                        : 'ACCENT'
                }
                variant="solid"
              >
                {scan.status}
              </Badge>
            }
          >
            <StatRow>
              <Stat
                label="Files scanned"
                value={formatNumber(scan.progress.files_scanned)}
                hint={`${formatNumber(scan.progress.files_discovered)} discovered`}
              />
              <Stat label="Raw findings" value={formatNumber(scan.progress.raw_findings_count)} />
              <Stat label="Crypto assets" value={formatNumber(scan.progress.assets_count)} />
              <Stat label="Duration" value={formatDuration(scan.duration_seconds)} />
            </StatRow>

            {(scan.warnings.length > 0 || scan.errors.length > 0) && (
              <div className={styles.diagnostics}>
                {scan.errors.length > 0 && (
                  <Panel eyebrow="Errors" title="The run recorded errors">
                    <ul className={styles.diagnosticList} data-sev="CRITICAL">
                      {scan.errors.map((message) => (
                        <li key={message}>{message}</li>
                      ))}
                    </ul>
                  </Panel>
                )}
                {scan.warnings.length > 0 && (
                  <Panel eyebrow="Warnings" title="Non-fatal issues during the run">
                    <ul className={styles.diagnosticList} data-sev="MEDIUM">
                      {scan.warnings.map((message) => (
                        <li key={message}>{message}</li>
                      ))}
                    </ul>
                  </Panel>
                )}
              </div>
            )}
          </Section>

          <Section
            eyebrow="Stages"
            title="What ran, and what each stage answered"
            lede="The pipeline is sequential. If a stage did not complete, the views that depend on it show that rather than partial numbers."
          >
            <ol className={styles.stages}>
              {scan.progress.stages.map((stage: ScanStage) => (
                <li className={styles.stage} key={stage.name} data-sev={STAGE_TONE[stage.status]}>
                  <span className={styles.stageGlyph} aria-hidden="true">
                    {STAGE_GLYPH[stage.status]}
                  </span>
                  <div className={styles.stageBody}>
                    <div className={styles.stageHead}>
                      <span className={styles.stageName}>
                        {stageLabel[stage.name] ?? stage.name}
                      </span>
                      <span className={styles.stageStatus}>{stage.status.toLowerCase()}</span>
                    </div>
                    {stageQuestion[stage.name] && (
                      <p className={styles.stageQuestion}>{stageQuestion[stage.name]}</p>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </Section>

          {scan.normalization && (
            <Section
              eyebrow="Normalization"
              title="From evidence to assets"
              lede="Several observations usually describe one piece of cryptography. Normalization merges them into a single canonical asset, and keeps every contributing finding attached to it."
            >
              <div className={styles.normalization}>
                <div className={styles.funnel}>
                  <div className={styles.funnelStep}>
                    <p className={`${styles.funnelValue} numeric`}>
                      {formatNumber(scan.normalization.raw_findings_count)}
                    </p>
                    <p className={styles.funnelLabel}>raw findings</p>
                  </div>
                  <span className={styles.funnelArrow} aria-hidden="true">
                    →
                  </span>
                  <div className={styles.funnelStep}>
                    <p className={`${styles.funnelValue} numeric`}>
                      {formatNumber(scan.normalization.assets_produced_count)}
                    </p>
                    <p className={styles.funnelLabel}>canonical assets</p>
                  </div>
                  <div className={styles.funnelAside}>
                    <p className={`${styles.funnelAsideValue} numeric`}>
                      {formatNumber(scan.normalization.findings_merged_count)}
                    </p>
                    <p className={styles.funnelLabel}>
                      findings merged ({formatPercent(scan.normalization.merge_ratio)})
                    </p>
                  </div>
                </div>

                <div className={styles.breakdowns}>
                  <Breakdown
                    title="By primitive type"
                    counts={scan.normalization.assets_by_primitive_type}
                    label={(key) => primitiveLabel[key as PrimitiveType] ?? key}
                  />
                  <Breakdown
                    title="By confidence"
                    counts={scan.normalization.assets_by_confidence_level}
                    label={(key) => confidenceLevelLabel[key] ?? key}
                  />
                  <Breakdown
                    title="By library"
                    counts={scan.normalization.assets_by_library}
                    limit={8}
                  />
                </div>
              </div>
            </Section>
          )}
        </>
      )}
    </>
  );
}

function Breakdown({
  title,
  counts,
  limit = 10,
  label,
}: {
  title: string;
  counts: Record<string, number>;
  limit?: number;
  /** Library names are proper nouns and are shown exactly as the backend reported them. */
  label?: (key: string) => string;
}) {
  const entries = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
  return (
    <div className={styles.breakdown}>
      <p className="eyebrow">{title}</p>
      <ul className={styles.breakdownList}>
        {entries.map(([key, count]) => (
          <li key={key} className={styles.breakdownRow}>
            <span className={styles.breakdownLabel}>{label ? label(key) : key}</span>
            <span className={`${styles.breakdownCount} numeric`}>{count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
