import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { API_MODE } from '../api/client';
import { getMoscaParameterSupport } from '../api/capabilities';
import { useAssets, useMosca } from '../api/queries';
import type { CryptoAsset, MoscaUrgency } from '../api/types';
import { formatNumber, formatYears, NOT_AVAILABLE, share } from '../lib/format';
import {
  HNDL_ORDER,
  hndlLabel,
  hndlTone,
  primitiveLabel,
  URGENCY_ORDER,
  urgencyDescription,
  urgencyLabel,
  urgencyTone,
} from '../lib/labels';
import { useTableState } from '../lib/useTableState';
import {
  Badge,
  DataTable,
  EmptyState,
  ErrorState,
  Meter,
  PageHeader,
  PaginationBar,
  PathRef,
  Panel,
  Section,
  SkeletonBlock,
  SkeletonRows,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useAssetIndex } from '../features/asset/useAssetIndex';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import tableStyles from './Tables.module.css';
import styles from './MoscaPage.module.css';

export function MoscaPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const [x, setX] = useState<number | null>(null);
  const [z, setZ] = useState<number | null>(null);

  const support = useQuery({
    queryKey: ['mosca-support', API_MODE],
    queryFn: getMoscaParameterSupport,
    staleTime: Infinity,
  });

  const mosca = useMosca(scanId, x, z);
  const table = useTableState({ sort: { key: 'risk_score', order: 'desc' } });
  const assets = useAssets(scanId, table.queryParams);
  const { moscaByAsset } = useAssetIndex(scanId, x, z);

  const report = mosca.data;

  // Keep the controls in step with whatever parameters the engine last reported.
  const effectiveX = x ?? report?.parameters.data_shelf_life_years_x ?? null;
  const effectiveZ = z ?? report?.parameters.quantum_threat_horizon_years_z ?? null;

  const columns: Column<CryptoAsset>[] = useMemo(
    () => [
      {
        key: 'algorithm',
        header: 'Asset',
        sortKey: 'algorithm',
        render: (asset) => (
          <div className={tableStyles.primaryCell}>
            <span className={`${tableStyles.primaryValue} mono`}>
              {asset.algorithm}
              {asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
            </span>
            <span className={tableStyles.secondaryValue}>
              {primitiveLabel[asset.primitive_type]}
            </span>
          </div>
        ),
      },
      {
        key: 'location',
        header: 'Location',
        priority: 'xl',
        render: (asset) => (
          <PathRef filePath={asset.location.file_path} line={asset.location.start_line} />
        ),
      },
      {
        key: 'terms',
        header: 'X + Y vs Z',
        render: (asset) => {
          const assessment = moscaByAsset.get(asset.asset_id);
          if (!assessment || !assessment.mosca_applicable) {
            return <span className={tableStyles.muted}>Not applicable</span>;
          }
          return (
            <span className={`${styles.terms} mono numeric`}>
              <span className={styles.termX}>{formatShort(assessment.x_data_lifetime_years)}</span>
              <span className={styles.termOp}>+</span>
              <span className={styles.termY}>{formatShort(assessment.y_migration_time_years)}</span>
              <span
                className={styles.termOp}
                data-sev={assessment.inequality_triggered ? 'CRITICAL' : 'SAFE'}
              >
                {assessment.inequality_triggered === null
                  ? '?'
                  : assessment.inequality_triggered
                    ? '>'
                    : '≤'}
              </span>
              <span className={styles.termZ}>
                {formatShort(assessment.z_quantum_arrival_years)}
              </span>
            </span>
          );
        },
      },
      {
        key: 'gap',
        header: 'Exposure gap',
        align: 'right',
        priority: 'lg',
        render: (asset) => {
          const assessment = moscaByAsset.get(asset.asset_id);
          if (!assessment || assessment.exposure_gap_years === null) {
            return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
          }
          return (
            <span className={`${styles.gap} numeric`} data-sev={assessment.exposure_gap_years > 0 ? 'CRITICAL' : 'SAFE'}>
              {formatYears(assessment.exposure_gap_years)}
            </span>
          );
        },
      },
      {
        key: 'hndl',
        header: 'HNDL',
        priority: 'lg',
        render: (asset) => {
          const assessment = moscaByAsset.get(asset.asset_id);
          if (!assessment) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
          return (
            <Badge tone={hndlTone[assessment.hndl_exposure]} variant="dot" size="sm">
              {hndlLabel[assessment.hndl_exposure]}
            </Badge>
          );
        },
      },
      {
        key: 'urgency',
        header: 'Urgency',
        align: 'right',
        width: '128px',
        render: (asset) => {
          const assessment = moscaByAsset.get(asset.asset_id);
          if (!assessment) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
          return (
            <Badge tone={urgencyTone[assessment.urgency]} size="sm">
              {urgencyLabel[assessment.urgency]}
            </Badge>
          );
        },
      },
    ],
    [moscaByAsset],
  );

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  return (
    <>
      <PageHeader
        eyebrow="Timing"
        title="Mosca assessment"
        lede={
          <>
            Mosca&rsquo;s inequality asks one question: will the data you are protecting today still
            need protecting when a quantum computer can break the cryptography protecting it? If{' '}
            <span className="mono">X + Y &gt; Z</span>, you are already late.
          </>
        }
      />

      {/* --- The three terms ------------------------------------------------ */}
      <Section divided={false}>
        <div className={styles.terminology}>
          <TermCard
            symbol="X"
            name="Data shelf life"
            value={formatYears(effectiveX)}
            copy="How long this data must stay confidential. This is a policy decision about your own data — no scanner can discover it, and QNetra never guesses a value."
          />
          <TermCard
            symbol="Y"
            name="Migration time"
            value="Derived per asset"
            copy="How long migrating this kind of cryptography takes. The engine derives it from the primitive type, because replacing a hash is not the same job as replacing a key exchange."
          />
          <TermCard
            symbol="Z"
            name="Quantum horizon"
            value={formatYears(effectiveZ)}
            copy="Years until a cryptographically relevant quantum computer is expected. An assumption drawn from NIST, ENISA and BSI consensus — not a prediction QNetra makes."
          />
        </div>
      </Section>

      {/* --- Controls ------------------------------------------------------- */}
      <Section
        eyebrow="Parameters"
        title="Change the assumptions"
        lede="Adjusting a parameter sends it back to core.mosca_engine, which re-evaluates every asset. The interface never evaluates the inequality itself."
      >
        <Panel>
          {support.data && (
            <div className={styles.controls}>
              <ParameterControl
                label="X — Data shelf life"
                value={effectiveX}
                onChange={setX}
                support={support.data.xValues}
                continuous={support.data.continuous}
                min={1}
                max={30}
              />
              <ParameterControl
                label="Z — Quantum horizon"
                value={effectiveZ}
                onChange={setZ}
                support={support.data.zValues}
                continuous={support.data.continuous}
                min={3}
                max={25}
              />
            </div>
          )}
          {support.data && !support.data.continuous && (
            <p className={styles.controlNote}>
              The QNetra API service is not running, so this session can only show parameter
              combinations the engine was run for offline. With the API connected, any value is
              recomputed on demand.
            </p>
          )}
          {mosca.error && (
            <div className={styles.controlError}>
              <ErrorState error={mosca.error} compact />
            </div>
          )}
        </Panel>
      </Section>

      {/* --- Verdict -------------------------------------------------------- */}
      <Section
        eyebrow="Result"
        title="The portfolio verdict"
        lede="Y differs per asset, so the inequality is evaluated per asset rather than once for the whole target."
      >
        {mosca.isLoading && !report && <SkeletonBlock height={220} />}
        {report && (
          <div className={styles.verdict}>
            <div className={styles.verdictHeadline}>
              <p className={styles.verdictNumber} data-sev={report.mosca_triggered_assets > 0 ? 'CRITICAL' : 'SAFE'}>
                <span className="numeric">{formatNumber(report.mosca_triggered_assets)}</span>
                <span className={styles.verdictOf}>
                  {' '}
                  of {formatNumber(report.mosca_applicable_assets)}
                </span>
              </p>
              <p className={styles.verdictCaption}>
                applicable assets fail the inequality at these parameters
              </p>
              <Meter
                value={share(report.mosca_triggered_assets, report.mosca_applicable_assets)}
                tone={report.mosca_triggered_assets > 0 ? 'CRITICAL' : 'SAFE'}
              />
              <p className={styles.verdictNote}>
                {formatNumber(report.total_assets - report.mosca_applicable_assets)} of the{' '}
                {formatNumber(report.total_assets)} discovered assets are outside Mosca&rsquo;s
                scope — libraries, randomness sources and algorithms that are already
                quantum-resistant.
              </p>
            </div>

            <div className={styles.verdictBreakdown}>
              <div>
                <h3 className={styles.blockTitle}>Migration urgency</h3>
                <ul className={styles.urgencyList}>
                  {URGENCY_ORDER.filter(
                    (urgency) => (report.urgency_distribution[urgency] ?? 0) > 0,
                  ).map((urgency: MoscaUrgency) => (
                    <li key={urgency} className={styles.urgencyRow} data-sev={urgencyTone[urgency]}>
                      <div className={styles.urgencyHead}>
                        <span className={styles.urgencyLabel}>{urgencyLabel[urgency]}</span>
                        <span className={`${styles.urgencyCount} numeric`}>
                          {formatNumber(report.urgency_distribution[urgency])}
                        </span>
                      </div>
                      <Meter
                        value={share(report.urgency_distribution[urgency], report.total_assets)}
                        tone={urgencyTone[urgency]}
                        size="sm"
                      />
                      <p className={styles.urgencyCopy}>{urgencyDescription[urgency]}</p>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 className={styles.blockTitle}>Harvest now, decrypt later</h3>
                <p className={styles.hndlCopy}>
                  An adversary does not need a quantum computer today to benefit from one later.
                  Traffic captured now can be stored and decrypted the moment the capability
                  arrives. Anything with a long confidentiality requirement is exposed from the
                  moment it is transmitted.
                </p>
                <ul className={styles.hndlList}>
                  {HNDL_ORDER.filter(
                    (exposure) => (report.hndl_distribution[exposure] ?? 0) > 0,
                  ).map((exposure) => (
                    <li key={exposure} className={styles.hndlRow} data-sev={hndlTone[exposure]}>
                      <span className={styles.hndlDot} aria-hidden="true" />
                      <span className={styles.hndlLabel}>{hndlLabel[exposure]}</span>
                      <span className={`${styles.hndlCount} numeric`}>
                        {formatNumber(report.hndl_distribution[exposure])}
                      </span>
                    </li>
                  ))}
                </ul>
                <p className={styles.hndlNote}>
                  Exposure is reported as UNKNOWN where the engine could not establish the
                  sensitivity of the data an asset protects. That is a gap in the inputs, not a
                  clean bill of health.
                </p>
              </div>
            </div>
          </div>
        )}
      </Section>

      {/* --- Per asset ------------------------------------------------------ */}
      <Section
        eyebrow="Detail"
        title="Every asset against the clock"
        lede="The terms as the engine evaluated them, per asset. Open a row for the full rationale and the assumptions behind it."
      >
        <Panel flush>
          {assets.isLoading && !assets.data && <SkeletonRows rows={10} columns={5} />}
          {assets.data && (
            <>
              <DataTable
                columns={columns}
                rows={assets.data.data}
                rowKey={(asset) => asset.asset_id}
                onRowClick={(asset) => setOpenAssetId(asset.asset_id)}
                activeRowKey={openAssetId}
                sort={table.sort}
                onSortChange={table.toggleSort}
                caption="Mosca assessment per asset"
                emptyState={<EmptyState title="No assets to assess" compact />}
              />
              <PaginationBar
                page={assets.data.pagination.page}
                pageSize={assets.data.pagination.page_size}
                totalItems={assets.data.pagination.total_items}
                totalPages={assets.data.pagination.total_pages}
                onPageChange={table.setPage}
                onPageSizeChange={table.setPageSize}
                noun="assets"
              />
            </>
          )}
        </Panel>
      </Section>

      <AssetDrawer
        scanId={scanId}
        assetId={openAssetId}
        onClose={() => setOpenAssetId(null)}
        moscaX={x}
        moscaZ={z}
      />
    </>
  );
}

/* --- Local components ----------------------------------------------------- */

function TermCard({
  symbol,
  name,
  value,
  copy,
}: {
  symbol: string;
  name: string;
  value: string;
  copy: string;
}) {
  return (
    <article className={styles.term}>
      <div className={styles.termHead}>
        <span className={`${styles.termSymbol} mono`}>{symbol}</span>
        <div>
          <p className={styles.termName}>{name}</p>
          <p className={`${styles.termValue} numeric`}>{value}</p>
        </div>
      </div>
      <p className={styles.termCopy}>{copy}</p>
    </article>
  );
}

function ParameterControl({
  label,
  value,
  onChange,
  support,
  continuous,
  min,
  max,
}: {
  label: string;
  value: number | null;
  onChange: (value: number) => void;
  support?: number[];
  continuous: boolean;
  min: number;
  max: number;
}) {
  if (!continuous && support && support.length > 0) {
    const index = Math.max(
      0,
      support.findIndex((candidate) => candidate === value),
    );
    return (
      <div className={styles.control}>
        <div className={styles.controlHead}>
          <label className={styles.controlLabel} htmlFor={`param-${label}`}>
            {label}
          </label>
          <span className={`${styles.controlValue} numeric`}>{formatYears(value)}</span>
        </div>
        <input
          id={`param-${label}`}
          type="range"
          min={0}
          max={support.length - 1}
          step={1}
          value={index}
          onChange={(event) => onChange(support[Number(event.target.value)])}
          className={styles.slider}
        />
        <div className={styles.ticks}>
          {support.map((candidate) => (
            <button
              key={candidate}
              type="button"
              className={`${styles.tick} ${candidate === value ? styles.tickActive : ''}`}
              onClick={() => onChange(candidate)}
            >
              {candidate}
            </button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={styles.control}>
      <div className={styles.controlHead}>
        <label className={styles.controlLabel} htmlFor={`param-${label}`}>
          {label}
        </label>
        <span className={`${styles.controlValue} numeric`}>{formatYears(value)}</span>
      </div>
      <input
        id={`param-${label}`}
        type="range"
        min={min}
        max={max}
        step={0.5}
        value={value ?? min}
        onChange={(event) => onChange(Number(event.target.value))}
        className={styles.slider}
      />
      <div className={styles.ticks}>
        <span className={styles.tick}>{min}</span>
        <span className={styles.tick}>{max}</span>
      </div>
    </div>
  );
}

function formatShort(value: number | null): string {
  if (value === null) return '?';
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}
