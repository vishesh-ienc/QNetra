import { useState } from 'react';
import { useAssets, useRisk } from '../api/queries';
import type { CryptoAsset, QuantumThreatType } from '../api/types';
import { formatBits, formatNumber, NOT_AVAILABLE, share } from '../lib/format';
import {
  primitiveLabel,
  quantumStatusLabel,
  quantumStatusTone,
  quantumThreatExplanation,
  quantumThreatLabel,
  quantumThreatShort,
  quantumThreatTone,
} from '../lib/labels';
import { useTableState } from '../lib/useTableState';
import {
  Badge,
  DataTable,
  EmptyState,
  ErrorState,
  FilterBar,
  Meter,
  PageHeader,
  PaginationBar,
  PathRef,
  Panel,
  ResetFilters,
  SearchInput,
  Section,
  Select,
  SkeletonBlock,
  SkeletonRows,
  Unavailable,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import tableStyles from './Tables.module.css';
import styles from './QuantumPage.module.css';

const THREAT_FILTERS: { value: QuantumThreatType; label: string }[] = [
  { value: 'SHOR_POLYNOMIAL_BREAK', label: 'Shor — polynomial break' },
  { value: 'CLASSICALLY_BROKEN', label: 'Classically broken' },
  { value: 'GROVER_BIT_HALVING', label: 'Grover — bit halving' },
  { value: 'QUANTUM_RESISTANT', label: 'Quantum resistant' },
  { value: 'NOT_APPLICABLE', label: 'Not applicable' },
];

export function QuantumPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const risk = useRisk(scanId);
  const table = useTableState({ sort: { key: 'risk_score', order: 'desc' } });
  const assets = useAssets(scanId, table.queryParams);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const report = risk.data;

  const classes: { key: QuantumThreatType; count: number }[] = report
    ? [
        { key: 'SHOR_POLYNOMIAL_BREAK', count: report.shor_vulnerable_count },
        { key: 'CLASSICALLY_BROKEN', count: report.classically_broken_count },
        { key: 'GROVER_BIT_HALVING', count: report.grover_impacted_count },
        { key: 'QUANTUM_RESISTANT', count: report.quantum_resistant_count },
      ]
    : [];

  const columns: Column<CryptoAsset>[] = [
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
      key: 'threat',
      header: 'Threat',
      render: (asset) =>
        asset.quantum_threat_type ? (
          <Badge tone={quantumThreatTone[asset.quantum_threat_type]} variant="dot">
            {quantumThreatShort[asset.quantum_threat_type]}
          </Badge>
        ) : (
          <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>
        ),
    },
    {
      key: 'bits',
      header: 'Effective security',
      render: (asset) => (
        <div className={styles.bits}>
          <span className={`${styles.bitsClassical} numeric`}>
            {asset.effective_classical_security_bits === null
              ? '—'
              : formatBits(asset.effective_classical_security_bits)}
          </span>
          <span className={styles.bitsArrow} aria-hidden="true">
            →
          </span>
          <span
            className={`${styles.bitsQuantum} numeric`}
            data-sev={
              asset.effective_quantum_security_bits === null &&
              asset.quantum_threat_type === 'SHOR_POLYNOMIAL_BREAK'
                ? 'CRITICAL'
                : 'UNKNOWN'
            }
            title={
              asset.effective_quantum_security_bits === null
                ? asset.quantum_threat_type === 'SHOR_POLYNOMIAL_BREAK'
                  ? 'Not expressible as a bit count — Shor breaks the construction outright.'
                  : 'Not estimable without the key parameters.'
                : undefined
            }
          >
            {asset.effective_quantum_security_bits === null
              ? asset.quantum_threat_type === 'SHOR_POLYNOMIAL_BREAK'
                ? 'broken'
                : 'unknown'
              : formatBits(asset.effective_quantum_security_bits)}
          </span>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Quantum status',
      priority: 'lg',
      render: (asset) =>
        asset.quantum_security_status ? (
          <Badge tone={quantumStatusTone[asset.quantum_security_status]} size="sm">
            {quantumStatusLabel[asset.quantum_security_status]}
          </Badge>
        ) : (
          <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>
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
      key: 'risk',
      header: 'Risk',
      sortKey: 'risk_score',
      align: 'right',
      width: '92px',
      render: (asset) => (
        <span
          className={`${tableStyles.score} numeric`}
          data-sev={asset.risk_severity ?? 'UNKNOWN'}
        >
          {asset.risk_score ?? NOT_AVAILABLE}
        </span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Exposure"
        title="Quantum"
        lede="What a cryptographically relevant quantum computer does to this inventory. Every asset is placed in exactly one threat class by core.classification, based on the algorithm and the parameters the scanners actually observed."
      />

      <Section divided={false}>
        {risk.isLoading && <SkeletonBlock height={280} />}
        {risk.error && <ErrorState error={risk.error} onRetry={() => risk.refetch()} />}
        {report && (
          <div className={styles.classes}>
            {classes.map((entry) => (
              <article
                key={entry.key}
                className={styles.class}
                data-sev={quantumThreatTone[entry.key]}
              >
                <div className={styles.classHead}>
                  <span className={`${styles.classCount} numeric`}>
                    {formatNumber(entry.count)}
                  </span>
                  <div className={styles.classHeading}>
                    <h3 className={styles.classTitle}>{quantumThreatLabel[entry.key]}</h3>
                    <Meter
                      value={share(entry.count, report.total_assets_discovered)}
                      tone={quantumThreatTone[entry.key]}
                      size="sm"
                    />
                  </div>
                </div>
                <p className={styles.classCopy}>{quantumThreatExplanation[entry.key]}</p>
              </article>
            ))}
          </div>
        )}
      </Section>

      <Section
        eyebrow="Scope"
        title="What this page does not claim"
        lede="QNetra reports the threat class and the effective security bits its engines can justify. It does not roll them up into a single quantum-readiness number."
      >
        <Unavailable
          label="Quantum readiness score — not available"
          reason={
            <>
              No engine in <span className="mono">core/</span> computes an aggregate
              quantum-readiness score, so QNetra does not display one. The threat class counts
              above, and the per-asset effective security bits below, are the figures the pipeline
              actually produces. A composite score would be an invention of the interface, and the
              product does not manufacture security intelligence.
            </>
          }
        />
      </Section>

      <Section
        eyebrow="Detail"
        title="Effective security, asset by asset"
        lede="Classical security bits and their post-quantum equivalent, where the engine could estimate them. Shor-vulnerable assets do not have a reduced bit count — the construction is broken, not weakened."
      >
        <Panel flush>
          <FilterBar
            trailing={<ResetFilters onReset={table.resetFilters} count={table.activeFilterCount} />}
          >
            <SearchInput
              value={table.search}
              onChange={table.setSearch}
              placeholder="Search algorithm or path"
              width="280px"
            />
            <Select
              label="Threat class"
              value={table.filters.quantum_threat_type ?? ''}
              options={THREAT_FILTERS}
              onChange={(value) => table.setFilter('quantum_threat_type', value)}
            />
          </FilterBar>

          {assets.isLoading && !assets.data && <SkeletonRows rows={10} columns={5} />}
          {assets.error && (
            <div className={tableStyles.pad}>
              <ErrorState error={assets.error} onRetry={() => assets.refetch()} compact />
            </div>
          )}
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
                caption="Assets by quantum threat class"
                emptyState={
                  <EmptyState
                    title="No assets match these filters"
                    description="Clear a filter to widen the search."
                    compact
                  />
                }
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

      <AssetDrawer scanId={scanId} assetId={openAssetId} onClose={() => setOpenAssetId(null)} />
    </>
  );
}
