import { useState } from 'react';
import { useAssets, useRisk } from '../api/queries';
import type { CryptoAsset } from '../api/types';
import { formatDateTime, formatNumber, NOT_AVAILABLE, share } from '../lib/format';
import {
  primitiveLabel,
  quantumThreatShort,
  quantumThreatTone,
  SEVERITY_ORDER,
  severityTone,
} from '../lib/labels';
import { useTableState } from '../lib/useTableState';
import {
  Badge,
  DataTable,
  DistributionBar,
  EmptyState,
  ErrorState,
  FilterBar,
  Meter,
  PageHeader,
  PaginationBar,
  PathRef,
  Panel,
  ResetFilters,
  ScoreDial,
  SearchInput,
  Section,
  Select,
  SkeletonBlock,
  SkeletonRows,
  Stat,
  StatRow,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import tableStyles from './Tables.module.css';
import styles from './RiskPage.module.css';

export function RiskPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const risk = useRisk(scanId);
  const table = useTableState({ sort: { key: 'risk_score', order: 'desc' } });
  const assets = useAssets(scanId, table.queryParams);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const report = risk.data;

  const rationaleByAsset = new Map(
    (report?.assessments ?? []).map((assessment) => [assessment.asset_id, assessment]),
  );

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
      key: 'location',
      header: 'Location',
      priority: 'lg',
      render: (asset) => (
        <PathRef filePath={asset.location.file_path} line={asset.location.start_line} />
      ),
    },
    {
      key: 'rationale',
      header: 'Why',
      render: (asset) => {
        const assessment = rationaleByAsset.get(asset.asset_id);
        if (!assessment) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
        return (
          <span className={styles.rationale} title={assessment.rationale}>
            {assessment.rationale}
          </span>
        );
      },
    },
    {
      key: 'quantum',
      header: 'Quantum',
      priority: 'xl',
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
      key: 'severity',
      header: 'Severity',
      align: 'right',
      priority: 'lg',
      width: '110px',
      render: (asset) =>
        asset.risk_severity ? (
          <Badge tone={severityTone[asset.risk_severity]} size="sm">
            {asset.risk_severity}
          </Badge>
        ) : (
          <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>
        ),
    },
    {
      key: 'score',
      header: 'Score',
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
        title="Risk"
        lede="A deterministic score per asset, produced by core.risk_engine from the algorithm class, the observed parameters and the quantum threat that applies. The same inputs always produce the same score — nothing here is estimated or weighted by the interface."
        meta={report && <span>Assessed {formatDateTime(report.calculated_at)}</span>}
      />

      <Section divided={false}>
        {risk.isLoading && <SkeletonBlock height={220} />}
        {risk.error && <ErrorState error={risk.error} onRetry={() => risk.refetch()} />}
        {report && (
          <div className={styles.overview}>
            <div className={styles.dial}>
              <ScoreDial
                score={report.overall_risk_score}
                label="Repository risk"
                tone={severityTone[report.overall_severity]}
                size={200}
              />
              <Badge tone={severityTone[report.overall_severity]} variant="solid">
                {report.overall_severity}
              </Badge>
            </div>

            <div className={styles.overviewBody}>
              <div className={styles.distribution}>
                <div className={styles.distributionHead}>
                  <h3 className={styles.blockTitle}>Severity distribution</h3>
                  <span className={styles.distributionTotal}>
                    <span className="numeric">
                      {formatNumber(report.total_assets_discovered)}
                    </span>{' '}
                    assets
                  </span>
                </div>
                <DistributionBar
                  total={report.total_assets_discovered}
                  segments={SEVERITY_ORDER.map((severity) => ({
                    key: severity,
                    label: severity,
                    count: report.severity_distribution[severity] ?? 0,
                    tone: severityTone[severity],
                  }))}
                />
                <ul className={styles.severityList}>
                  {SEVERITY_ORDER.map((severity) => {
                    const count = report.severity_distribution[severity] ?? 0;
                    return (
                      <li
                        key={severity}
                        className={styles.severityRow}
                        data-sev={severityTone[severity]}
                      >
                        <span className={styles.severityLabel}>{severity}</span>
                        <Meter
                          value={share(count, report.total_assets_discovered)}
                          tone={severityTone[severity]}
                          size="sm"
                        />
                        <span className={`${styles.severityCount} numeric`}>
                          {formatNumber(count)}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>

              <StatRow>
                <Stat
                  label="Vulnerable assets"
                  value={formatNumber(report.vulnerable_assets_count)}
                  hint="Classified vulnerable by the engine"
                />
                <Stat
                  label="Shor-vulnerable"
                  value={formatNumber(report.shor_vulnerable_count)}
                  tone="CRITICAL"
                  hint="Broken outright by a CRQC"
                />
                <Stat
                  label="Classically broken"
                  value={formatNumber(report.classically_broken_count)}
                  tone="CRITICAL"
                  hint="Broken today, without quantum"
                />
                <Stat
                  label="Quantum resistant"
                  value={formatNumber(report.quantum_resistant_count)}
                  tone="SAFE"
                  hint="Adequate at current parameters"
                />
              </StatRow>
            </div>
          </div>
        )}
      </Section>

      <Section
        eyebrow="Ranking"
        title="Every asset, ranked"
        lede="Sorted by the engine's score. The 'why' column is the engine's own rationale — open a row for the individual factors that produced the number."
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
              label="Severity"
              value={table.filters.severity ?? ''}
              options={SEVERITY_ORDER.map((severity) => ({
                value: severity,
                label: severity,
                count: report?.severity_distribution[severity],
              }))}
              onChange={(value) => table.setFilter('severity', value)}
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
                caption="Assets ranked by risk score"
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
