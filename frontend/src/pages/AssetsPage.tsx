import { useState } from 'react';
import { useAssets } from '../api/queries';
import type { CryptoAsset } from '../api/types';
import { formatNumber, formatPercent, NOT_AVAILABLE } from '../lib/format';
import {
  confidenceTone,
  primitiveLabel,
  quantumThreatLabel,
  quantumThreatShort,
  quantumThreatTone,
  recommendationShort,
} from '../lib/labels';
import { facetOptions, useTableState } from '../lib/useTableState';
import {
  Badge,
  DataTable,
  EmptyState,
  ErrorState,
  FilterBar,
  PageHeader,
  PaginationBar,
  PathRef,
  Panel,
  ResetFilters,
  SearchInput,
  Section,
  Select,
  SkeletonRows,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useAssetIndex } from '../features/asset/useAssetIndex';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import styles from './Tables.module.css';

const QUANTUM_FILTERS = [
  { value: 'SHOR_POLYNOMIAL_BREAK', label: 'Shor — polynomial break' },
  { value: 'CLASSICALLY_BROKEN', label: 'Classically broken' },
  { value: 'GROVER_BIT_HALVING', label: 'Grover — bit halving' },
  { value: 'QUANTUM_RESISTANT', label: 'Quantum resistant' },
  { value: 'NOT_APPLICABLE', label: 'Not applicable' },
];

const SEVERITY_FILTERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => ({
  value,
  label: value,
}));

export function AssetsPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const table = useTableState({ sort: { key: 'risk_score', order: 'desc' } });
  const assets = useAssets(scanId, table.queryParams);
  const { recommendationByAsset } = useAssetIndex(scanId);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const stats = scan.normalization;

  const columns: Column<CryptoAsset>[] = [
    {
      key: 'algorithm',
      header: 'Algorithm',
      sortKey: 'algorithm',
      render: (asset) => (
        <div className={styles.primaryCell}>
          <span className={`${styles.primaryValue} mono`}>
            {asset.algorithm}
            {asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
          </span>
          <span className={styles.secondaryValue}>{primitiveLabel[asset.primitive_type]}</span>
        </div>
      ),
    },
    {
      key: 'parameters',
      header: 'Parameters',
      priority: 'xl',
      render: (asset) => {
        const parts = [
          asset.curve && `curve ${asset.curve}`,
          asset.mode && `mode ${asset.mode}`,
          asset.padding && `pad ${asset.padding}`,
        ].filter(Boolean);
        if (parts.length === 0) {
          return (
            <span className={styles.muted} title="No mode, curve or padding was observed">
              {NOT_AVAILABLE}
            </span>
          );
        }
        return <span className={`${styles.muted} mono`}>{parts.join(' · ')}</span>;
      },
    },
    {
      key: 'library',
      header: 'Library',
      priority: 'lg',
      render: (asset) =>
        asset.implementation_library ? (
          <span className="mono">{asset.implementation_library}</span>
        ) : (
          <span className={styles.muted}>{NOT_AVAILABLE}</span>
        ),
    },
    {
      key: 'location',
      header: 'Location',
      render: (asset) => (
        <PathRef filePath={asset.location.file_path} line={asset.location.start_line} />
      ),
    },
    {
      key: 'quantum',
      header: 'Quantum',
      render: (asset) =>
        asset.quantum_threat_type ? (
          <Badge
            tone={quantumThreatTone[asset.quantum_threat_type]}
            variant="dot"
            title={quantumThreatLabel[asset.quantum_threat_type]}
          >
            {quantumThreatShort[asset.quantum_threat_type]}
          </Badge>
        ) : (
          <span className={styles.muted}>{NOT_AVAILABLE}</span>
        ),
    },
    {
      key: 'recommendation',
      header: 'Recommended',
      priority: 'xl',
      render: (asset) => {
        const recommendation = recommendationByAsset.get(asset.asset_id);
        if (!recommendation) return <span className={styles.muted}>{NOT_AVAILABLE}</span>;
        return (
          <div className={styles.primaryCell}>
            <span className="mono">{recommendation.recommended_algorithm ?? '—'}</span>
            <span className={styles.secondaryValue}>
              {recommendationShort[recommendation.recommendation_type]}
            </span>
          </div>
        );
      },
    },
    {
      key: 'confidence',
      header: 'Confidence',
      sortKey: 'confidence_score',
      align: 'right',
      priority: 'lg',
      width: '110px',
      render: (asset) => (
        <Badge tone={confidenceTone(asset.confidence_score)} size="sm">
          {formatPercent(asset.confidence_score)}
        </Badge>
      ),
    },
    {
      key: 'risk',
      header: 'Risk',
      sortKey: 'risk_score',
      align: 'right',
      width: '96px',
      render: (asset) => (
        <span
          className={`${styles.score} numeric`}
          data-sev={asset.risk_severity ?? 'UNKNOWN'}
          title={asset.risk_severity ?? undefined}
        >
          {asset.risk_score ?? NOT_AVAILABLE}
        </span>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Inventory"
        title="Crypto assets"
        lede="The canonical inventory. Each row is one distinct cryptographic construction, merged from every scanner observation that described it. Open a row for its evidence, classification, risk and recommendation."
        meta={
          stats && (
            <>
              <span>
                <strong className="numeric">{formatNumber(stats.raw_findings_count)}</strong> raw
                findings
              </span>
              <span aria-hidden="true">→</span>
              <span>
                <strong className="numeric">{formatNumber(stats.assets_produced_count)}</strong>{' '}
                canonical assets
              </span>
              <span aria-hidden="true">·</span>
              <span>
                <strong className="numeric">{formatNumber(stats.findings_merged_count)}</strong>{' '}
                merged by deduplication
              </span>
            </>
          )
        }
      />

      <Section divided={false}>
        <Panel flush>
          <FilterBar
            trailing={
              <ResetFilters onReset={table.resetFilters} count={table.activeFilterCount} />
            }
          >
            <SearchInput
              value={table.search}
              onChange={table.setSearch}
              placeholder="Search algorithm, path, library"
              width="280px"
            />
            <Select
              label="Primitive"
              value={table.filters.primitive_type ?? ''}
              options={facetOptions(stats?.assets_by_primitive_type)}
              onChange={(value) => table.setFilter('primitive_type', value)}
            />
            <Select
              label="Algorithm"
              value={table.filters.algorithm ?? ''}
              options={facetOptions(stats?.assets_by_algorithm)}
              onChange={(value) => table.setFilter('algorithm', value)}
            />
            <Select
              label="Quantum"
              value={table.filters.quantum_threat_type ?? ''}
              options={QUANTUM_FILTERS}
              onChange={(value) => table.setFilter('quantum_threat_type', value)}
            />
            <Select
              label="Severity"
              value={table.filters.severity ?? ''}
              options={SEVERITY_FILTERS}
              onChange={(value) => table.setFilter('severity', value)}
            />
            <Select
              label="Library"
              value={table.filters.library ?? ''}
              options={facetOptions(stats?.assets_by_library, ['Unspecified'])}
              onChange={(value) => table.setFilter('library', value)}
            />
          </FilterBar>

          {assets.isLoading && !assets.data && <SkeletonRows rows={10} columns={6} />}
          {assets.error && (
            <div className={styles.pad}>
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
                caption="Discovered cryptographic assets"
                emptyState={
                  <EmptyState
                    title={
                      table.activeFilterCount > 0
                        ? 'No assets match these filters'
                        : 'No cryptographic assets were discovered'
                    }
                    description={
                      table.activeFilterCount > 0
                        ? 'Clear a filter to widen the search.'
                        : 'The scan completed and normalization produced no cryptographic assets for this target.'
                    }
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
