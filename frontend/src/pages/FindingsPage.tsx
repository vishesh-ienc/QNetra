import { useState } from 'react';
import { useFindings } from '../api/queries';
import type { Finding } from '../api/types';
import { formatNumber, formatPercent, oneLine } from '../lib/format';
import { confidenceTone, discoveryMethodLabel } from '../lib/labels';
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
import { FindingDrawer } from '../features/finding/FindingDrawer';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import styles from './Tables.module.css';

export function FindingsPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openFindingId, setOpenFindingId] = useState<string | null>(null);
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const table = useTableState({ sort: { key: 'confidence_score', order: 'desc' } });
  const findings = useFindings(scanId, table.queryParams);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const discovery = scan.discovery;

  const columns: Column<Finding>[] = [
    {
      key: 'symbol',
      header: 'Evidence',
      render: (finding) => (
        <div className={styles.primaryCell}>
          <span className={`${styles.primaryValue} mono`}>
            {finding.suspected_algorithm ?? oneLine(finding.raw_symbol, 40)}
          </span>
          <span className={`${styles.snippet} mono`}>{oneLine(finding.raw_symbol, 70)}</span>
        </div>
      ),
    },
    {
      key: 'category',
      header: 'Category',
      priority: 'lg',
      render: (finding) => (
        <span className={styles.muted}>
          {finding.artifact_category.replace(/_/g, ' ').toLowerCase()}
        </span>
      ),
    },
    {
      key: 'location',
      header: 'Location',
      render: (finding) => (
        <PathRef filePath={finding.location.file_path} line={finding.location.start_line} />
      ),
    },
    {
      key: 'method',
      header: 'Method',
      render: (finding) => (
        <Badge tone="ACCENT" variant="outline" size="sm">
          {discoveryMethodLabel[finding.discovery_method] ?? finding.discovery_method}
        </Badge>
      ),
    },
    {
      key: 'scanner',
      header: 'Scanner',
      priority: 'xl',
      render: (finding) => (
        <span className={`${styles.muted} mono`}>
          {finding.scanner_name.split('/').pop() ?? finding.scanner_name}
        </span>
      ),
    },
    {
      key: 'confidence',
      header: 'Confidence',
      sortKey: 'confidence_score',
      align: 'right',
      width: '112px',
      render: (finding) => (
        <Badge tone={confidenceTone(finding.confidence_score)} size="sm">
          {formatPercent(finding.confidence_score)}
        </Badge>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Evidence"
        title="Findings"
        lede="Raw scanner output, before normalization. Each row is a single observation at a single location — the primary evidence behind every conclusion QNetra draws. Findings are not assets: several findings usually describe the same asset."
        meta={
          <>
            <span>
              <strong className="numeric">{formatNumber(scan.progress.raw_findings_count)}</strong>{' '}
              findings across{' '}
              <strong className="numeric">{formatNumber(scan.progress.files_scanned)}</strong>{' '}
              scanned files
            </span>
          </>
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
              placeholder="Search symbol, path, algorithm"
              width="300px"
            />
            <Select
              label="Method"
              value={table.filters.method ?? ''}
              options={facetOptions(discovery?.findings_by_method)}
              onChange={(value) => table.setFilter('method', value)}
            />
            <Select
              label="Category"
              value={table.filters.category ?? ''}
              options={facetOptions(discovery?.findings_by_category)}
              onChange={(value) => table.setFilter('category', value)}
            />
            <Select
              label="Min confidence"
              value={table.filters.min_confidence ?? ''}
              allLabel="Any"
              options={[
                { value: '0.85', label: 'Very high (85%+)' },
                { value: '0.7', label: 'High (70%+)' },
                { value: '0.45', label: 'Medium (45%+)' },
              ]}
              onChange={(value) => table.setFilter('min_confidence', value)}
            />
          </FilterBar>

          {findings.isLoading && !findings.data && <SkeletonRows rows={10} columns={5} />}
          {findings.error && (
            <div className={styles.pad}>
              <ErrorState error={findings.error} onRetry={() => findings.refetch()} compact />
            </div>
          )}
          {findings.data && (
            <>
              <DataTable
                columns={columns}
                rows={findings.data.data}
                rowKey={(finding) => finding.finding_id}
                onRowClick={(finding) => setOpenFindingId(finding.finding_id)}
                activeRowKey={openFindingId}
                sort={table.sort}
                onSortChange={table.toggleSort}
                caption="Raw scanner findings"
                emptyState={
                  <EmptyState
                    title={
                      table.activeFilterCount > 0
                        ? 'No findings match these filters'
                        : 'No cryptographic evidence was detected'
                    }
                    description={
                      table.activeFilterCount > 0
                        ? 'Clear a filter to widen the search.'
                        : 'The scanners ran successfully and recorded no cryptographic artifacts in this target.'
                    }
                    compact
                  />
                }
              />
              <PaginationBar
                page={findings.data.pagination.page}
                pageSize={findings.data.pagination.page_size}
                totalItems={findings.data.pagination.total_items}
                totalPages={findings.data.pagination.total_pages}
                onPageChange={table.setPage}
                onPageSizeChange={table.setPageSize}
                noun="findings"
              />
            </>
          )}
        </Panel>
      </Section>

      <FindingDrawer
        scanId={scanId}
        findingId={openFindingId}
        onClose={() => setOpenFindingId(null)}
        onOpenAsset={(assetId) => {
          setOpenFindingId(null);
          setOpenAssetId(assetId);
        }}
      />
      <AssetDrawer scanId={scanId} assetId={openAssetId} onClose={() => setOpenAssetId(null)} />
    </>
  );
}
