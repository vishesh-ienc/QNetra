import { useMemo, useState } from 'react';
import { api } from '../api/endpoints';
import { useCbom } from '../api/queries';
import type { CbomComponent } from '../api/types';
import { formatDateTime, formatNumber, NOT_AVAILABLE, oneLine } from '../lib/format';
import { quantumThreatShort, quantumThreatTone } from '../lib/labels';
import { useTableState } from '../lib/useTableState';
import {
  Badge,
  Button,
  DataTable,
  Drawer,
  DrawerSection,
  EmptyState,
  ErrorState,
  FilterBar,
  KeyValue,
  PageHeader,
  PaginationBar,
  Panel,
  ResetFilters,
  SearchInput,
  Section,
  Select,
  SkeletonBlock,
  SkeletonRows,
  Stat,
  StatRow,
  type Column,
} from '../components/primitives';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import tableStyles from './Tables.module.css';
import styles from './CbomPage.module.css';

const PAGE_SIZE = 50;

function property(component: CbomComponent, name: string): string | null {
  return component.properties?.find((entry) => entry.name === name)?.value ?? null;
}

export function CbomPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const cbom = useCbom(scanId);
  const [openRef, setOpenRef] = useState<string | null>(null);
  const [xmlError, setXmlError] = useState<unknown>(null);
  const [exportingXml, setExportingXml] = useState(false);
  const table = useTableState({ pageSize: PAGE_SIZE });

  const document = cbom.data;

  const summary = useMemo(() => {
    const components = document?.components ?? [];
    const byAssetType: Record<string, number> = {};
    const byThreat: Record<string, number> = {};
    for (const component of components) {
      const assetType = component.cryptoProperties?.assetType ?? 'unknown';
      byAssetType[assetType] = (byAssetType[assetType] ?? 0) + 1;
      const threat = property(component, 'qnetra:quantum-threat-type') ?? 'UNKNOWN';
      byThreat[threat] = (byThreat[threat] ?? 0) + 1;
    }
    return { total: components.length, byAssetType, byThreat };
  }, [document]);

  // The CBOM endpoint returns the whole document. Filtering and paging it for
  // display is a presentation concern; the exported file is always the full document.
  const filtered = useMemo(() => {
    const components = document?.components ?? [];
    const search = table.search.trim().toLowerCase();
    return components.filter((component) => {
      const assetType = component.cryptoProperties?.assetType ?? 'unknown';
      if (table.filters.assetType && assetType !== table.filters.assetType) return false;
      if (
        table.filters.threat &&
        (property(component, 'qnetra:quantum-threat-type') ?? 'UNKNOWN') !== table.filters.threat
      )
        return false;
      if (!search) return true;
      const haystack = [
        component.name,
        component['bom-ref'],
        component.cryptoProperties?.algorithmProperties?.primitive,
        component.evidence?.occurrences?.[0]?.location,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(search);
    });
  }, [document, table.search, table.filters]);

  const paged = useMemo(() => {
    const start = (table.page - 1) * table.pageSize;
    return filtered.slice(start, start + table.pageSize);
  }, [filtered, table.page, table.pageSize]);

  const openComponent = useMemo(
    () => document?.components.find((component) => component['bom-ref'] === openRef) ?? null,
    [document, openRef],
  );

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const downloadXml = async () => {
    setExportingXml(true);
    setXmlError(null);
    try {
      const exported = await api.exportCbom(scanId, 'xml');
      saveFile(exported.content, exported.filename, exported.mediaType);
    } catch (caught) {
      setXmlError(caught);
    } finally {
      setExportingXml(false);
    }
  };

  const columns: Column<CbomComponent>[] = [
    {
      key: 'name',
      header: 'Component',
      render: (component) => (
        <div className={tableStyles.primaryCell}>
          <span className={`${tableStyles.primaryValue} mono`}>{component.name}</span>
          <span className={tableStyles.secondaryValue}>
            {component.cryptoProperties?.assetType ?? 'unknown'}
          </span>
        </div>
      ),
    },
    {
      key: 'primitive',
      header: 'Primitive',
      priority: 'lg',
      render: (component) => (
        <span className={`${tableStyles.muted} mono`}>
          {component.cryptoProperties?.algorithmProperties?.primitive ?? NOT_AVAILABLE}
        </span>
      ),
    },
    {
      key: 'parameters',
      header: 'Parameters',
      priority: 'xl',
      render: (component) => {
        const props = component.cryptoProperties?.algorithmProperties;
        const parts = [
          props?.parameterSetIdentifier,
          props?.curve,
          props?.mode,
          props?.padding,
        ].filter(Boolean);
        return parts.length ? (
          <span className={`${tableStyles.muted} mono`}>{parts.join(' · ')}</span>
        ) : (
          <span className={tableStyles.muted}>—</span>
        );
      },
    },
    {
      key: 'security',
      header: 'Classical bits',
      align: 'right',
      priority: 'xl',
      render: (component) => {
        const bits = component.cryptoProperties?.algorithmProperties?.classicalSecurityLevel;
        return (
          <span className={`${tableStyles.muted} numeric`}>
            {bits === undefined ? '—' : bits}
          </span>
        );
      },
    },
    {
      key: 'location',
      header: 'First occurrence',
      priority: 'lg',
      render: (component) => {
        const occurrence = component.evidence?.occurrences?.[0];
        if (!occurrence) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
        return (
          <span className={`${tableStyles.snippet} mono`} title={occurrence.location}>
            {occurrence.location}
            {occurrence.line ? `:${occurrence.line}` : ''}
          </span>
        );
      },
    },
    {
      key: 'threat',
      header: 'Quantum',
      align: 'right',
      width: '120px',
      render: (component) => {
        const threat = property(component, 'qnetra:quantum-threat-type');
        if (!threat) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
        const key = threat as keyof typeof quantumThreatShort;
        return (
          <Badge tone={quantumThreatTone[key] ?? 'UNKNOWN'} variant="dot" size="sm">
            {quantumThreatShort[key] ?? threat}
          </Badge>
        );
      },
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Inventory"
        title="CBOM"
        lede="The Cryptographic Bill of Materials, serialised by core.cbom_generator to the CycloneDX 1.6 cryptography extension. This is the artifact you hand to an auditor, a customer, or another tool — it is not a QNetra-specific format."
        meta={
          document && (
            <>
              <span className="mono">
                {document.bomFormat} {document.specVersion}
              </span>
              <span aria-hidden="true">·</span>
              <span className="mono">{document.serialNumber}</span>
              {typeof document.metadata?.timestamp === 'string' && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>{formatDateTime(document.metadata.timestamp)}</span>
                </>
              )}
            </>
          )
        }
        actions={
          document && (
            <Button variant="primary" onClick={() => downloadCbom(document, scanId)}>
              Download CycloneDX JSON
            </Button>
          )
        }
      />

      <Section divided={false}>
        {cbom.isLoading && <SkeletonBlock height={140} />}
        {cbom.error && <ErrorState error={cbom.error} onRetry={() => cbom.refetch()} />}
        {document && (
          <>
            <StatRow>
              <Stat label="Components" value={formatNumber(summary.total)} />
              {Object.entries(summary.byAssetType)
                .sort((a, b) => b[1] - a[1])
                .map(([assetType, count]) => (
                  <Stat
                    key={assetType}
                    label={assetType.replace(/-/g, ' ')}
                    value={formatNumber(count)}
                  />
                ))}
            </StatRow>
            <p className={styles.note}>
              Every component carries its discovery evidence under{' '}
              <span className="mono">evidence.occurrences</span> and QNetra&rsquo;s own analysis
              under <span className="mono">properties</span> with the{' '}
              <span className="mono">qnetra:</span> prefix, so the classification travels with the
              inventory instead of living only in this interface.
            </p>
          </>
        )}
      </Section>

      <Section
        eyebrow="Inspect"
        title="Every component"
        lede="Open a row to read the exact CycloneDX record QNetra emitted for it, including the raw JSON."
      >
        <Panel flush>
          <FilterBar
            trailing={<ResetFilters onReset={table.resetFilters} count={table.activeFilterCount} />}
          >
            <SearchInput
              value={table.search}
              onChange={table.setSearch}
              placeholder="Search component, primitive, path"
              width="300px"
            />
            <Select
              label="Asset type"
              value={table.filters.assetType ?? ''}
              options={Object.entries(summary.byAssetType).map(([value, count]) => ({
                value,
                label: value.replace(/-/g, ' '),
                count,
              }))}
              onChange={(value) => table.setFilter('assetType', value)}
            />
            <Select
              label="Quantum"
              value={table.filters.threat ?? ''}
              options={Object.entries(summary.byThreat).map(([value, count]) => ({
                value,
                label: value.replace(/_/g, ' ').toLowerCase(),
                count,
              }))}
              onChange={(value) => table.setFilter('threat', value)}
            />
          </FilterBar>

          {cbom.isLoading && <SkeletonRows rows={10} columns={5} />}
          {document && (
            <>
              <DataTable
                columns={columns}
                rows={paged}
                rowKey={(component) => component['bom-ref']}
                onRowClick={(component) => setOpenRef(component['bom-ref'])}
                activeRowKey={openRef}
                caption="CycloneDX components"
                emptyState={
                  <EmptyState
                    title="No components match these filters"
                    description="Clear a filter to widen the search."
                    compact
                  />
                }
              />
              <PaginationBar
                page={table.page}
                pageSize={table.pageSize}
                totalItems={filtered.length}
                totalPages={Math.max(1, Math.ceil(filtered.length / table.pageSize))}
                onPageChange={table.setPage}
                onPageSizeChange={table.setPageSize}
                noun="components"
              />
            </>
          )}
        </Panel>
      </Section>

      <Section eyebrow="Export" title="Formats" lede="What can be produced from this scan today.">
        <div className={styles.exports}>
          <div className={styles.exportRow}>
            <div>
              <p className={styles.exportName}>CycloneDX 1.6 JSON</p>
              <p className={styles.exportCopy}>
                The complete document as returned by the API, unmodified.
              </p>
            </div>
            {document && (
              <Button onClick={() => downloadCbom(document, scanId)}>Download</Button>
            )}
          </div>
          <div className={styles.exportRow}>
            <div>
              <p className={styles.exportName}>CycloneDX 1.6 XML</p>
              <p className={styles.exportCopy}>
                Served by <span className="mono">core.cbom_generator</span>&rsquo;s XML serialiser
                through <span className="mono">GET /scans/{'{id}'}/cbom/export?format=xml</span> —
                the same document, in the other CycloneDX wire format.
              </p>
            </div>
            <Button onClick={downloadXml} disabled={exportingXml}>
              {exportingXml ? 'Preparing…' : 'Download'}
            </Button>
          </div>
          {xmlError !== null && <ErrorState error={xmlError} compact />}
        </div>
      </Section>

      <Drawer
        open={Boolean(openComponent)}
        onClose={() => setOpenRef(null)}
        width="lg"
        eyebrow="CycloneDX component"
        title={openComponent?.name ?? ''}
        subtitle={
          openComponent && (
            <span className="mono">{openComponent.cryptoProperties?.assetType}</span>
          )
        }
      >
        {openComponent && (
          <>
            <DrawerSection title="Identity">
              <KeyValue
                items={[
                  { label: 'bom-ref', value: openComponent['bom-ref'], mono: true },
                  { label: 'Type', value: openComponent.type, mono: true },
                  {
                    label: 'Asset type',
                    value: openComponent.cryptoProperties?.assetType ?? NOT_AVAILABLE,
                    mono: true,
                  },
                  {
                    label: 'Primitive',
                    value:
                      openComponent.cryptoProperties?.algorithmProperties?.primitive ??
                      NOT_AVAILABLE,
                    mono: true,
                  },
                  {
                    label: 'Parameter set',
                    value:
                      openComponent.cryptoProperties?.algorithmProperties
                        ?.parameterSetIdentifier ?? NOT_AVAILABLE,
                    mono: true,
                  },
                  {
                    label: 'Classical security',
                    value:
                      openComponent.cryptoProperties?.algorithmProperties
                        ?.classicalSecurityLevel ?? NOT_AVAILABLE,
                  },
                ]}
              />
            </DrawerSection>

            {openComponent.properties && openComponent.properties.length > 0 && (
              <DrawerSection
                title="QNetra properties"
                description="QNetra's own analysis, carried inside the standard document."
              >
                <KeyValue
                  items={openComponent.properties.map((entry) => ({
                    label: entry.name.replace('qnetra:', ''),
                    value: entry.value,
                    mono: entry.value.length < 40,
                  }))}
                />
              </DrawerSection>
            )}

            {openComponent.evidence?.occurrences && (
              <DrawerSection title="Occurrences">
                <ul className={styles.occurrences}>
                  {openComponent.evidence.occurrences.map((occurrence, index) => (
                    <li key={`${occurrence.location}-${index}`} className={styles.occurrence}>
                      <span className={`${styles.occurrenceLocation} mono`}>
                        {occurrence.location}
                        {occurrence.line ? `:${occurrence.line}` : ''}
                      </span>
                      {occurrence.symbol && (
                        <span className={`${styles.occurrenceSymbol} mono`}>
                          {oneLine(occurrence.symbol, 120)}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </DrawerSection>
            )}

            <DrawerSection
              title="Raw record"
              description="Exactly what the CBOM serialiser emitted for this component."
            >
              <pre className={styles.raw}>{JSON.stringify(openComponent, null, 2)}</pre>
            </DrawerSection>
          </>
        )}
      </Drawer>
    </>
  );
}

/**
 * Module-level so it always resolves the real global `document` — the
 * component above shadows that name with the CBOM document it renders.
 */
function saveFile(content: string, filename: string, mediaType: string): void {
  const blob = new Blob([content], { type: mediaType });
  const url = URL.createObjectURL(blob);
  const link = window.document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/** Saves the document the API returned. Nothing is re-serialised or reformatted. */
function downloadCbom(document_: unknown, scanId: string): void {
  saveFile(JSON.stringify(document_, null, 2), `qnetra-cbom-${scanId}.json`, 'application/json');
}
