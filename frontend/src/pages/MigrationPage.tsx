import { useMemo, useState } from 'react';
import { useAssets, useMosca, useRecommendations } from '../api/queries';
import type { CryptoAsset, MoscaUrgency, PqcRecommendation } from '../api/types';
import { formatNumber, NOT_AVAILABLE } from '../lib/format';
import {
  complexityTone,
  primitiveLabel,
  RECOMMENDATION_ORDER,
  recommendationDescription,
  recommendationLabel,
  recommendationShort,
  recommendationTone,
  URGENCY_ORDER,
  urgencyDescription,
  urgencyLabel,
  urgencyTone,
} from '../lib/labels';
import {
  Badge,
  DataTable,
  EmptyState,
  ErrorState,
  PageHeader,
  PathRef,
  Panel,
  Section,
  Segmented,
  SkeletonBlock,
  Stat,
  StatRow,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import tableStyles from './Tables.module.css';
import styles from './MigrationPage.module.css';

type GroupMode = 'urgency' | 'approach';

/** Rows shown per bucket before the reader asks for the rest. */
const BUCKET_PREVIEW = 12;

interface MigrationRow {
  asset: CryptoAsset;
  recommendation: PqcRecommendation | null;
  urgency: MoscaUrgency | null;
}

export function MigrationPage() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);
  const [group, setGroup] = useState<GroupMode>('urgency');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const recommendations = useRecommendations(scanId);
  const mosca = useMosca(scanId);
  // The plan is a whole-inventory view; it is grouped, not paged.
  const assets = useAssets(scanId, { page_size: 200, sort: 'risk_score', order: 'desc' });

  const rows = useMemo<MigrationRow[]>(() => {
    const recommendationByAsset = new Map(
      (recommendations.data?.recommendations ?? []).map((entry) => [entry.asset_id, entry]),
    );
    const urgencyByAsset = new Map(
      (mosca.data?.assessments ?? []).map((entry) => [entry.asset_id, entry.urgency]),
    );
    return (assets.data?.data ?? []).map((asset) => ({
      asset,
      recommendation: recommendationByAsset.get(asset.asset_id) ?? null,
      urgency: urgencyByAsset.get(asset.asset_id) ?? null,
    }));
  }, [assets.data, recommendations.data, mosca.data]);

  /**
   * Grouping only. The bucket an asset lands in is the urgency the Mosca engine
   * assigned it, or the recommendation type the recommendation engine assigned it.
   * No timeframe, deadline or ordering is invented here.
   */
  const groups = useMemo(() => {
    if (group === 'urgency') {
      return URGENCY_ORDER.map((key) => ({
        key,
        label: urgencyLabel[key],
        description: urgencyDescription[key],
        tone: urgencyTone[key],
        rows: rows.filter((row) => row.urgency === key),
      })).filter((bucket) => bucket.rows.length > 0);
    }
    return RECOMMENDATION_ORDER.map((key) => ({
      key,
      label: recommendationLabel[key],
      description: recommendationDescription[key],
      tone: recommendationTone[key],
      rows: rows.filter((row) => row.recommendation?.recommendation_type === key),
    })).filter((bucket) => bucket.rows.length > 0);
  }, [group, rows]);

  const columns: Column<MigrationRow>[] = [
    {
      key: 'asset',
      header: 'Current',
      render: (row) => (
        <div className={tableStyles.primaryCell}>
          <span className={`${tableStyles.primaryValue} mono`}>
            {row.asset.algorithm}
            {row.asset.key_length_bits ? `-${row.asset.key_length_bits}` : ''}
          </span>
          <span className={tableStyles.secondaryValue}>
            {primitiveLabel[row.asset.primitive_type]}
          </span>
        </div>
      ),
    },
    {
      key: 'location',
      header: 'Location',
      priority: 'lg',
      render: (row) => (
        <PathRef filePath={row.asset.location.file_path} line={row.asset.location.start_line} />
      ),
    },
    {
      key: 'target',
      header: 'Migrate to',
      render: (row) => {
        if (!row.recommendation) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
        return (
          <div className={tableStyles.primaryCell}>
            <span className={`${styles.target} mono`}>
              {row.recommendation.recommended_algorithm ?? 'No replacement required'}
            </span>
            {row.recommendation.pqc_standard && (
              <span className={styles.standard}>{row.recommendation.pqc_standard}</span>
            )}
          </div>
        );
      },
    },
    {
      key: 'hybrid',
      header: 'Hybrid scheme',
      priority: 'xl',
      render: (row) =>
        row.recommendation?.hybrid_recommendation ? (
          <span className={`${tableStyles.muted} mono`}>
            {row.recommendation.hybrid_recommendation}
          </span>
        ) : (
          <span className={tableStyles.muted}>—</span>
        ),
    },
    {
      key: 'approach',
      header: group === 'urgency' ? 'Approach' : 'Urgency',
      priority: 'lg',
      render: (row) => {
        if (group === 'urgency') {
          if (!row.recommendation) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
          return (
            <Badge tone={recommendationTone[row.recommendation.recommendation_type]} size="sm">
              {recommendationShort[row.recommendation.recommendation_type]}
            </Badge>
          );
        }
        if (!row.urgency) return <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>;
        return (
          <Badge tone={urgencyTone[row.urgency]} size="sm">
            {urgencyLabel[row.urgency]}
          </Badge>
        );
      },
    },
    {
      key: 'complexity',
      header: 'Effort',
      align: 'right',
      width: '96px',
      render: (row) =>
        row.recommendation ? (
          <Badge tone={complexityTone[row.recommendation.migration_complexity]} size="sm">
            {row.recommendation.migration_complexity}
          </Badge>
        ) : (
          <span className={tableStyles.muted}>{NOT_AVAILABLE}</span>
        ),
    },
  ];

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const report = recommendations.data;
  const isLoading = assets.isLoading || recommendations.isLoading || mosca.isLoading;

  return (
    <>
      <PageHeader
        eyebrow="Response"
        title="PQC migration"
        lede="Every discovered asset with the change it needs, grouped by how soon the Mosca engine says it needs it. Replacements come from core.recommendation_engine against the NIST post-quantum standards — QNetra does not choose algorithms in the interface."
      />

      <Section divided={false}>
        {recommendations.error && (
          <ErrorState error={recommendations.error} onRetry={() => recommendations.refetch()} />
        )}
        {report && (
          <>
            <StatRow>
              <Stat
                label="Direct PQC replacement"
                value={formatNumber(report.direct_pqc_count)}
                hint="Classical primitive swapped for a NIST PQC algorithm"
              />
              <Stat
                label="Hybrid transition"
                value={formatNumber(report.hybrid_count)}
                hint="Classical and post-quantum in parallel"
              />
              <Stat
                label="Classical upgrade"
                value={formatNumber(report.classical_upgrade_count)}
                tone="MEDIUM"
                hint="Stronger classical crypto — not post-quantum"
              />
              <Stat
                label="No migration required"
                value={formatNumber(report.no_migration_required_count)}
                tone="SAFE"
                hint="Outside algorithm replacement"
              />
              <Stat
                label="Undetermined"
                value={formatNumber(report.unknown_count)}
                tone="UNKNOWN"
                hint="Engine declined to guess"
              />
            </StatRow>

            <p className={styles.caution}>
              A classical upgrade such as <span className="mono">SHA-256 → SHA-384</span> or{' '}
              <span className="mono">AES-128 → AES-256-GCM</span> restores classical and Grover
              margin. It is not post-quantum cryptography, and QNetra keeps the two categories
              distinct so a hardened classical algorithm is never mistaken for a PQC one.
            </p>
          </>
        )}
      </Section>

      <Section
        eyebrow="Plan"
        title="The work, in order"
        lede="Buckets are the engines' own classifications, not a schedule invented by the interface. Open any row for the migration steps and the evidence behind the recommendation."
        actions={
          <Segmented<GroupMode>
            ariaLabel="Group migration plan by"
            value={group}
            onChange={setGroup}
            options={[
              { value: 'urgency', label: 'By urgency' },
              { value: 'approach', label: 'By approach' },
            ]}
          />
        }
      >
        {isLoading && <SkeletonBlock height={320} />}

        {!isLoading && groups.length === 0 && (
          <EmptyState
            title="No migration items"
            description="No assets were returned for this scan, so there is nothing to plan."
          />
        )}

        <div className={styles.buckets}>
          {groups.map((bucket) => {
            const isExpanded = expanded[bucket.key] ?? false;
            const visible = isExpanded ? bucket.rows : bucket.rows.slice(0, BUCKET_PREVIEW);
            const hidden = bucket.rows.length - visible.length;
            return (
              <section className={styles.bucket} key={bucket.key} data-sev={bucket.tone}>
                <header className={styles.bucketHead}>
                  <div className={styles.bucketHeading}>
                    <span className={styles.bucketMark} aria-hidden="true" />
                    <h3 className={styles.bucketTitle}>{bucket.label}</h3>
                    <span className={`${styles.bucketCount} numeric`}>
                      {formatNumber(bucket.rows.length)}
                    </span>
                  </div>
                  <p className={styles.bucketCopy}>{bucket.description}</p>
                </header>
                <Panel flush>
                  <DataTable
                    columns={columns}
                    rows={visible}
                    rowKey={(row) => row.asset.asset_id}
                    onRowClick={(row) => setOpenAssetId(row.asset.asset_id)}
                    activeRowKey={openAssetId}
                    caption={`Migration items — ${bucket.label}`}
                  />
                  {(hidden > 0 || isExpanded) && (
                    <button
                      type="button"
                      className={styles.expand}
                      onClick={() =>
                        setExpanded((current) => ({ ...current, [bucket.key]: !isExpanded }))
                      }
                    >
                      {isExpanded
                        ? `Collapse to first ${BUCKET_PREVIEW}`
                        : `Show ${formatNumber(hidden)} more in ${bucket.label.toLowerCase()}`}
                    </button>
                  )}
                </Panel>
              </section>
            );
          })}
        </div>

        {assets.data && assets.data.pagination.total_items > rows.length && (
          <p className={styles.truncation}>
            Showing {formatNumber(rows.length)} of{' '}
            {formatNumber(assets.data.pagination.total_items)} assets. The API caps a page at 200
            rows; use the Crypto Assets view to work through the full inventory.
          </p>
        )}
      </Section>

      <AssetDrawer scanId={scanId} assetId={openAssetId} onClose={() => setOpenAssetId(null)} />
    </>
  );
}
