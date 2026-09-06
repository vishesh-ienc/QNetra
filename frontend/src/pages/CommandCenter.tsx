import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAssets, useMosca, useRecommendations, useRisk } from '../api/queries';
import type { CryptoAsset, MoscaUrgency, QuantumThreatType, Severity } from '../api/types';
import { formatNumber, formatYears, NOT_AVAILABLE, share } from '../lib/format';
import {
  HNDL_ORDER,
  hndlLabel,
  hndlTone,
  primitiveLabel,
  quantumThreatExplanation,
  quantumThreatLabel,
  quantumThreatShort,
  quantumThreatTone,
  RECOMMENDATION_ORDER,
  recommendationDescription,
  recommendationLabel,
  recommendationShort,
  recommendationTone,
  SEVERITY_ORDER,
  severityTone,
  URGENCY_ORDER,
  urgencyLabel,
  urgencyTone,
} from '../lib/labels';
import {
  Badge,
  CodeEvidence,
  DataTable,
  DistributionBar,
  EmptyState,
  ErrorState,
  Meter,
  PageHeader,
  PathRef,
  Panel,
  ScoreDial,
  Section,
  SectionNav,
  SkeletonBlock,
  SkeletonRows,
  Stat,
  StatRow,
  type Column,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useAssetIndex } from '../features/asset/useAssetIndex';
import { useScanContext } from '../state/useScanContext';
import { NoScanState } from './shared/NoScanState';
import styles from './CommandCenter.module.css';

const TOP_PRIORITY_COUNT = 8;
const FULL_INVENTORY_PAGE_SIZE = 200;

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview' },
  { id: 'risk', label: 'Risk' },
  { id: 'quantum', label: 'Quantum' },
  { id: 'mosca', label: 'Mosca' },
  { id: 'migration', label: 'Migration' },
  { id: 'assets', label: 'Assets' },
  { id: 'cbom', label: 'CBOM' },
  { id: 'evidence', label: 'Evidence' },
];

export function CommandCenter() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);

  const risk = useRisk(scanId);
  const mosca = useMosca(scanId);
  const recommendations = useRecommendations(scanId);
  const topAssets = useAssets(scanId, {
    sort: 'risk_score',
    order: 'desc',
    page_size: TOP_PRIORITY_COUNT,
  });
  // A wider page for the parts of this page that need breadth rather than
  // rank — the architecture breakdown and the evidence example. 130 assets
  // fit in one page today; a target large enough to exceed 200 is a case for
  // the full Crypto Assets view, not this summary.
  const allAssets = useAssets(scanId, { page_size: FULL_INVENTORY_PAGE_SIZE });
  const { moscaByAsset, recommendationByAsset } = useAssetIndex(scanId);

  const components = useMemo(
    () => groupByComponent(allAssets.data?.data ?? []),
    [allAssets.data],
  );

  const immediateMigrationItems = useMemo(() => {
    const rows = (topAssets.data?.data ?? [])
      .map((asset) => ({
        asset,
        urgency: moscaByAsset.get(asset.asset_id)?.urgency,
        recommendation: recommendationByAsset.get(asset.asset_id),
      }))
      .filter((row) => row.urgency === 'IMMEDIATE');
    return rows.slice(0, 5);
  }, [topAssets.data, moscaByAsset, recommendationByAsset]);

  if (!scanId || !scan) return <NoScanState />;
  if (!hasResults) return <NoScanState scanRunning />;

  const report = risk.data;
  const moscaReport = mosca.data;
  const recommendationReport = recommendations.data;

  const priorityColumns: Column<CryptoAsset>[] = [
    {
      key: 'rank',
      header: '#',
      width: '40px',
      render: (asset) => (
        <span className={`${styles.rank} numeric`}>
          {(topAssets.data?.data.indexOf(asset) ?? 0) + 1}
        </span>
      ),
    },
    {
      key: 'algorithm',
      header: 'Asset',
      render: (asset) => (
        <div className={styles.assetCell}>
          <span className={`${styles.assetName} mono`}>
            {asset.algorithm}
            {asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
          </span>
          <span className={styles.assetType}>{primitiveLabel[asset.primitive_type]}</span>
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
      key: 'quantum',
      header: 'Quantum',
      priority: 'xl',
      render: (asset) =>
        asset.quantum_threat_type ? (
          <Badge tone={quantumThreatTone[asset.quantum_threat_type]} variant="dot">
            {quantumThreatLabel[asset.quantum_threat_type]}
          </Badge>
        ) : (
          NOT_AVAILABLE
        ),
    },
    {
      key: 'urgency',
      header: 'Urgency',
      priority: 'lg',
      render: (asset) => {
        const assessment = moscaByAsset.get(asset.asset_id);
        if (!assessment) return NOT_AVAILABLE;
        return (
          <Badge tone={urgencyTone[assessment.urgency]}>{urgencyLabel[assessment.urgency]}</Badge>
        );
      },
    },
    {
      key: 'action',
      header: 'Recommended',
      render: (asset) => {
        const recommendation = recommendationByAsset.get(asset.asset_id);
        if (!recommendation) return NOT_AVAILABLE;
        return (
          <div className={styles.actionCell}>
            <span className="mono">{recommendation.recommended_algorithm ?? '—'}</span>
            <span className={styles.actionType}>
              {recommendationShort[recommendation.recommendation_type]}
            </span>
          </div>
        );
      },
    },
    {
      key: 'risk',
      header: 'Risk',
      align: 'right',
      width: '92px',
      render: (asset) => (
        <span className={`${styles.riskScore} numeric`} data-sev={asset.risk_severity ?? 'UNKNOWN'}>
          {asset.risk_score ?? NOT_AVAILABLE}
        </span>
      ),
    },
  ];

  const exampleAsset = topAssets.data?.data[0];
  const exampleFinding = exampleAsset?.supporting_findings[0];

  return (
    <>
      <PageHeader
        eyebrow="Command Center"
        title="Cryptographic posture"
        lede={
          report ? (
            <>
              QNetra recorded{' '}
              <strong>{formatNumber(scan.progress.raw_findings_count)}</strong> pieces of
              cryptographic evidence across this target and normalized them into{' '}
              <strong>{formatNumber(report.total_assets_discovered)}</strong> distinct
              cryptographic assets.{' '}
              <strong>{formatNumber(report.vulnerable_assets_count)}</strong> of them are
              classified as vulnerable.
            </>
          ) : (
            'Reading the assessment produced by the analysis pipeline.'
          )
        }
        meta={
          <>
            <span className="mono">{scan.target.path}</span>
            <span aria-hidden="true">·</span>
            <Link to="/scan" className={styles.metaLink}>
              View pipeline run
            </Link>
          </>
        }
      />

      <SectionNav items={NAV_ITEMS} />

      {/* ================= 1. Overview — how bad is it ================= */}
      <Section divided={false} id="overview">
        {risk.isLoading && <SkeletonBlock height={220} />}
        {risk.error && <ErrorState error={risk.error} onRetry={() => risk.refetch()} />}
        {report && (
          <div className={styles.verdict}>
            <div className={styles.verdictDial}>
              <ScoreDial
                score={report.overall_risk_score}
                label="Overall risk"
                tone={severityTone[report.overall_severity]}
                size={200}
              />
              <Badge tone={severityTone[report.overall_severity]} variant="solid">
                {report.overall_severity}
              </Badge>
            </div>

            <div className={styles.verdictBody}>
              <p className={styles.verdictLede}>{verdictSentence(report.overall_severity)}</p>
              <p className={styles.verdictDetail}>
                The score is computed by <span className="mono">core.risk_engine</span> from the
                classification of every discovered asset — algorithm strength, quantum threat
                class, and observed parameters. Every figure on this page traces back to a
                specific finding at a specific line of code.
              </p>

              <StatRow>
                <Stat
                  label="Quantum vulnerable"
                  value={formatNumber(
                    report.shor_vulnerable_count +
                      report.grover_impacted_count +
                      report.classically_broken_count,
                  )}
                  hint={`of ${formatNumber(report.total_assets_discovered)} assets`}
                />
                <Stat
                  label="Critical severity"
                  value={formatNumber(report.severity_distribution.CRITICAL)}
                  tone="CRITICAL"
                  hint="Highest-scoring assets"
                />
                <Stat
                  label="Immediate urgency"
                  value={
                    moscaReport ? formatNumber(moscaReport.urgency_distribution.IMMEDIATE) : '—'
                  }
                  tone="CRITICAL"
                  hint="Mosca — begin migration now"
                />
                <Stat
                  label="Quantum resistant"
                  value={formatNumber(report.quantum_resistant_count)}
                  tone="SAFE"
                  hint="No migration required"
                />
              </StatRow>
            </div>
          </div>
        )}
      </Section>

      {/* ================= 2. Architecture — where is the problem ================= */}
      <Section
        eyebrow="Architecture"
        title="Where risk concentrates"
        lede="Assets grouped by the top-level directory the scanner found them in — the closest thing to a system boundary this pipeline can genuinely observe from file paths alone. QNetra does not infer service or system names it wasn't told."
      >
        {allAssets.isLoading && <SkeletonBlock height={200} />}
        {allAssets.error && <ErrorState error={allAssets.error} compact />}
        {components.length > 0 && (
          <div className={styles.componentList}>
            {components.map((component) => (
              <div key={component.name} className={styles.componentRow}>
                <div className={styles.componentHead}>
                  <span className={`${styles.componentName} mono`}>{component.name}</span>
                  <span className={styles.componentMeta}>
                    {formatNumber(component.total)} asset{component.total === 1 ? '' : 's'}
                    {component.critical > 0 && (
                      <>
                        {' '}
                        ·{' '}
                        <span data-sev="CRITICAL" className={styles.componentCritical}>
                          {formatNumber(component.critical)} critical
                        </span>
                      </>
                    )}
                  </span>
                </div>
                <Meter
                  value={report ? share(component.total, report.total_assets_discovered) : 0}
                  tone={component.critical > 0 ? 'CRITICAL' : 'ACCENT'}
                  size="sm"
                />
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* ================= 3. Priority actions — why + what to do ================= */}
      <Section
        eyebrow="Priority"
        title="What needs attention"
        lede="The highest-risk assets, explained rather than just listed. Each one names what was found, where, why it matters, how urgent it is, and what to do about it."
      >
        {topAssets.isLoading && <SkeletonBlock height={260} />}
        {topAssets.data && (
          <ol className={styles.priorityList}>
            {topAssets.data.data.slice(0, 5).map((asset, index) => {
              const assessment = moscaByAsset.get(asset.asset_id);
              const recommendation = recommendationByAsset.get(asset.asset_id);
              return (
                <li
                  key={asset.asset_id}
                  className={styles.priorityItem}
                  data-sev={asset.risk_severity ?? 'UNKNOWN'}
                >
                  <button
                    type="button"
                    className={styles.priorityButton}
                    onClick={() => setOpenAssetId(asset.asset_id)}
                  >
                    <span className={`${styles.priorityRank} numeric`}>{index + 1}</span>
                    <div className={styles.priorityBody}>
                      <div className={styles.priorityWhat}>
                        <span className={`${styles.priorityAlgorithm} mono`}>
                          {asset.algorithm}
                          {asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
                        </span>
                        <Badge tone={severityTone[asset.risk_severity ?? 'LOW']} size="sm">
                          {asset.risk_severity ?? 'UNKNOWN'}
                        </Badge>
                        {asset.quantum_threat_type && (
                          <Badge tone={quantumThreatTone[asset.quantum_threat_type]} variant="dot" size="sm">
                            {quantumThreatShort[asset.quantum_threat_type]}
                          </Badge>
                        )}
                      </div>
                      <p className={styles.priorityWhere}>
                        <PathRef
                          filePath={asset.location.file_path}
                          line={asset.location.start_line}
                        />
                      </p>
                      <p className={styles.priorityWhy}>
                        {asset.classification_notes ??
                          `Risk score ${asset.risk_score ?? NOT_AVAILABLE}/100 assigned by core.risk_engine.`}
                      </p>
                      <div className={styles.priorityFooter}>
                        <span className={styles.priorityUrgency}>
                          {assessment
                            ? `Mosca: ${urgencyLabel[assessment.urgency]}`
                            : 'Mosca: not evaluated'}
                        </span>
                        <span className={styles.priorityAction}>
                          → {recommendation?.recommended_algorithm ?? 'No replacement required'}
                        </span>
                      </div>
                    </div>
                  </button>
                </li>
              );
            })}
          </ol>
        )}
      </Section>

      {/* ================= 4. Risk — distribution + full ranking ================= */}
      <Section
        id="risk"
        eyebrow="Risk"
        title="Severity distribution and full ranking"
        lede="Every asset gets exactly one severity tier from core.risk_engine. This is the complete ranked list, not a sample — open a row for the evidence behind its score."
        actions={
          <Link to="/risk" className={styles.sectionLink}>
            Full risk page →
          </Link>
        }
      >
        {report && (
          <div className={styles.severityBlock}>
            <DistributionBar
              total={report.total_assets_discovered}
              segments={SEVERITY_ORDER.map((severity) => ({
                key: severity,
                label: severity,
                count: report.severity_distribution[severity] ?? 0,
                tone: severityTone[severity],
              }))}
            />
            <ul className={styles.legend}>
              {SEVERITY_ORDER.map((severity) => {
                const count = report.severity_distribution[severity] ?? 0;
                return (
                  <li key={severity} className={styles.legendRow} data-sev={severityTone[severity]}>
                    <span className={styles.legendLabel}>{severity}</span>
                    <Meter
                      value={share(count, report.total_assets_discovered)}
                      tone={severityTone[severity]}
                      size="sm"
                    />
                    <span className={`${styles.legendCount} numeric`}>{formatNumber(count)}</span>
                  </li>
                );
              })}
            </ul>
            <p className={styles.legendNote}>
              Severity is the risk engine&rsquo;s own tier for each asset, not a count of files or
              findings. One critical asset can appear at many call sites.
            </p>
          </div>
        )}

        <Panel flush className={styles.rankingPanel}>
          {topAssets.isLoading && <SkeletonRows rows={6} columns={5} />}
          {topAssets.error && (
            <div className={styles.panelPad}>
              <ErrorState error={topAssets.error} onRetry={() => topAssets.refetch()} compact />
            </div>
          )}
          {topAssets.data && (
            <DataTable
              columns={priorityColumns}
              rows={topAssets.data.data}
              rowKey={(asset) => asset.asset_id}
              onRowClick={(asset) => setOpenAssetId(asset.asset_id)}
              activeRowKey={openAssetId}
              caption="Highest-risk cryptographic assets"
              emptyState={
                <EmptyState
                  title="No cryptographic assets were discovered"
                  description="The scan completed successfully and found no cryptographic usage in this target."
                  compact
                />
              }
            />
          )}
        </Panel>
      </Section>

      {/* ================= 5. Quantum exposure ================= */}
      <Section
        id="quantum"
        eyebrow="Quantum"
        title="What a quantum adversary does to this inventory"
        lede="Every asset is placed in exactly one threat class by core.classification, based on the algorithm and the parameters actually observed."
        actions={
          <Link to="/quantum" className={styles.sectionLink}>
            Quantum exposure in detail →
          </Link>
        }
      >
        {report && (
          <ul className={styles.threatList}>
            {quantumRows(report).map((row) => (
              <li key={row.key} className={styles.threat} data-sev={quantumThreatTone[row.key]}>
                <div className={styles.threatHead}>
                  <span className={styles.threatLabel}>{quantumThreatLabel[row.key]}</span>
                  <span className={`${styles.threatCount} numeric`}>{formatNumber(row.count)}</span>
                </div>
                <Meter
                  value={share(row.count, report.total_assets_discovered)}
                  tone={quantumThreatTone[row.key]}
                  size="sm"
                />
                <p className={styles.threatCopy}>{quantumThreatExplanation[row.key]}</p>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {/* ================= 6. Mosca / HNDL — how urgent ================= */}
      <Section
        id="mosca"
        eyebrow="Timing"
        title="How urgent is this — Mosca and HNDL"
        lede={
          <>
            Mosca&rsquo;s inequality asks whether the data you protect today outlives the arrival
            of a quantum computer capable of breaking it:{' '}
            <span className="mono">X + Y &gt; Z</span>. Harvest-now-decrypt-later asks whether an
            adversary could be capturing that data already.
          </>
        }
        actions={
          <Link to="/mosca" className={styles.sectionLink}>
            Explore the parameters →
          </Link>
        }
      >
        {mosca.isLoading && <SkeletonBlock height={160} />}
        {mosca.error && <ErrorState error={mosca.error} compact />}
        {moscaReport && (
          <div className={styles.mosca}>
            <div className={styles.moscaStatement}>
              <p className={styles.moscaHeadline}>
                <strong className="numeric">
                  {formatNumber(moscaReport.mosca_triggered_assets)}
                </strong>{' '}
                of {formatNumber(moscaReport.mosca_applicable_assets)} applicable assets fail the
                inequality
              </p>
              <p className={styles.moscaParams}>
                Assessed with a data shelf life (X) of{' '}
                <strong>{formatYears(moscaReport.parameters.data_shelf_life_years_x)}</strong> and a
                quantum horizon (Z) of{' '}
                <strong>{formatYears(moscaReport.parameters.quantum_threat_horizon_years_z)}</strong>
                . Migration time (Y) is derived per primitive type by the engine.
              </p>
              <p className={styles.moscaNote}>
                X is a policy input about your own data, not something a scanner can discover.
                Change it on the Mosca page to see the assessment recomputed.
              </p>
            </div>

            <div className={styles.moscaBreakdown}>
              <div>
                <p className="eyebrow">Migration urgency</p>
                <ul className={styles.miniList}>
                  {URGENCY_ORDER.filter(
                    (urgency) => (moscaReport.urgency_distribution[urgency] ?? 0) > 0,
                  ).map((urgency: MoscaUrgency) => (
                    <li key={urgency} className={styles.miniRow} data-sev={urgencyTone[urgency]}>
                      <span className={styles.legendDot} aria-hidden="true" />
                      <span className={styles.miniLabel}>{urgencyLabel[urgency]}</span>
                      <span className={`${styles.miniCount} numeric`}>
                        {formatNumber(moscaReport.urgency_distribution[urgency])}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <p className="eyebrow">Harvest-now-decrypt-later exposure</p>
                <ul className={styles.miniList}>
                  {HNDL_ORDER.filter(
                    (exposure) => (moscaReport.hndl_distribution[exposure] ?? 0) > 0,
                  ).map((exposure) => (
                    <li key={exposure} className={styles.miniRow} data-sev={hndlTone[exposure]}>
                      <span className={styles.legendDot} aria-hidden="true" />
                      <span className={styles.miniLabel}>{hndlLabel[exposure]}</span>
                      <span className={`${styles.miniCount} numeric`}>
                        {formatNumber(moscaReport.hndl_distribution[exposure])}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </Section>

      {/* ================= 7. Migration roadmap — what + how long ================= */}
      <Section
        id="migration"
        eyebrow="Response"
        title="Migration roadmap"
        lede="The recommendation engine classifies every asset by the kind of change it needs. A classical upgrade is not post-quantum cryptography, and QNetra never labels it as such."
        actions={
          <Link to="/migration" className={styles.sectionLink}>
            Build the migration plan →
          </Link>
        }
      >
        {recommendations.isLoading && <SkeletonBlock height={180} />}
        {recommendations.error && <ErrorState error={recommendations.error} compact />}
        {recommendationReport && (
          <div className={styles.response}>
            <ul className={styles.approachList}>
              {RECOMMENDATION_ORDER.map((type) => {
                const count = recommendationCount(recommendationReport, type);
                if (count === 0) return null;
                return (
                  <li key={type} className={styles.approach} data-sev={recommendationTone[type]}>
                    <div className={styles.approachHead}>
                      <span className={`${styles.approachCount} numeric`}>
                        {formatNumber(count)}
                      </span>
                      <span className={styles.approachLabel}>{recommendationLabel[type]}</span>
                    </div>
                    <p className={styles.approachCopy}>{recommendationDescription[type]}</p>
                  </li>
                );
              })}
            </ul>

            <Panel
              eyebrow="Target algorithms"
              title="What QNetra recommends migrating to"
              description="Counted across every asset that received a replacement recommendation."
            >
              <ul className={styles.targetList}>
                {Object.entries(recommendationReport.recommendations_by_target_algorithm)
                  .sort((a, b) => b[1] - a[1])
                  .map(([algorithm, count]) => (
                    <li key={algorithm} className={styles.targetRow}>
                      <span className={`${styles.targetName} mono`}>{algorithm}</span>
                      <Meter
                        value={share(count, recommendationReport.total_assets)}
                        tone="ACCENT"
                        size="sm"
                      />
                      <span className={`${styles.targetCount} numeric`}>{count}</span>
                    </li>
                  ))}
              </ul>
            </Panel>
          </div>
        )}

        {immediateMigrationItems.length > 0 && (
          <div className={styles.immediateBlock}>
            <p className="eyebrow">Start here — immediate urgency, highest risk first</p>
            <ul className={styles.immediateList}>
              {immediateMigrationItems.map(({ asset, recommendation }) => (
                <li key={asset.asset_id} className={styles.immediateRow}>
                  <button
                    type="button"
                    className={styles.immediateButton}
                    onClick={() => setOpenAssetId(asset.asset_id)}
                  >
                    <span className={`${styles.immediateCurrent} mono`}>
                      {asset.algorithm}
                      {asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
                    </span>
                    <span className={styles.immediateArrow} aria-hidden="true">
                      →
                    </span>
                    <span className={`${styles.immediateTarget} mono`}>
                      {recommendation?.recommended_algorithm ?? 'No replacement required'}
                    </span>
                    <PathRef
                      filePath={asset.location.file_path}
                      line={asset.location.start_line}
                    />
                    {recommendation && (
                      <Badge tone="MEDIUM" size="sm">
                        {recommendation.migration_complexity} effort
                      </Badge>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Section>

      {/* ================= 8. Crypto asset inventory ================= */}
      <Section
        id="assets"
        eyebrow="Inventory"
        title="Crypto asset inventory"
        lede="The full canonical inventory lives on its own page with search, filtering and pagination. Here is the shape of it: how the discovered cryptography breaks down by primitive type."
        actions={
          <Link to="/assets" className={styles.sectionLink}>
            Open the full inventory →
          </Link>
        }
      >
        {scan.normalization && (
          <ul className={styles.primitiveList}>
            {Object.entries(scan.normalization.assets_by_primitive_type)
              .sort((a, b) => b[1] - a[1])
              .map(([type, count]) => (
                <li key={type} className={styles.primitiveRow}>
                  <span className={styles.primitiveName}>
                    {primitiveLabel[type as CryptoAsset['primitive_type']] ?? type}
                  </span>
                  <Meter
                    value={share(count, scan.normalization?.assets_produced_count ?? 1)}
                    tone="ACCENT"
                    size="sm"
                  />
                  <span className={`${styles.primitiveCount} numeric`}>{count}</span>
                </li>
              ))}
          </ul>
        )}
      </Section>

      {/* ================= 9. CBOM ================= */}
      <Section
        id="cbom"
        eyebrow="Inventory"
        title="Cryptography Bill of Materials"
        lede="Every discovered asset becomes exactly one CycloneDX 1.6 component. The full CBOM view is searchable and exportable as JSON or XML."
        actions={
          <Link to="/cbom" className={styles.sectionLink}>
            Inspect the CBOM →
          </Link>
        }
      >
        {report && (
          <StatRow>
            <Stat label="Components" value={formatNumber(report.total_assets_discovered)} />
            <Stat
              label="Quantum vulnerable"
              value={formatNumber(report.vulnerable_assets_count)}
              tone="CRITICAL"
            />
            <Stat
              label="Quantum resistant"
              value={formatNumber(report.quantum_resistant_count)}
              tone="SAFE"
            />
          </StatRow>
        )}
      </Section>

      {/* ================= 10. Evidence ================= */}
      <Section
        id="evidence"
        eyebrow="Verification"
        title="Why do we think this?"
        lede="Every conclusion on this page traces back to a scanner observation at a specific location. Open any asset to see its full evidence trail — here is one, so the claim is not abstract."
      >
        {exampleFinding && exampleAsset && (
          <div className={styles.evidenceExample}>
            <p className={styles.evidenceIntro}>
              For example, QNetra classified{' '}
              <strong className="mono">
                {exampleAsset.algorithm}
                {exampleAsset.key_length_bits ? `-${exampleAsset.key_length_bits}` : ''}
              </strong>{' '}
              as {exampleAsset.risk_severity?.toLowerCase() ?? 'unclassified'} risk because of this:
            </p>
            <CodeEvidence
              filePath={exampleFinding.location.file_path}
              startLine={exampleFinding.location.start_line}
              endLine={exampleFinding.location.end_line}
              snippet={exampleFinding.location.snippet}
              symbol={exampleFinding.raw_symbol}
            />
            <p className={styles.evidenceRationale}>{exampleFinding.confidence_rationale}</p>
            <button
              type="button"
              className={styles.sectionLink}
              onClick={() => setOpenAssetId(exampleAsset.asset_id)}
            >
              Open this asset&rsquo;s full evidence trail →
            </button>
          </div>
        )}
      </Section>

      <AssetDrawer scanId={scanId} assetId={openAssetId} onClose={() => setOpenAssetId(null)} />
    </>
  );
}

/* --- Local helpers -------------------------------------------------------- */

function verdictSentence(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return 'This environment carries critical cryptographic risk.';
    case 'HIGH':
      return 'This environment carries high cryptographic risk.';
    case 'MEDIUM':
      return 'This environment carries moderate cryptographic risk.';
    default:
      return 'This environment carries low cryptographic risk.';
  }
}

function quantumRows(report: {
  shor_vulnerable_count: number;
  grover_impacted_count: number;
  classically_broken_count: number;
  quantum_resistant_count: number;
}): { key: QuantumThreatType; count: number }[] {
  return [
    { key: 'SHOR_POLYNOMIAL_BREAK', count: report.shor_vulnerable_count },
    { key: 'CLASSICALLY_BROKEN', count: report.classically_broken_count },
    { key: 'GROVER_BIT_HALVING', count: report.grover_impacted_count },
    { key: 'QUANTUM_RESISTANT', count: report.quantum_resistant_count },
  ];
}

function recommendationCount(
  report: {
    direct_pqc_count: number;
    hybrid_count: number;
    classical_upgrade_count: number;
    already_pqc_count: number;
    no_migration_required_count: number;
    unknown_count: number;
  },
  type: string,
): number {
  switch (type) {
    case 'DIRECT_PQC':
      return report.direct_pqc_count;
    case 'HYBRID':
      return report.hybrid_count;
    case 'CLASSICAL_UPGRADE':
      return report.classical_upgrade_count;
    case 'ALREADY_PQC':
      return report.already_pqc_count;
    case 'NO_MIGRATION_REQUIRED':
      return report.no_migration_required_count;
    default:
      return report.unknown_count;
  }
}

interface ComponentGroup {
  name: string;
  total: number;
  critical: number;
}

/**
 * Groups assets by the top-level path segment of their discovery location —
 * the only "system" boundary genuinely present in the data. This is a
 * presentation grouping over real location metadata, not an invented
 * architecture model: QNetra does not know what a "service" or "system" is,
 * only where in the file tree an asset was found.
 */
function groupByComponent(assets: CryptoAsset[]): ComponentGroup[] {
  const groups = new Map<string, ComponentGroup>();
  for (const asset of assets) {
    const segments = asset.location.file_path.split('/').filter(Boolean);
    const name = segments.length > 1 ? segments[0] : '(root)';
    const group = groups.get(name) ?? { name, total: 0, critical: 0 };
    group.total += 1;
    if (asset.risk_severity === 'CRITICAL') group.critical += 1;
    groups.set(name, group);
  }
  return Array.from(groups.values()).sort((a, b) => b.critical - a.critical || b.total - a.total);
}
