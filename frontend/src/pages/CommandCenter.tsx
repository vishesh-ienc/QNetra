import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAssets, useCbom, useMosca, useRecommendations, useRisk } from '../api/queries';
import { formatDuration, formatNumber, NOT_AVAILABLE } from '../lib/format';
import {
  RECOMMENDATION_ORDER,
  recommendationLabel,
  recommendationShort,
  recommendationTone,
  quantumThreatShort,
  quantumThreatTone,
  severityTone,
  urgencyLabel,
} from '../lib/labels';
import {
  Badge,
  CodeEvidence,
  ErrorState,
  PageHeader,
  PathRef,
  ScoreDial,
  Section,
  SkeletonBlock,
  Stat,
  StatRow,
} from '../components/primitives';
import { AssetDrawer } from '../features/asset/AssetDrawer';
import { useAssetIndex } from '../features/asset/useAssetIndex';
import { useScanContext } from '../state/useScanContext';
import { ScanGate } from './shared/ScanGate';
import styles from './CommandCenter.module.css';

const TOP_PRIORITY_COUNT = 8;

export function CommandCenter() {
  const { scanId, scan, hasResults } = useScanContext();
  const [openAssetId, setOpenAssetId] = useState<string | null>(null);

  const risk = useRisk(scanId);
  const mosca = useMosca(scanId);
  const recommendations = useRecommendations(scanId);
  const cbom = useCbom(scanId);
  const topAssets = useAssets(scanId, {
    sort: 'risk_score',
    order: 'desc',
    page_size: TOP_PRIORITY_COUNT,
  });
  const { moscaByAsset, recommendationByAsset } = useAssetIndex(scanId);

  if (!scanId || !scan) return <Navigate to="/scan" replace />;
  if (!hasResults) return <ScanGate requiredStage="RISK_ANALYSIS" pageName="Cryptographic Posture"><></></ScanGate>;

  const report = risk.data;
  const moscaReport = mosca.data;
  const recommendationReport = recommendations.data;

  const exampleAsset = topAssets.data?.data[0];
  const exampleFinding = exampleAsset?.supporting_findings[0];

  return (
    <ScanGate requiredStage="RISK_ANALYSIS" pageName="Cryptographic Posture">
      <>
      <PageHeader
        eyebrow="Executive Summary"
        title="Cryptographic Posture"
        lede={
          report ? (
            <>
              QNetra discovered{' '}
              <strong>{formatNumber(scan.progress.raw_findings_count)}</strong> pieces of
              cryptographic evidence and normalized them into{' '}
              <strong>{formatNumber(report.total_assets_discovered)}</strong> distinct
              cryptographic assets.{' '}
              <strong>{formatNumber(report.vulnerable_assets_count)}</strong> require attention or migration.
            </>
          ) : (
            'Reading the cryptographic assessment produced by the analysis pipeline.'
          )
        }
        meta={
          <>
            <span className="mono">{scan.target.name || scan.target.path}</span>
            <span aria-hidden="true">·</span>
            <span>{formatDuration(scan.duration_seconds)}</span>
            <span aria-hidden="true">·</span>
            <Link to="/scan" className={styles.metaLink}>View scan details</Link>
          </>
        }
      />

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* 1. CRYPTOGRAPHIC POSTURE — risk dial + key metrics                 */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <Section divided={false} id="posture">
        {risk.isLoading && <SkeletonBlock height={220} />}
        {risk.error && <ErrorState error={risk.error} onRetry={() => risk.refetch()} />}
        {report && (
          <div className={styles.posture}>
            <div className={styles.postureDial}>
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

            <div className={styles.postureBody}>
              <p className={styles.postureLede}>{verdictSentence(report.overall_severity)}</p>

              <StatRow>
                <Stat
                  label="Crypto assets"
                  value={formatNumber(report.total_assets_discovered)}
                  hint="Identified after deduplication"
                />
                <Stat
                  label="Quantum exposed"
                  value={formatNumber(
                    report.shor_vulnerable_count +
                      report.grover_impacted_count +
                      report.classically_broken_count,
                  )}
                  tone="CRITICAL"
                  hint="Require migration"
                />
                <Stat
                  label="Critical severity"
                  value={formatNumber(report.severity_distribution.CRITICAL)}
                  tone="CRITICAL"
                  hint="Highest-risk assets"
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

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* 2. PRIORITY EXPOSURES — what needs immediate attention             */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <Section
        eyebrow="Exposure"
        title="What needs attention"
        lede="The highest-risk assets, each with the reason it matters, how urgent migration is, and what to replace it with."
        actions={
          <Link to="/risk" className={styles.sectionLink}>
            View Risk Analysis →
          </Link>
        }
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
                        <PathRef filePath={asset.location.file_path} line={asset.location.start_line} />
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
                    <span className={styles.priorityInspect} aria-hidden="true">Inspect →</span>
                  </button>
                </li>
              );
            })}
          </ol>
        )}
      </Section>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* 3. MIGRATION SUMMARY — roadmap compact                             */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {recommendationReport && (
        <Section
          eyebrow="Response"
          title="Migration strategy"
          lede="The recommendation engine classifies every asset by the kind of change it needs."
          actions={
            <Link to="/migration" className={styles.sectionLink}>
              View PQC Migration Plan →
            </Link>
          }
        >
          <div className={styles.actionGrid}>
            {RECOMMENDATION_ORDER.map((type) => {
              const count = recommendationCount(recommendationReport, type);
              if (count === 0) return null;
              return (
                <div key={type} className={styles.actionCard} data-sev={recommendationTone[type]}>
                  <span className={`${styles.actionCount} numeric`}>{formatNumber(count)}</span>
                  <span className={styles.actionLabel}>{recommendationLabel[type]}</span>
                  <span className={styles.actionShort}>{recommendationShort[type]}</span>
                </div>
              );
            })}
          </div>

          {/* Immediate items preview */}
          {topAssets.data && moscaByAsset.size > 0 && (() => {
            const immediate = topAssets.data.data
              .filter((a) => moscaByAsset.get(a.asset_id)?.urgency === 'IMMEDIATE')
              .slice(0, 4);
            if (immediate.length === 0) return null;
            return (
              <div className={styles.immediateBlock}>
                <p className="eyebrow">Start here — immediate urgency</p>
                <ul className={styles.immediateList}>
                  {immediate.map((asset) => {
                    const rec = recommendationByAsset.get(asset.asset_id);
                    return (
                      <li key={asset.asset_id} className={styles.immediateRow}>
                        <button
                          type="button"
                          className={styles.immediateButton}
                          onClick={() => setOpenAssetId(asset.asset_id)}
                        >
                          <span className={`${styles.immediateCurrent} mono`}>
                            {asset.algorithm}{asset.key_length_bits ? `-${asset.key_length_bits}` : ''}
                          </span>
                          <span className={styles.immediateArrow} aria-hidden="true">→</span>
                          <span className={`${styles.immediateTarget} mono`}>
                            {rec?.recommended_algorithm ?? 'No replacement required'}
                          </span>
                          <PathRef filePath={asset.location.file_path} line={asset.location.start_line} />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })()}
        </Section>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* 4. DEEP-DIVE SHORTCUTS — concise summary links to all views       */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <Section eyebrow="Investigation" title="Deep-dive analysis">
        <div className={styles.summaryStrip}>

          {/* Risk */}
          <Link to="/risk" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>Risk</span>
            {report ? (
              <>
                <span className={`${styles.summaryCardValue} numeric`} data-sev={severityTone[report.overall_severity]}>
                  {report.overall_risk_score.toFixed(1)}
                </span>
                <span className={styles.summaryCardSub}>
                  {report.severity_distribution.CRITICAL ?? 0} critical · {report.severity_distribution.HIGH ?? 0} high
                </span>
              </>
            ) : (
              <span className={styles.summaryCardValue}>—</span>
            )}
            <span className={styles.summaryCardLink}>View Risk →</span>
          </Link>

          {/* Quantum */}
          <Link to="/quantum" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>Quantum Exposure</span>
            {report ? (
              <>
                <span className={`${styles.summaryCardValue} numeric`} data-sev="CRITICAL">
                  {formatNumber(report.shor_vulnerable_count + report.grover_impacted_count + report.classically_broken_count)}
                </span>
                <span className={styles.summaryCardSub}>
                  {report.shor_vulnerable_count} Shor-vulnerable assets
                </span>
              </>
            ) : (
              <span className={styles.summaryCardValue}>—</span>
            )}
            <span className={styles.summaryCardLink}>View Quantum Exposure →</span>
          </Link>

          {/* Mosca */}
          <Link to="/mosca" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>Mosca / HNDL</span>
            {moscaReport ? (
              <>
                <span className={`${styles.summaryCardValue} numeric`} data-sev="CRITICAL">
                  {formatNumber(moscaReport.mosca_triggered_assets)}
                  <span className={styles.summaryCardOf}> / {formatNumber(moscaReport.mosca_applicable_assets)}</span>
                </span>
                <span className={styles.summaryCardSub}>
                  assets exceed X + Y &gt; Z
                </span>
              </>
            ) : (
              <span className={styles.summaryCardValue}>—</span>
            )}
            <span className={styles.summaryCardLink}>View Mosca / HNDL →</span>
          </Link>

          {/* CBOM */}
          <Link to="/cbom" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>CBOM</span>
            <span className={`${styles.summaryCardValue} numeric`}>
              {formatNumber(cbom.data?.components.length ?? report?.total_assets_discovered ?? 0)}
            </span>
            <span className={styles.summaryCardSub}>
              CycloneDX 1.6 components
            </span>
            <span className={styles.summaryCardLink}>View CBOM →</span>
          </Link>

          {/* Evidence */}
          <Link to="/findings" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>Evidence</span>
            <span className={`${styles.summaryCardValue} numeric`}>
              {formatNumber(scan.progress.raw_findings_count)}
            </span>
            <span className={styles.summaryCardSub}>
              raw scanner findings
            </span>
            <span className={styles.summaryCardLink}>View Evidence →</span>
          </Link>

          {/* Reports & Exports */}
          <Link to="/reports" className={styles.summaryCard}>
            <span className={styles.summaryCardEyebrow}>Reports &amp; Exports</span>
            <span className={`${styles.summaryCardValue} numeric`}>
              4
            </span>
            <span className={styles.summaryCardSub}>
              JSON &amp; CycloneDX formats
            </span>
            <span className={styles.summaryCardLink}>View Reports &amp; Exports →</span>
          </Link>

        </div>
      </Section>

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* 5. EVIDENCE EXAMPLE — concrete verified finding                    */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {exampleFinding && exampleAsset && (
        <Section
          eyebrow="Verification"
          title="Verifiable evidence"
          lede="Every conclusion traces back to static scanner evidence at a verified source location."
          actions={
            <Link to="/findings" className={styles.sectionLink}>
              View All Evidence →
            </Link>
          }
        >
          <div className={styles.evidenceExample}>
            <p className={styles.evidenceIntro}>
              For example, QNetra classified{' '}
              <strong className="mono">
                {exampleAsset.algorithm}
                {exampleAsset.key_length_bits ? `-${exampleAsset.key_length_bits}` : ''}
              </strong>{' '}
              as {exampleAsset.risk_severity?.toLowerCase() ?? 'unclassified'} risk from this code location:
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
              Inspect this asset's full details →
            </button>
          </div>
        </Section>
      )}

      <AssetDrawer scanId={scanId} assetId={openAssetId} onClose={() => setOpenAssetId(null)} />
      </>
    </ScanGate>
  );
}

/* --- Local helpers -------------------------------------------------------- */

function verdictSentence(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'This environment carries critical cryptographic risk.';
    case 'HIGH':     return 'This environment carries high cryptographic risk.';
    case 'MEDIUM':   return 'This environment carries moderate cryptographic risk.';
    default:         return 'This environment carries low cryptographic risk.';
  }
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
    case 'DIRECT_PQC':          return report.direct_pqc_count;
    case 'HYBRID':              return report.hybrid_count;
    case 'CLASSICAL_UPGRADE':   return report.classical_upgrade_count;
    case 'ALREADY_PQC':         return report.already_pqc_count;
    case 'NO_MIGRATION_REQUIRED': return report.no_migration_required_count;
    default:                    return report.unknown_count;
  }
}
