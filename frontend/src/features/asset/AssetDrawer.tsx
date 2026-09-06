import { useState } from 'react';
import type { CryptoAsset } from '../../api/types';
import {
  formatBits,
  formatDecimal,
  formatPercent,
  formatYears,
  NOT_AVAILABLE,
} from '../../lib/format';
import {
  classicalStatusLabel,
  classicalStatusTone,
  complexityTone,
  confidenceLevelLabel,
  confidenceTone,
  discoveryMethodExplanation,
  discoveryMethodLabel,
  hndlLabel,
  hndlTone,
  primitiveLabel,
  quantumStatusLabel,
  quantumStatusTone,
  quantumThreatExplanation,
  quantumThreatLabel,
  quantumThreatTone,
  recommendationDescription,
  recommendationLabel,
  recommendationTone,
  severityTone,
  urgencyDescription,
  urgencyLabel,
  urgencyTone,
} from '../../lib/labels';
import {
  Badge,
  CodeEvidence,
  Drawer,
  DrawerSection,
  KeyValue,
  Meter,
  NoteList,
  Prose,
  StepList,
} from '../../components/primitives';
import { useAssetDossier } from './useAssetDossier';
import styles from './AssetDrawer.module.css';

interface AssetDrawerProps {
  scanId: string | null;
  assetId: string | null;
  onClose: () => void;
  moscaX?: number | null;
  moscaZ?: number | null;
}

export function AssetDrawer({
  scanId,
  assetId,
  onClose,
  moscaX = null,
  moscaZ = null,
}: AssetDrawerProps) {
  const { asset, risk, mosca, recommendation, isLoading, error } = useAssetDossier(
    scanId,
    assetId,
    moscaX,
    moscaZ,
  );
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  if (!assetId) return null;

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      eyebrow="Crypto asset"
      title={asset ? assetTitle(asset) : 'Loading…'}
      subtitle={
        asset && (
          <>
            <span>{primitiveLabel[asset.primitive_type]}</span>
            {asset.implementation_library && (
              <>
                <span aria-hidden="true">·</span>
                <span className="mono">{asset.implementation_library}</span>
              </>
            )}
            <span aria-hidden="true">·</span>
            <span className="mono">
              {asset.location.file_path}
              {asset.location.start_line !== null ? `:${asset.location.start_line}` : ''}
            </span>
          </>
        )
      }
    >
      {error && <Prose>{error.message}</Prose>}
      {isLoading && !asset && <Prose>Loading asset detail…</Prose>}

      {asset && (
        <>
          {/* --- Headline verdicts ------------------------------------------ */}
          <div className={styles.verdicts}>
            <Verdict
              label="Risk"
              value={asset.risk_score === null ? NOT_AVAILABLE : String(asset.risk_score)}
              suffix={asset.risk_score === null ? undefined : '/100'}
              badge={
                asset.risk_severity && (
                  <Badge tone={severityTone[asset.risk_severity]} variant="quiet">
                    {asset.risk_severity}
                  </Badge>
                )
              }
              tone={asset.risk_severity ? severityTone[asset.risk_severity] : 'UNKNOWN'}
            />
            <Verdict
              label="Quantum"
              value={
                asset.quantum_threat_type
                  ? quantumThreatLabel[asset.quantum_threat_type]
                  : NOT_AVAILABLE
              }
              small
              tone={
                asset.quantum_threat_type
                  ? quantumThreatTone[asset.quantum_threat_type]
                  : 'UNKNOWN'
              }
            />
            <Verdict
              label="Migration urgency"
              value={mosca ? urgencyLabel[mosca.urgency] : NOT_AVAILABLE}
              small
              tone={mosca ? urgencyTone[mosca.urgency] : 'UNKNOWN'}
            />
          </div>

          {/* --- Identity --------------------------------------------------- */}
          <DrawerSection title="Identity">
            <KeyValue
              items={[
                { label: 'Algorithm', value: asset.algorithm, mono: true },
                { label: 'Family', value: asset.algorithm_family ?? NOT_AVAILABLE, mono: true },
                { label: 'Primitive', value: primitiveLabel[asset.primitive_type] },
                {
                  label: 'Key length',
                  value:
                    asset.key_length_bits === null
                      ? notObserved('Key length was not observable at the discovery site.')
                      : formatBits(asset.key_length_bits),
                  mono: asset.key_length_bits !== null,
                },
                { label: 'Curve', value: asset.curve ?? NOT_AVAILABLE, mono: Boolean(asset.curve) },
                { label: 'Mode', value: asset.mode ?? NOT_AVAILABLE, mono: Boolean(asset.mode) },
                {
                  label: 'Padding',
                  value: asset.padding ?? NOT_AVAILABLE,
                  mono: Boolean(asset.padding),
                },
                {
                  label: 'Library',
                  value: asset.implementation_library ?? NOT_AVAILABLE,
                  mono: Boolean(asset.implementation_library),
                },
                { label: 'Asset ID', value: asset.asset_id, mono: true },
              ]}
            />
          </DrawerSection>

          {/* --- Classification --------------------------------------------- */}
          <DrawerSection
            title="Classification"
            description="Assigned by core.classification from the recovered parameters."
          >
            <KeyValue
              items={[
                {
                  label: 'Classical status',
                  value: asset.classical_security_status ? (
                    <Badge tone={classicalStatusTone[asset.classical_security_status]}>
                      {classicalStatusLabel[asset.classical_security_status]}
                    </Badge>
                  ) : (
                    NOT_AVAILABLE
                  ),
                },
                {
                  label: 'Quantum status',
                  value: asset.quantum_security_status ? (
                    <Badge tone={quantumStatusTone[asset.quantum_security_status]}>
                      {quantumStatusLabel[asset.quantum_security_status]}
                    </Badge>
                  ) : (
                    NOT_AVAILABLE
                  ),
                },
                {
                  label: 'Classical security',
                  value:
                    asset.effective_classical_security_bits === null
                      ? notObserved('Not estimable without the key parameters.')
                      : formatBits(asset.effective_classical_security_bits),
                },
                {
                  label: 'Quantum security',
                  value:
                    asset.effective_quantum_security_bits === null
                      ? notObserved(
                          asset.quantum_threat_type === 'SHOR_POLYNOMIAL_BREAK'
                            ? 'Not expressible as a bit count — Shor breaks the construction outright.'
                            : 'Not estimable without the key parameters.',
                        )
                      : formatBits(asset.effective_quantum_security_bits),
                },
              ]}
            />
            {asset.quantum_threat_type && (
              <div className={styles.explain}>
                <Prose>{quantumThreatExplanation[asset.quantum_threat_type]}</Prose>
              </div>
            )}
            {asset.classification_notes && (
              <div className={styles.notes}>
                <p className={styles.notesLabel}>Engine notes</p>
                <p className={styles.notesBody}>{asset.classification_notes}</p>
              </div>
            )}
          </DrawerSection>

          {/* --- Risk -------------------------------------------------------- */}
          <DrawerSection
            title="Risk"
            description="Deterministic score from core.risk_engine, with the factors that produced it."
          >
            {risk ? (
              <>
                <Prose>{risk.rationale}</Prose>
                <ul className={styles.factors}>
                  {risk.factors.map((factor) => (
                    <li key={factor.name} className={styles.factor}>
                      <div className={styles.factorHead}>
                        <span className={styles.factorName}>
                          {factor.name.replace(/_/g, ' ')}
                        </span>
                        <span className={`${styles.factorScore} numeric`}>
                          {formatDecimal(factor.score, 0)}
                          <span className={styles.factorMax}>
                            {' / '}
                            {formatDecimal(factor.maximum, 0)}
                          </span>
                        </span>
                      </div>
                      <Meter
                        value={factor.maximum > 0 ? factor.score / factor.maximum : 0}
                        tone={asset.risk_severity ? severityTone[asset.risk_severity] : 'ACCENT'}
                        size="sm"
                      />
                      <p className={styles.factorReason}>{factor.reason}</p>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <Prose>No risk assessment was returned for this asset.</Prose>
            )}
          </DrawerSection>

          {/* --- Mosca ------------------------------------------------------- */}
          <DrawerSection
            title="Migration urgency — Mosca"
            description="Evaluated by core.mosca_engine. The frontend never computes X + Y > Z."
          >
            {mosca ? (
              mosca.mosca_applicable ? (
                <>
                  <div className={styles.inequality}>
                    <Term label="X — data shelf life" value={formatYears(mosca.x_data_lifetime_years)} />
                    <span className={styles.operator}>+</span>
                    <Term label="Y — migration time" value={formatYears(mosca.y_migration_time_years)} />
                    <span className={styles.operator}>
                      {mosca.inequality_triggered === null
                        ? '?'
                        : mosca.inequality_triggered
                          ? '>'
                          : '≤'}
                    </span>
                    <Term
                      label="Z — quantum horizon"
                      value={formatYears(mosca.z_quantum_arrival_years)}
                    />
                  </div>
                  <KeyValue
                    items={[
                      { label: 'X + Y', value: formatYears(mosca.x_plus_y) },
                      {
                        label: 'Exposure gap',
                        value:
                          mosca.exposure_gap_years === null
                            ? NOT_AVAILABLE
                            : formatYears(mosca.exposure_gap_years),
                      },
                      {
                        label: 'Latest safe start',
                        value:
                          mosca.migration_deadline_years_from_now === null
                            ? NOT_AVAILABLE
                            : `${formatYears(mosca.migration_deadline_years_from_now)} from the assessment date`,
                      },
                      {
                        label: 'HNDL exposure',
                        value: (
                          <Badge tone={hndlTone[mosca.hndl_exposure]}>
                            {hndlLabel[mosca.hndl_exposure]}
                          </Badge>
                        ),
                      },
                      {
                        label: 'Urgency',
                        value: (
                          <Badge tone={urgencyTone[mosca.urgency]}>
                            {urgencyLabel[mosca.urgency]}
                          </Badge>
                        ),
                      },
                    ]}
                  />
                  <div className={styles.explain}>
                    <Prose>{urgencyDescription[mosca.urgency]}</Prose>
                  </div>
                  {mosca.rationale.length > 0 && <NoteList notes={mosca.rationale} />}
                  {mosca.assumptions.length > 0 && (
                    <div className={styles.assumptions}>
                      <p className={styles.notesLabel}>Assumptions</p>
                      <NoteList notes={mosca.assumptions} tone="quiet" />
                    </div>
                  )}
                </>
              ) : (
                <>
                  <Prose>
                    Mosca analysis does not apply to this entry. {urgencyDescription[mosca.urgency]}
                  </Prose>
                  {mosca.assumptions.length > 0 && (
                    <NoteList notes={mosca.assumptions} tone="quiet" />
                  )}
                </>
              )
            ) : (
              <Prose>No Mosca assessment was returned for this asset.</Prose>
            )}
          </DrawerSection>

          {/* --- Recommendation ---------------------------------------------- */}
          <DrawerSection
            title="Recommended action"
            description="Produced by core.recommendation_engine against the NIST PQC standards."
          >
            {recommendation ? (
              <>
                <div className={styles.migration}>
                  <div className={styles.migrationSide}>
                    <p className="eyebrow">Current</p>
                    <p className={`${styles.migrationValue} mono`}>
                      {recommendation.current_algorithm}
                    </p>
                  </div>
                  <span className={styles.migrationArrow} aria-hidden="true">
                    →
                  </span>
                  <div className={styles.migrationSide}>
                    <p className="eyebrow">Recommended</p>
                    <p className={`${styles.migrationValue} mono`}>
                      {recommendation.recommended_algorithm ?? 'No replacement required'}
                    </p>
                    {recommendation.pqc_standard && (
                      <p className={styles.migrationStandard}>{recommendation.pqc_standard}</p>
                    )}
                  </div>
                </div>

                <KeyValue
                  items={[
                    {
                      label: 'Approach',
                      value: (
                        <Badge tone={recommendationTone[recommendation.recommendation_type]}>
                          {recommendationLabel[recommendation.recommendation_type]}
                        </Badge>
                      ),
                    },
                    ...(recommendation.hybrid_recommendation
                      ? [
                          {
                            label: 'Hybrid scheme',
                            value: recommendation.hybrid_recommendation,
                            mono: true,
                          },
                        ]
                      : []),
                    {
                      label: 'Complexity',
                      value: (
                        <Badge tone={complexityTone[recommendation.migration_complexity]}>
                          {recommendation.migration_complexity}
                        </Badge>
                      ),
                    },
                    { label: 'Engine confidence', value: recommendation.confidence },
                  ]}
                />

                <div className={styles.explain}>
                  <Prose>
                    {recommendationDescription[recommendation.recommendation_type]}
                  </Prose>
                </div>

                {recommendation.rationale.length > 0 && (
                  <NoteList notes={recommendation.rationale} />
                )}

                {recommendation.guidance_steps.length > 0 && (
                  <div className={styles.steps}>
                    <p className={styles.notesLabel}>Migration steps</p>
                    <StepList steps={recommendation.guidance_steps} />
                  </div>
                )}

                {recommendation.limitations.length > 0 && (
                  <div className={styles.assumptions}>
                    <p className={styles.notesLabel}>Limitations</p>
                    <NoteList notes={recommendation.limitations} tone="quiet" />
                  </div>
                )}
                {recommendation.assumptions.length > 0 && (
                  <div className={styles.assumptions}>
                    <p className={styles.notesLabel}>Assumptions</p>
                    <NoteList notes={recommendation.assumptions} tone="quiet" />
                  </div>
                )}
              </>
            ) : (
              <Prose>No recommendation was returned for this asset.</Prose>
            )}
          </DrawerSection>

          {/* --- Evidence ----------------------------------------------------- */}
          <DrawerSection
            title={`Evidence — ${asset.supporting_findings.length} supporting finding${
              asset.supporting_findings.length === 1 ? '' : 's'
            }`}
            description="Every conclusion above traces back to these scanner observations."
            action={
              asset.supporting_findings.length > 1 && (
                <button
                  type="button"
                  className={styles.toggle}
                  onClick={() => setEvidenceOpen((open) => !open)}
                >
                  {evidenceOpen ? 'Show first only' : `Show all ${asset.supporting_findings.length}`}
                </button>
              )
            }
          >
            <div className={styles.confidence}>
              <div className={styles.confidenceHead}>
                <span className={styles.notesLabel}>Aggregate confidence</span>
                <Badge tone={confidenceTone(asset.confidence_score)}>
                  {formatPercent(asset.confidence_score)} ·{' '}
                  {confidenceLevelLabel[asset.confidence_level] ?? asset.confidence_level}
                </Badge>
              </div>
              <Meter value={asset.confidence_score} tone={confidenceTone(asset.confidence_score)} />
              <p className={styles.factorReason}>{asset.confidence_rationale}</p>
            </div>

            <div className={styles.evidenceList}>
              {(evidenceOpen ? asset.supporting_findings : asset.supporting_findings.slice(0, 1)).map(
                (finding) => (
                  <article className={styles.evidence} key={finding.finding_id}>
                    <div className={styles.evidenceMeta}>
                      <Badge tone="ACCENT" variant="outline" size="sm">
                        {discoveryMethodLabel[finding.discovery_method] ?? finding.discovery_method}
                      </Badge>
                      <span className={styles.evidenceScanner}>{finding.scanner_name}</span>
                      <span className={`${styles.evidenceConfidence} numeric`}>
                        {formatPercent(finding.confidence_score)}
                      </span>
                    </div>
                    <CodeEvidence
                      filePath={finding.location.file_path}
                      startLine={finding.location.start_line}
                      endLine={finding.location.end_line}
                      snippet={finding.location.snippet}
                      symbol={finding.raw_symbol}
                    />
                    <p className={styles.evidenceRationale}>
                      {discoveryMethodExplanation[finding.discovery_method] ?? ''}{' '}
                      {finding.confidence_rationale}
                    </p>
                  </article>
                ),
              )}
            </div>
          </DrawerSection>
        </>
      )}
    </Drawer>
  );
}

/* --- Local helpers -------------------------------------------------------- */

function assetTitle(asset: CryptoAsset): string {
  if (asset.key_length_bits) return `${asset.algorithm}-${asset.key_length_bits}`;
  return asset.algorithm;
}

function notObserved(reason: string) {
  return (
    <span className={styles.notObserved} title={reason}>
      Not observed
    </span>
  );
}

function Verdict({
  label,
  value,
  suffix,
  badge,
  tone,
  small,
}: {
  label: string;
  value: string;
  suffix?: string;
  badge?: React.ReactNode;
  tone: string;
  small?: boolean;
}) {
  return (
    <div className={styles.verdict} data-sev={tone}>
      <p className={styles.verdictLabel}>{label}</p>
      <p className={`${small ? styles.verdictTextValue : styles.verdictValue} numeric`}>
        {value}
        {suffix && <span className={styles.verdictSuffix}>{suffix}</span>}
      </p>
      {badge}
    </div>
  );
}

function Term({ label, value }: { label: string; value: string }) {
  return (
    <div className={styles.term}>
      <p className={`${styles.termValue} numeric`}>{value}</p>
      <p className={styles.termLabel}>{label}</p>
    </div>
  );
}
