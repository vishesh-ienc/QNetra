/**
 * QNetra API types.
 *
 * Source of truth: docs/10_API_CONTRACT.md, reconciled against the actual
 * serialisation of the core engines (core/models.py, core/risk_engine,
 * core/mosca_engine, core/recommendation_engine, core/cbom_generator).
 *
 * Where the contract document and the implemented engines disagree, these types
 * follow the ENGINES, because the engines are what the Phase 4 API will expose.
 * Every such divergence is recorded in frontend/API_GAPS.md.
 *
 * Nothing in this file is derived, defaulted or inferred by the frontend.
 * Fields the backend cannot compute are typed `| null` and rendered as an
 * explicit "not available" state.
 */

/* -------------------------------------------------------------------------- */
/* Shared                                                                     */
/* -------------------------------------------------------------------------- */

export interface FileLocation {
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  byte_offset: number | null;
  snippet: string | null;
}

export interface Pagination {
  page: number;
  page_size: number;
  total_items: number;
  total_pages: number;
}

export interface Paginated<T> {
  data: T[];
  pagination: Pagination;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ConfidenceLevel =
  | 'VERY_HIGH'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'VERY_LOW';

export type QuantumThreatType =
  | 'SHOR_POLYNOMIAL_BREAK'
  | 'GROVER_BIT_HALVING'
  | 'CLASSICALLY_BROKEN'
  | 'QUANTUM_RESISTANT'
  | 'NOT_APPLICABLE'
  | 'UNKNOWN';

export type ClassicalSecurityStatus = 'SECURE' | 'WEAK' | 'BROKEN' | 'UNKNOWN';

export type QuantumSecurityStatus = 'SAFE' | 'DEGRADED' | 'CRITICAL' | 'UNKNOWN';

export type PrimitiveType =
  | 'ASYMMETRIC_ENCRYPTION'
  | 'DIGITAL_SIGNATURE'
  | 'KEY_EXCHANGE'
  | 'SYMMETRIC_CIPHER'
  | 'HASH_FUNCTION'
  | 'MAC'
  | 'KDF'
  | 'PROTOCOL'
  | 'LIBRARY'
  | 'CERTIFICATE'
  | 'KEY_MATERIAL'
  | 'RANDOM'
  | 'UNKNOWN';

export type DiscoveryMethod =
  | 'AST'
  | 'REGEX'
  | 'API_CALL'
  | 'IMPORT_ANALYSIS'
  | 'SYMBOL_TABLE'
  | 'STRING_EXTRACTION'
  | 'MANIFEST'
  | 'FILE_SIGNATURE';

/* -------------------------------------------------------------------------- */
/* Scan                                                                       */
/* -------------------------------------------------------------------------- */

export type ScanStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED'
  | 'CANCELLED';

export type StageStatus = 'WAITING' | 'RUNNING' | 'COMPLETED' | 'SKIPPED' | 'FAILED';

export type PipelineStage =
  | 'QUEUED'
  | 'DISCOVERY'
  | 'NORMALIZATION'
  | 'CLASSIFICATION'
  | 'CBOM'
  | 'RISK_ANALYSIS'
  | 'MOSCA_ANALYSIS'
  | 'PQC_ANALYSIS'
  | 'COMPLETED';

export interface ScanStage {
  name: PipelineStage;
  status: StageStatus;
}

export interface ScanProgress {
  stages: ScanStage[];
  directories_visited: number | null;
  files_discovered: number | null;
  files_scanned: number | null;
  files_skipped: number | null;
  files_errored: number | null;
  raw_findings_count: number | null;
  assets_count: number | null;
}

export interface NormalizationStatistics {
  raw_findings_count: number;
  assets_produced_count: number;
  findings_merged_count: number;
  merge_ratio: number;
  assets_by_algorithm: Record<string, number>;
  assets_by_primitive_type: Record<string, number>;
  assets_by_library: Record<string, number>;
  assets_by_confidence_level: Record<string, number>;
}

export interface DiscoveryStatistics {
  findings_by_method: Record<string, number>;
  findings_by_category: Record<string, number>;
}

export interface ScanTargetSummary {
  target_id: string;
  name: string | null;
  target_type: string;
  path: string;
}

export interface Scan {
  scan_id: string;
  name: string | null;
  artifact_id: string | null;
  target: ScanTargetSummary;
  status: ScanStatus;
  current_stage: PipelineStage;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  progress: ScanProgress;
  discovery: DiscoveryStatistics | null;
  normalization: NormalizationStatistics | null;
  errors: string[];
  warnings: string[];
}

/* -------------------------------------------------------------------------- */
/* Findings — raw scanner evidence (RawFinding v1.1.0)                        */
/* -------------------------------------------------------------------------- */

export interface ContainerContext {
  image_reference: string | null;
  layer_id: string | null;
  filesystem_path: string;
}

export interface Finding {
  finding_id: string;
  scanner_name: string;
  scanner_version: string;
  discovery_method: DiscoveryMethod;
  raw_symbol: string;
  suspected_algorithm: string | null;
  artifact_category: string;
  library_hint: string | null;
  key_size_hint: number | null;
  mode_hint: string | null;
  curve_hint: string | null;
  location: FileLocation;
  confidence_score: number;
  confidence_level: ConfidenceLevel;
  confidence_rationale: string;
  binary_format: string | null;
  symbol_name: string | null;
  container_context: ContainerContext | null;
  raw_parameters: Record<string, unknown> | null;
  discovered_at: string;
}

/* -------------------------------------------------------------------------- */
/* Crypto assets — normalized canonical inventory                             */
/* -------------------------------------------------------------------------- */

export interface SupportingFinding {
  finding_id: string;
  scanner_name: string;
  discovery_method: string;
  raw_symbol: string;
  location: FileLocation;
  confidence_score: number;
  confidence_rationale: string;
}

export interface CryptoAsset {
  asset_id: string;
  algorithm: string;
  algorithm_family: string | null;
  primitive_type: PrimitiveType;
  key_length_bits: number | null;
  curve: string | null;
  mode: string | null;
  padding: string | null;
  implementation_library: string | null;
  location: FileLocation;
  locations: FileLocation[];
  classical_security_status: ClassicalSecurityStatus | null;
  quantum_vulnerable: boolean | null;
  quantum_threat_type: QuantumThreatType | null;
  quantum_security_status: QuantumSecurityStatus | null;
  effective_classical_security_bits: number | null;
  effective_quantum_security_bits: number | null;
  classification_notes: string | null;
  confidence_score: number;
  confidence_level: ConfidenceLevel;
  confidence_rationale: string;
  risk_score: number | null;
  risk_severity: Severity | null;
  supporting_finding_ids: string[];
  supporting_findings: SupportingFinding[];
  recommendation_id: string | null;
}

/* -------------------------------------------------------------------------- */
/* Risk                                                                        */
/* -------------------------------------------------------------------------- */

export interface RiskFactor {
  name: string;
  score: number;
  maximum: number;
  reason: string;
  source_field: string;
}

export interface RiskAssessment {
  asset_id: string;
  risk_score: number;
  severity: Severity;
  factors: RiskFactor[];
  rationale: string;
  confidence: number | null;
}

export interface AssetRiskDetail {
  asset_id: string;
  score: number;
  severity: Severity;
  rationale: string;
}

export interface RiskReport {
  scan_id: string;
  overall_risk_score: number;
  overall_severity: Severity;
  total_assets_discovered: number;
  vulnerable_assets_count: number;
  shor_vulnerable_count: number;
  grover_impacted_count: number;
  classically_broken_count: number;
  quantum_resistant_count: number;
  severity_distribution: Record<Severity, number>;
  asset_scores: AssetRiskDetail[];
  assessments: RiskAssessment[];
  calculated_at: string;
}

/* -------------------------------------------------------------------------- */
/* Mosca / HNDL                                                                */
/* -------------------------------------------------------------------------- */

export type MoscaUrgency =
  | 'IMMEDIATE'
  | 'URGENT'
  | 'PLANNED'
  | 'MONITOR'
  | 'NOT_REQUIRED'
  | 'UNKNOWN';

export type HndlExposure =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'NONE'
  | 'UNKNOWN';

export interface MoscaAssessment {
  asset_id: string;
  x_data_lifetime_years: number | null;
  y_migration_time_years: number | null;
  z_quantum_arrival_years: number | null;
  x_plus_y: number | null;
  inequality_triggered: boolean | null;
  exposure_gap_years: number | null;
  urgency: MoscaUrgency;
  hndl_exposure: HndlExposure;
  migration_deadline_years_from_now: number | null;
  assessment_date: string | null;
  mosca_applicable: boolean;
  assumptions: string[];
  rationale: string[];
}

export interface AssetMoscaDetail {
  asset_id: string;
  urgency: MoscaUrgency;
  hndl_exposure: HndlExposure;
  inequality_triggered: boolean | null;
  mosca_applicable: boolean;
}

export interface MoscaParameters {
  /** X — data shelf life in years. Supplied by the user; never fabricated. */
  data_shelf_life_years_x: number | null;
  /** Y — migration time in years. `null` means the engine derived it per primitive. */
  migration_time_years_y: number | null;
  /** Z — quantum threat horizon in years. */
  quantum_threat_horizon_years_z: number;
  migration_time_source?: string;
}

export interface MoscaReport {
  scan_id: string;
  parameters: MoscaParameters;
  total_assets: number;
  mosca_applicable_assets: number;
  mosca_triggered_assets: number;
  hndl_exposed_assets: number;
  urgency_distribution: Record<MoscaUrgency, number>;
  hndl_distribution: Record<HndlExposure, number>;
  highest_urgency_assets: AssetMoscaDetail[];
  assessments: MoscaAssessment[];
  assessment_date: string | null;
  assessed_at: string;
}

export interface MoscaRequest {
  data_shelf_life_years_x: number;
  migration_time_years_y?: number | null;
  quantum_threat_horizon_years_z?: number | null;
}

/* -------------------------------------------------------------------------- */
/* PQC recommendations                                                         */
/* -------------------------------------------------------------------------- */

export type RecommendationType =
  | 'DIRECT_PQC'
  | 'CLASSICAL_UPGRADE'
  | 'HYBRID'
  | 'ALREADY_PQC'
  | 'NO_MIGRATION_REQUIRED'
  | 'UNKNOWN';

export type MigrationComplexity = 'LOW' | 'MEDIUM' | 'HIGH';

export interface PqcRecommendation {
  asset_id: string;
  current_algorithm: string;
  current_primitive: PrimitiveType;
  recommendation_type: RecommendationType;
  recommended_algorithm: string | null;
  pqc_standard: string | null;
  hybrid_recommendation: string | null;
  rationale: string[];
  assumptions: string[];
  limitations: string[];
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'INSUFFICIENT_DATA';
  migration_complexity: MigrationComplexity;
  guidance_steps: string[];
}

export interface RecommendationReport {
  scan_id: string;
  total_assets: number;
  direct_pqc_count: number;
  classical_upgrade_count: number;
  hybrid_count: number;
  already_pqc_count: number;
  no_migration_required_count: number;
  unknown_count: number;
  recommendations_by_target_algorithm: Record<string, number>;
  recommendations_by_current_algorithm: Record<string, number>;
  recommendations_by_primitive: Record<string, number>;
  recommendations: PqcRecommendation[];
}

/* -------------------------------------------------------------------------- */
/* CBOM — CycloneDX 1.6                                                        */
/* -------------------------------------------------------------------------- */

export interface CbomProperty {
  name: string;
  value: string;
}

export interface CbomOccurrence {
  location: string;
  line?: number | null;
  symbol?: string | null;
}

export interface CbomAlgorithmProperties {
  primitive?: string;
  parameterSetIdentifier?: string;
  curve?: string;
  executionEnvironment?: string;
  implementationPlatform?: string;
  cryptoFunctions?: string[];
  classicalSecurityLevel?: number;
  nistQuantumSecurityLevel?: number;
  mode?: string;
  padding?: string;
}

export interface CbomCryptoProperties {
  assetType: string;
  algorithmProperties?: CbomAlgorithmProperties;
  oid?: string;
}

export interface CbomComponent {
  type: string;
  'bom-ref': string;
  name: string;
  cryptoProperties?: CbomCryptoProperties;
  evidence?: { occurrences?: CbomOccurrence[] };
  properties?: CbomProperty[];
}

export interface CbomDocument {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata?: Record<string, unknown>;
  components: CbomComponent[];
}

/* -------------------------------------------------------------------------- */
/* Errors                                                                      */
/* -------------------------------------------------------------------------- */

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}
