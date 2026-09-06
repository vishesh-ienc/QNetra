/**
 * Human-readable labels and explanations for backend enum values.
 *
 * These are vocabulary, not judgement: each entry renames or explains a value the
 * backend already decided. No label implies a severity the backend did not assign.
 * Explanatory text is sourced from docs/09_KNOWLEDGE_BASE.md and docs/05_ALGORITHMS.md.
 */

import type {
  ClassicalSecurityStatus,
  HndlExposure,
  MoscaUrgency,
  PrimitiveType,
  QuantumSecurityStatus,
  QuantumThreatType,
  RecommendationType,
  Severity,
} from '../api/types';

export type SeverityTone = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' | 'UNKNOWN' | 'ACCENT';

export const severityTone: Record<Severity, SeverityTone> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/* --- Quantum ------------------------------------------------------------- */

export const quantumThreatLabel: Record<QuantumThreatType, string> = {
  SHOR_POLYNOMIAL_BREAK: 'Shor — polynomial break',
  GROVER_BIT_HALVING: 'Grover — bit halving',
  CLASSICALLY_BROKEN: 'Classically broken',
  QUANTUM_RESISTANT: 'Quantum resistant',
  NOT_APPLICABLE: 'Not applicable',
  UNKNOWN: 'Unknown',
};

export const quantumThreatShort: Record<QuantumThreatType, string> = {
  SHOR_POLYNOMIAL_BREAK: 'Shor',
  GROVER_BIT_HALVING: 'Grover',
  CLASSICALLY_BROKEN: 'Broken',
  QUANTUM_RESISTANT: 'Resistant',
  NOT_APPLICABLE: 'N/A',
  UNKNOWN: 'Unknown',
};

export const quantumThreatTone: Record<QuantumThreatType, SeverityTone> = {
  SHOR_POLYNOMIAL_BREAK: 'CRITICAL',
  GROVER_BIT_HALVING: 'MEDIUM',
  CLASSICALLY_BROKEN: 'CRITICAL',
  QUANTUM_RESISTANT: 'SAFE',
  NOT_APPLICABLE: 'UNKNOWN',
  UNKNOWN: 'UNKNOWN',
};

export const quantumThreatExplanation: Record<QuantumThreatType, string> = {
  SHOR_POLYNOMIAL_BREAK:
    "Shor's algorithm solves the integer factorisation and discrete logarithm problems in polynomial time. A cryptographically relevant quantum computer recovers the private key outright — no key size mitigates this.",
  GROVER_BIT_HALVING:
    "Grover's algorithm gives a quadratic speed-up on brute-force search, halving the effective security of symmetric keys and degrading hash collision resistance. Larger parameters restore the margin.",
  CLASSICALLY_BROKEN:
    'Already broken by classical cryptanalysis, independent of any quantum threat. Migration is warranted today.',
  QUANTUM_RESISTANT:
    'No known quantum attack meaningfully reduces the security of this construction at its current parameters.',
  NOT_APPLICABLE:
    'This entry is not a directly attackable primitive — quantum threat classification does not apply to it on its own.',
  UNKNOWN:
    'QNetra could not determine a quantum threat classification from the parameters it recovered. Parameters such as key length were not observable at the discovery site.',
};

export const classicalStatusLabel: Record<ClassicalSecurityStatus, string> = {
  SECURE: 'Secure',
  WEAK: 'Weak',
  BROKEN: 'Broken',
  UNKNOWN: 'Unknown',
};

export const classicalStatusTone: Record<ClassicalSecurityStatus, SeverityTone> = {
  SECURE: 'SAFE',
  WEAK: 'MEDIUM',
  BROKEN: 'CRITICAL',
  UNKNOWN: 'UNKNOWN',
};

export const quantumStatusLabel: Record<QuantumSecurityStatus, string> = {
  SAFE: 'Safe',
  DEGRADED: 'Degraded',
  CRITICAL: 'Critical',
  UNKNOWN: 'Unknown',
};

export const quantumStatusTone: Record<QuantumSecurityStatus, SeverityTone> = {
  SAFE: 'SAFE',
  DEGRADED: 'MEDIUM',
  CRITICAL: 'CRITICAL',
  UNKNOWN: 'UNKNOWN',
};

/* --- Primitives ---------------------------------------------------------- */

export const primitiveLabel: Record<PrimitiveType, string> = {
  ASYMMETRIC_ENCRYPTION: 'Asymmetric encryption',
  DIGITAL_SIGNATURE: 'Digital signature',
  KEY_EXCHANGE: 'Key exchange',
  SYMMETRIC_CIPHER: 'Symmetric cipher',
  HASH_FUNCTION: 'Hash function',
  MAC: 'MAC',
  KDF: 'Key derivation',
  PROTOCOL: 'Protocol',
  LIBRARY: 'Library',
  CERTIFICATE: 'Certificate',
  KEY_MATERIAL: 'Key material',
  RANDOM: 'Randomness',
  UNKNOWN: 'Unknown',
};

export const discoveryMethodLabel: Record<string, string> = {
  AST: 'AST',
  REGEX: 'Pattern',
  API_CALL: 'API call',
  IMPORT_ANALYSIS: 'Import',
  SYMBOL_TABLE: 'Symbol table',
  STRING_EXTRACTION: 'Binary string',
  MANIFEST: 'Manifest',
  FILE_SIGNATURE: 'File signature',
};

export const discoveryMethodExplanation: Record<string, string> = {
  AST: 'Abstract syntax tree parse — the call was structurally confirmed in the source grammar.',
  REGEX: 'Pattern match against the curated QNetra pattern registry.',
  API_CALL: 'A known cryptographic API signature was matched, including its literal arguments.',
  IMPORT_ANALYSIS: 'A cryptographic module or package import was detected.',
  SYMBOL_TABLE: 'Symbol recovered from the binary import/export table.',
  STRING_EXTRACTION: 'Printable string recovered from binary contents.',
  MANIFEST: 'Declared dependency read from a package manifest.',
  FILE_SIGNATURE: 'File magic bytes identified the artifact type.',
};

/* --- Mosca --------------------------------------------------------------- */

export const urgencyLabel: Record<MoscaUrgency, string> = {
  IMMEDIATE: 'Immediate',
  URGENT: 'Urgent',
  PLANNED: 'Planned',
  MONITOR: 'Monitor',
  NOT_REQUIRED: 'Not required',
  UNKNOWN: 'Unknown',
};

export const urgencyTone: Record<MoscaUrgency, SeverityTone> = {
  IMMEDIATE: 'CRITICAL',
  URGENT: 'HIGH',
  PLANNED: 'MEDIUM',
  MONITOR: 'LOW',
  NOT_REQUIRED: 'SAFE',
  UNKNOWN: 'UNKNOWN',
};

export const URGENCY_ORDER: MoscaUrgency[] = [
  'IMMEDIATE',
  'URGENT',
  'PLANNED',
  'MONITOR',
  'NOT_REQUIRED',
  'UNKNOWN',
];

export const urgencyDescription: Record<MoscaUrgency, string> = {
  IMMEDIATE:
    'X + Y exceeds Z, and either the overshoot is small enough that the window is closing right now, or the data carries critical harvest-now-decrypt-later exposure.',
  URGENT:
    'X + Y exceeds Z. On these assumptions the window has already closed, so migration belongs in the next few months rather than the next planning cycle.',
  PLANNED:
    'X + Y stays within Z, but the remaining buffer is narrow enough that the work should be scheduled now rather than revisited later.',
  MONITOR:
    'Quantum-vulnerable, but X + Y stays comfortably within Z at these parameters. Revisit when the parameters or the horizon move.',
  NOT_REQUIRED:
    'Outside the scope of the inequality — libraries, randomness sources and algorithms that are already quantum-resistant.',
  UNKNOWN:
    'The engine could not evaluate the inequality because a required input was missing. This is a gap in the inputs, not a safe result.',
};

export const hndlLabel: Record<HndlExposure, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  NONE: 'None',
  UNKNOWN: 'Unknown',
};

export const hndlTone: Record<HndlExposure, SeverityTone> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'SAFE',
  UNKNOWN: 'UNKNOWN',
};

export const HNDL_ORDER: HndlExposure[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'NONE',
  'UNKNOWN',
];

/* --- Recommendations ------------------------------------------------------ */

export const recommendationLabel: Record<RecommendationType, string> = {
  DIRECT_PQC: 'Direct PQC replacement',
  CLASSICAL_UPGRADE: 'Classical upgrade',
  HYBRID: 'Hybrid transition',
  ALREADY_PQC: 'Already post-quantum',
  NO_MIGRATION_REQUIRED: 'No migration required',
  UNKNOWN: 'Undetermined',
};

export const recommendationShort: Record<RecommendationType, string> = {
  DIRECT_PQC: 'Direct PQC',
  CLASSICAL_UPGRADE: 'Classical upgrade',
  HYBRID: 'Hybrid',
  ALREADY_PQC: 'Already PQC',
  NO_MIGRATION_REQUIRED: 'No migration',
  UNKNOWN: 'Undetermined',
};

export const recommendationTone: Record<RecommendationType, SeverityTone> = {
  DIRECT_PQC: 'ACCENT',
  CLASSICAL_UPGRADE: 'MEDIUM',
  HYBRID: 'ACCENT',
  ALREADY_PQC: 'SAFE',
  NO_MIGRATION_REQUIRED: 'SAFE',
  UNKNOWN: 'UNKNOWN',
};

export const recommendationDescription: Record<RecommendationType, string> = {
  DIRECT_PQC:
    'The classical primitive is replaced outright by a NIST-standardised post-quantum algorithm.',
  CLASSICAL_UPGRADE:
    'A weak or insufficient classical primitive is strengthened to a stronger classical primitive. This is not post-quantum cryptography — it restores classical margin and, where applicable, the Grover margin.',
  HYBRID:
    'The classical primitive runs alongside a post-quantum primitive so security holds if either survives. This is the standard transitional posture.',
  ALREADY_PQC: 'The asset already uses a NIST-approved post-quantum algorithm.',
  NO_MIGRATION_REQUIRED:
    'This entry is not subject to algorithm replacement — libraries, randomness sources and already-adequate primitives fall here.',
  UNKNOWN:
    'The engine could not determine a reliable recommendation from the parameters recovered. It deliberately does not guess.',
};

export const RECOMMENDATION_ORDER: RecommendationType[] = [
  'DIRECT_PQC',
  'HYBRID',
  'CLASSICAL_UPGRADE',
  'ALREADY_PQC',
  'NO_MIGRATION_REQUIRED',
  'UNKNOWN',
];

export const complexityTone: Record<string, SeverityTone> = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
};

export const confidenceTone = (score: number): SeverityTone => {
  if (score >= 0.85) return 'SAFE';
  if (score >= 0.7) return 'LOW';
  if (score >= 0.45) return 'MEDIUM';
  return 'UNKNOWN';
};

export const confidenceLevelLabel: Record<string, string> = {
  VERY_HIGH: 'Very high',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  VERY_LOW: 'Very low',
};

/* --- Scan ---------------------------------------------------------------- */

export const stageLabel: Record<string, string> = {
  QUEUED: 'Queued',
  DISCOVERY: 'Discovery',
  NORMALIZATION: 'Normalization',
  CLASSIFICATION: 'Classification',
  CBOM: 'CBOM generation',
  RISK_ANALYSIS: 'Risk assessment',
  MOSCA_ANALYSIS: 'Mosca / HNDL analysis',
  PQC_ANALYSIS: 'PQC recommendations',
  COMPLETED: 'Completed',
};

export const stageQuestion: Record<string, string> = {
  DISCOVERY: 'What cryptographic evidence exists in the target?',
  NORMALIZATION: 'Which distinct cryptographic assets does that evidence describe?',
  CLASSIFICATION: 'What kind of cryptography is each asset, and what threat applies?',
  CBOM: 'What is the standardised inventory of everything found?',
  RISK_ANALYSIS: 'Which assets carry the most risk?',
  MOSCA_ANALYSIS: 'How urgent is migration given the data being protected?',
  PQC_ANALYSIS: 'What should each vulnerable asset be replaced with?',
};
