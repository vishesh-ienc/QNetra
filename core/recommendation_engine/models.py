"""
QNetra Recommendation Engine — Domain Models
=============================================

Defines output data contracts for Milestone 3.3: NIST PQC Recommendation Engine.

Models:
  - PQCRecommendationType: Recommendation outcome classification.
  - MigrationComplexity: Complexity tier for migration effort estimation.
  - PQCRecommendation: Per-asset PQC migration recommendation with full explainability.
  - AssetRecommendationDetail: Lightweight summary for reports and APIs.
  - PQCRecommendationReport: Aggregate repository-level recommendation report.

Design Principles:
  - Output models use Python dataclasses (not Pydantic), consistent with risk_engine and mosca_engine.
  - to_dict() on each model for JSON serialization.
  - NO CryptoAsset mutation — all models are output-only.
  - Recommendation type is NEVER determined by risk_score or Mosca urgency.
  - Only finalized NIST PQC standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).

Contract References:
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.5: PQCRecommendationReport)
  - docs/05_ALGORITHMS.md (Alg-08: PQC Recommendation Engine)
  - docs/10_API_CONTRACT.md (Section 13: Recommendations API)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class PQCRecommendationType(str, Enum):
    """
    Recommendation outcome classification for a CryptoAsset.

    Represents the type of migration action required or its current PQC status.

    Values:
      DIRECT_PQC          : Asset should be replaced with a standardized NIST PQC algorithm directly.
      HYBRID              : Asset should transition via a hybrid classical + PQC construction.
      ALREADY_PQC         : Asset is already using a standardized NIST PQC algorithm (FIPS 203/204/205).
      NO_MIGRATION_REQUIRED: Asset is not subject to PQC migration (library, PRNG, or non-applicable).
      UNKNOWN             : Insufficient information to produce a reliable recommendation.
    """
    DIRECT_PQC = "DIRECT_PQC"
    HYBRID = "HYBRID"
    ALREADY_PQC = "ALREADY_PQC"
    NO_MIGRATION_REQUIRED = "NO_MIGRATION_REQUIRED"
    UNKNOWN = "UNKNOWN"


class MigrationComplexity(str, Enum):
    """
    Migration effort complexity estimate for a given PQC recommendation.

    Tiers:
      LOW    : Configuration-only or parameter-upgrade change (e.g. AES-128 -> AES-256).
      MEDIUM : Library update, API surface changes, and test suite updates.
      HIGH   : Protocol-level changes, certificate rotation, or multi-system coordination.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class PQCRecommendation:
    """
    Per-asset Post-Quantum Cryptography migration recommendation.

    Attributes:
      asset_id:
          UUID of the evaluated CryptoAsset. Preserves traceability to the canonical asset.
      current_algorithm:
          Algorithm name as normalized in the CryptoAsset (e.g. 'RSA', 'ECDH', 'SHA-256').
      current_primitive:
          PrimitiveType.value string of the asset (e.g. 'ASYMMETRIC_ENCRYPTION').
      recommendation_type:
          PQCRecommendationType outcome (DIRECT_PQC, HYBRID, ALREADY_PQC, etc.).
      recommended_algorithm:
          Recommended PQC replacement algorithm (e.g. 'ML-KEM-768', 'ML-DSA-65', 'SHA-384').
          None if recommendation_type is ALREADY_PQC, NO_MIGRATION_REQUIRED, or UNKNOWN.
      pqc_standard:
          Applicable NIST FIPS standard (e.g. 'NIST FIPS 203').
          None if no NIST standard applies.
      hybrid_recommendation:
          Hybrid construction description (e.g. 'X25519 + ML-KEM-768').
          Only populated if recommendation_type is HYBRID.
      rationale:
          Ordered list of explanation strings. Each entry explains one aspect of the recommendation.
          Minimum: what was detected, why migration is/is not needed, which PQC was chosen, and why.
      assumptions:
          Explicit list of assumption strings. All parameter selection and policy defaults
          are declared here. No silent assumptions.
      limitations:
          Known limitations, caveats, or conditions where the recommendation may not apply.
      confidence:
          Confidence level string: 'HIGH', 'MEDIUM', 'LOW', or 'INSUFFICIENT_DATA'.
          Reflects the engine's certainty in the recommendation, based on available parameters.
      migration_complexity:
          Estimated complexity tier for executing this migration.
      guidance_steps:
          Ordered list of actionable guidance steps for implementing the recommendation.
    """
    asset_id: str
    current_algorithm: str
    current_primitive: str
    recommendation_type: PQCRecommendationType
    recommended_algorithm: Optional[str] = None
    pqc_standard: Optional[str] = None
    hybrid_recommendation: Optional[str] = None
    rationale: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    confidence: str = "HIGH"
    migration_complexity: MigrationComplexity = MigrationComplexity.MEDIUM
    guidance_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize recommendation to API-compatible dictionary."""
        return {
            "asset_id": self.asset_id,
            "current_algorithm": self.current_algorithm,
            "current_primitive": self.current_primitive,
            "recommendation_type": self.recommendation_type.value,
            "recommended_algorithm": self.recommended_algorithm,
            "pqc_standard": self.pqc_standard,
            "hybrid_recommendation": self.hybrid_recommendation,
            "rationale": self.rationale,
            "assumptions": self.assumptions,
            "limitations": self.limitations,
            "confidence": self.confidence,
            "migration_complexity": self.migration_complexity.value,
            "guidance_steps": self.guidance_steps,
        }


@dataclass
class AssetRecommendationDetail:
    """
    Lightweight asset recommendation record for aggregate reports and API listings.

    Provides a compact summary without the full rationale/assumptions lists.
    """
    asset_id: str
    current_algorithm: str
    recommendation_type: str
    recommended_algorithm: Optional[str]
    pqc_standard: Optional[str]
    hybrid_recommendation: Optional[str]
    migration_complexity: str
    confidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "current_algorithm": self.current_algorithm,
            "recommendation_type": self.recommendation_type,
            "recommended_algorithm": self.recommended_algorithm,
            "pqc_standard": self.pqc_standard,
            "hybrid_recommendation": self.hybrid_recommendation,
            "migration_complexity": self.migration_complexity,
            "confidence": self.confidence,
        }


@dataclass
class PQCRecommendationReport:
    """
    Aggregate repository-level PQC recommendation report.

    Conforms to:
      - docs/06_API_AND_DATA_CONTRACTS.md Section 2.5 (PQCRecommendationReport)
      - docs/10_API_CONTRACT.md Section 13 (Recommendations API)

    Attributes:
      total_assets:
          Total number of CryptoAssets analyzed.
      direct_pqc_count:
          Count of assets with DIRECT_PQC recommendation.
      hybrid_count:
          Count of assets with HYBRID recommendation.
      already_pqc_count:
          Count of assets already using NIST-approved PQC algorithms.
      no_migration_required_count:
          Count of assets that do not require PQC migration.
      unknown_count:
          Count of assets where recommendation could not be determined.
      recommendations_by_target_algorithm:
          Counts of recommended target algorithms (e.g. {'ML-KEM-768': 10, 'ML-DSA-65': 5}).
      recommendations_by_current_algorithm:
          Counts of current algorithms that received recommendations.
      recommendations_by_primitive:
          Counts grouped by current PrimitiveType.
      asset_details:
          Lightweight AssetRecommendationDetail list for all assets.
      recommendations:
          Full PQCRecommendation list for all assets.
    """
    total_assets: int
    direct_pqc_count: int
    hybrid_count: int
    already_pqc_count: int
    no_migration_required_count: int
    unknown_count: int
    recommendations_by_target_algorithm: dict[str, int] = field(default_factory=dict)
    recommendations_by_current_algorithm: dict[str, int] = field(default_factory=dict)
    recommendations_by_primitive: dict[str, int] = field(default_factory=dict)
    asset_details: list[AssetRecommendationDetail] = field(default_factory=list)
    recommendations: list[PQCRecommendation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize report matching docs/06 Section 2.5 and docs/10 Section 13 schemas."""
        return {
            "total_assets": self.total_assets,
            "direct_pqc_count": self.direct_pqc_count,
            "hybrid_count": self.hybrid_count,
            "already_pqc_count": self.already_pqc_count,
            "no_migration_required_count": self.no_migration_required_count,
            "unknown_count": self.unknown_count,
            "recommendations_by_target_algorithm": self.recommendations_by_target_algorithm,
            "recommendations_by_current_algorithm": self.recommendations_by_current_algorithm,
            "recommendations_by_primitive": self.recommendations_by_primitive,
            "asset_details": [d.to_dict() for d in self.asset_details],
        }
