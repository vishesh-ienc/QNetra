"""
QNetra Recommendation Engine — Engine Orchestrator
===================================================

The primary entry point for Milestone 3.3: NIST PQC Recommendation Engine.

Orchestrates single-asset recommendations, batch evaluations, and aggregate
repository-level PQC recommendation reporting.

Design Principles:
  - Deterministic: Output order and recommendation values are strictly reproducible.
  - Side-effect Isolation: `recommend()` and `recommend_all()` are PURELY FUNCTIONAL.
    They NEVER mutate the input CryptoAsset.
  - Risk/Mosca Independence: Recommendation logic does NOT use risk_score or Mosca urgency.
    These fields are intentionally ignored during routing.
  - No-fabrication: Unknown algorithms return UNKNOWN recommendations.
  - Strict Boundary Separation: Does NOT invoke scanners, normalization, CBOM serialization,
    Risk Engine scoring, Mosca inequality simulation, or FastAPI logic.
  - Only finalized NIST PQC standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).

Usage:
    from core.recommendation_engine import RecommendationEngine

    engine = RecommendationEngine()

    # Pure single-asset recommendation (no asset mutation)
    rec = engine.recommend(asset)

    # Batch recommendation (deterministic sort by asset_id)
    recs = engine.recommend_all(assets)

    # Repository-level report
    report = engine.generate_report(assets, recommendations=recs)

Contract References:
  - docs/05_ALGORITHMS.md (Alg-08: PQC Recommendation Engine)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.5: PQCRecommendationReport)
  - docs/10_API_CONTRACT.md (Section 13: Recommendations API)
"""

from __future__ import annotations

import logging

from core.models import CryptoAsset
from core.recommendation_engine.mapper import map_asset_to_recommendation
from core.recommendation_engine.models import (
    AssetRecommendationDetail,
    PQCRecommendation,
    PQCRecommendationReport,
    PQCRecommendationType,
)

logger = logging.getLogger(__name__)


class RecommendationEngine:
    """
    Deterministic NIST PQC recommendation engine for QNetra.

    Consumes classified CryptoAsset instances and produces per-asset
    PQCRecommendation objects and aggregate PQCRecommendationReport.

    Strict Boundaries:
      ✓ Maps algorithm + primitive type -> PQC recommendation
      ✓ Selects parameter sets (ML-KEM-768 default, escalates for high-security)
      ✓ Determines hybrid vs direct PQC transition strategy
      ✓ Produces explainable rationale, assumptions, limitations
      ✗ Does NOT perform risk scoring (core.risk_engine owns that)
      ✗ Does NOT calculate Mosca urgency (core.mosca_engine owns that)
      ✗ Does NOT run scanners or normalization
      ✗ Does NOT modify CryptoAsset objects (recommend() is pure)
      ✗ Does NOT use risk_score or Mosca urgency to determine recommendations
    """

    def __init__(self) -> None:
        """Initialize RecommendationEngine. No configuration required — fully deterministic."""
        pass

    def recommend(self, asset: CryptoAsset) -> PQCRecommendation:
        """
        Pure functional single-asset PQC recommendation.

        This method NEVER mutates the input CryptoAsset.

        The recommendation is determined solely by:
          - asset.algorithm (canonical name)
          - asset.primitive_type (functional cryptographic category)
          - asset.key_length_bits (if available — used for parameter selection only)
          - asset.curve (if available — used for parameter selection only)
          - asset.quantum_threat_type (if available — used for routing verification only)

        NOT used (never influences recommendation routing):
          - asset.risk_score
          - asset.risk_severity
          - Any Mosca urgency fields

        Args:
            asset: A classified CryptoAsset (with classification fields populated).

        Returns:
            PQCRecommendation — deterministic, fully explainable, never fabricated.
        """
        return map_asset_to_recommendation(asset)

    def recommend_all(self, assets: list[CryptoAsset]) -> list[PQCRecommendation]:
        """
        Pure functional batch PQC recommendation.

        This method NEVER mutates any input CryptoAsset.
        Results are sorted deterministically by asset_id.

        Args:
            assets: List of classified CryptoAssets.

        Returns:
            Deterministic list of PQCRecommendation objects sorted by asset_id.
        """
        recommendations = [self.recommend(asset) for asset in assets]
        # Deterministic sort by asset_id
        recommendations.sort(key=lambda r: r.asset_id)
        return recommendations

    def generate_report(
        self,
        assets: list[CryptoAsset],
        recommendations: list[PQCRecommendation] | None = None,
    ) -> PQCRecommendationReport:
        """
        Generate aggregate repository-level PQCRecommendationReport.

        Conforms to:
          - docs/06_API_AND_DATA_CONTRACTS.md Section 2.5
          - docs/10_API_CONTRACT.md Section 13

        Args:
            assets: List of classified CryptoAssets.
            recommendations: Optional pre-computed recommendations. If None, computed internally.

        Returns:
            Populated PQCRecommendationReport.
        """
        if recommendations is None:
            recommendations = self.recommend_all(assets)

        total_assets = len(assets)

        # Initialize distribution counters
        direct_pqc_count = 0
        classical_upgrade_count = 0
        hybrid_count = 0
        already_pqc_count = 0
        no_migration_required_count = 0
        unknown_count = 0

        recommendations_by_target_algorithm: dict[str, int] = {}
        recommendations_by_current_algorithm: dict[str, int] = {}
        recommendations_by_primitive: dict[str, int] = {}

        for rec in recommendations:
            # Count by recommendation type
            if rec.recommendation_type == PQCRecommendationType.DIRECT_PQC:
                direct_pqc_count += 1
            elif rec.recommendation_type == PQCRecommendationType.CLASSICAL_UPGRADE:
                classical_upgrade_count += 1
            elif rec.recommendation_type == PQCRecommendationType.HYBRID:
                hybrid_count += 1
            elif rec.recommendation_type == PQCRecommendationType.ALREADY_PQC:
                already_pqc_count += 1
            elif rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED:
                no_migration_required_count += 1
            elif rec.recommendation_type == PQCRecommendationType.UNKNOWN:
                unknown_count += 1

            # Count by target algorithm
            if rec.recommended_algorithm is not None:
                key = rec.recommended_algorithm
                recommendations_by_target_algorithm[key] = (
                    recommendations_by_target_algorithm.get(key, 0) + 1
                )

            # Count by current algorithm
            current_alg = rec.current_algorithm
            recommendations_by_current_algorithm[current_alg] = (
                recommendations_by_current_algorithm.get(current_alg, 0) + 1
            )

            # Count by primitive
            primitive = rec.current_primitive
            recommendations_by_primitive[primitive] = (
                recommendations_by_primitive.get(primitive, 0) + 1
            )

        # Build lightweight asset details
        asset_details = [
            AssetRecommendationDetail(
                asset_id=rec.asset_id,
                current_algorithm=rec.current_algorithm,
                recommendation_type=rec.recommendation_type.value,
                recommended_algorithm=rec.recommended_algorithm,
                pqc_standard=rec.pqc_standard,
                hybrid_recommendation=rec.hybrid_recommendation,
                migration_complexity=rec.migration_complexity.value,
                confidence=rec.confidence,
            )
            for rec in recommendations
        ]

        return PQCRecommendationReport(
            total_assets=total_assets,
            direct_pqc_count=direct_pqc_count,
            classical_upgrade_count=classical_upgrade_count,
            hybrid_count=hybrid_count,
            already_pqc_count=already_pqc_count,
            no_migration_required_count=no_migration_required_count,
            unknown_count=unknown_count,
            recommendations_by_target_algorithm=recommendations_by_target_algorithm,
            recommendations_by_current_algorithm=recommendations_by_current_algorithm,
            recommendations_by_primitive=recommendations_by_primitive,
            asset_details=asset_details,
            recommendations=recommendations,
        )
