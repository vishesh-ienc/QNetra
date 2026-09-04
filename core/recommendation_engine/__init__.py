"""
QNetra Recommendation Engine — Public API
==========================================

Exports the public interface for the NIST PQC Recommendation Engine (Milestone 3.3).

Usage:
    from core.recommendation_engine import (
        RecommendationEngine,
        PQCRecommendation,
        PQCRecommendationReport,
        PQCRecommendationType,
        MigrationComplexity,
    )

Contract References:
  - docs/04_MODULES.md (Module: core.recommendation_engine)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.5)
"""

from core.recommendation_engine.engine import RecommendationEngine
from core.recommendation_engine.models import (
    AssetRecommendationDetail,
    MigrationComplexity,
    PQCRecommendation,
    PQCRecommendationReport,
    PQCRecommendationType,
)

__all__ = [
    "RecommendationEngine",
    "PQCRecommendation",
    "PQCRecommendationReport",
    "PQCRecommendationType",
    "MigrationComplexity",
    "AssetRecommendationDetail",
]
