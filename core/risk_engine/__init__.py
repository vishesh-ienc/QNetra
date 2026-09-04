"""
QNetra Risk Engine — Public Package Interface
==============================================

Milestone 3.1: Deterministic Cryptographic Risk Engine

Provides deterministic, auditable 0–100 risk scoring and 4-tier severity assessment
for canonical CryptoAsset instances.

Public API:
    from core.risk_engine import (
        RiskEngine,
        RiskAssessment,
        RiskAssessmentReport,
        RiskFactor,
        RiskSeverity,
        AssetRiskDetail,
        RiskScorer,
    )

Pipeline Position:
    Scanners → Normalization → CryptoAsset → Classification → Risk Engine → Mosca Engine
                                                  └→ CBOM         └→ Recommendations

References:
    - docs/05_ALGORITHMS.md (Alg-06)
    - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.3)
    - docs/10_API_CONTRACT.md (Section 9)
    - PROJECT_RULES.md (RULE-002, RULE-003)
"""

from core.risk_engine.engine import RiskEngine
from core.risk_engine.models import (
    AssetRiskDetail,
    RiskAssessment,
    RiskAssessmentReport,
    RiskFactor,
    RiskSeverity,
)
from core.risk_engine.scorer import RiskScorer

__all__ = [
    "RiskEngine",
    "RiskAssessment",
    "RiskAssessmentReport",
    "RiskFactor",
    "RiskSeverity",
    "AssetRiskDetail",
    "RiskScorer",
]
