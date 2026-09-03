"""
QNetra Core Analysis & Intelligence Package
===========================================

Contains the canonical data models, normalization engine, CBOM generator,
quantum risk scoring engine, Mosca theorem analyzer, and PQC recommender.

Layer 2 & Layer 3 in the QNetra Layered Architecture (docs/02_SYSTEM_ARCHITECTURE.md).
"""

from core.models import CryptoAsset, PrimitiveType, SupportingFindingEvidence

__all__ = [
    "CryptoAsset",
    "PrimitiveType",
    "SupportingFindingEvidence",
]
