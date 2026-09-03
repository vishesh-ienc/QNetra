"""
QNetra Classification Layer — Public API
==========================================

Exposes ClassificationEngine as the primary public interface.

Usage:
  from core.classification import ClassificationEngine
  engine = ClassificationEngine()
  classified_assets = engine.classify(normalized_assets)

Also exports classification domain models for testing and inspection.
"""

from core.classification.classifier import ClassificationEngine
from core.classification.models import (
    ClassicalSecurityStatus,
    ClassificationResult,
    QuantumSecurityStatus,
)

__all__ = [
    "ClassificationEngine",
    "ClassicalSecurityStatus",
    "ClassificationResult",
    "QuantumSecurityStatus",
]
