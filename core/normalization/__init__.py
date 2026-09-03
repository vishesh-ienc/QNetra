"""
QNetra Normalization Subsystem
==============================

Transforms raw, heterogeneous scanner findings (List[RawFinding]) into canonical,
deduplicated, standards-compliant cryptographic assets (List[CryptoAsset]).

Components:
  - Normalizer: Orchestrator entry point.
  - AlgorithmNormalizer: Canonical naming, alias resolution, parameter extraction.
  - Deduplicator: Grouping, cluster merging, deterministic ID assignment.
  - ConfidenceAggregator: Multi-signal confidence combination.

Layer 2 in QNetra Architecture (docs/02_SYSTEM_ARCHITECTURE.md).
"""

from core.normalization.normalizer import Normalizer

__all__ = ["Normalizer"]
