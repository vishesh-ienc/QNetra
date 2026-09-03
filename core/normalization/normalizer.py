"""
QNetra Normalization Subsystem — Orchestrator
=============================================

Public entry point for Layer 2 Normalization.
Converts a sequence of heterogeneous `RawFinding` evidence records into
standardized, deduplicated, and traceable `CryptoAsset` canonical records.

Architecture Reference:
  - docs/02_SYSTEM_ARCHITECTURE.md (Layer 2)
  - docs/03_DATA_FLOW.md (Stage 5)
  - docs/04_MODULES.md (MOD-005)
"""

from __future__ import annotations

from typing import Any, Sequence

from pydantic import BaseModel, Field

from core.models import CryptoAsset
from core.normalization.deduplicator import Deduplicator
from scanners.framework.models import RawFinding


class NormalizationStatistics(BaseModel):
    """Execution metrics and aggregation summary for a normalization pass."""
    raw_findings_count: int = 0
    assets_produced_count: int = 0
    findings_merged_count: int = 0
    merge_ratio: float = 0.0
    assets_by_algorithm: dict[str, int] = Field(default_factory=dict)
    assets_by_primitive_type: dict[str, int] = Field(default_factory=dict)
    assets_by_library: dict[str, int] = Field(default_factory=dict)
    assets_by_confidence_level: dict[str, int] = Field(default_factory=dict)


class Normalizer:
    """
    Main Normalization Engine.
    Coordinates algorithm canonicalization, multi-signal deduplication,
    confidence aggregation, and deterministic ID generation.
    """

    def __init__(self) -> None:
        self._deduplicator = Deduplicator()

    def normalize(self, findings: Sequence[RawFinding]) -> list[CryptoAsset]:
        """
        Normalize and deduplicate a sequence of RawFinding records into canonical CryptoAssets.

        Args:
            findings: Sequence of RawFinding instances emitted by scanners.

        Returns:
            Deterministic, sorted list of canonical CryptoAsset instances.
        """
        if not findings:
            return []

        return self._deduplicator.deduplicate(findings)

    @staticmethod
    def compute_statistics(
        findings: Sequence[RawFinding],
        assets: Sequence[CryptoAsset],
    ) -> NormalizationStatistics:
        """
        Compute quantitative metrics comparing raw findings input to normalized assets output.
        """
        raw_count = len(findings)
        asset_count = len(assets)
        merged_count = max(0, raw_count - asset_count)
        ratio = round(merged_count / raw_count, 4) if raw_count > 0 else 0.0

        by_alg: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_lib: dict[str, int] = {}
        by_conf: dict[str, int] = {}

        for a in assets:
            by_alg[a.algorithm] = by_alg.get(a.algorithm, 0) + 1
            by_type[a.primitive_type.value] = by_type.get(a.primitive_type.value, 0) + 1
            lib = a.implementation_library or "Unspecified"
            by_lib[lib] = by_lib.get(lib, 0) + 1
            by_conf[a.confidence_level.value] = by_conf.get(a.confidence_level.value, 0) + 1

        return NormalizationStatistics(
            raw_findings_count=raw_count,
            assets_produced_count=asset_count,
            findings_merged_count=merged_count,
            merge_ratio=ratio,
            assets_by_algorithm=dict(sorted(by_alg.items(), key=lambda x: -x[1])),
            assets_by_primitive_type=dict(sorted(by_type.items(), key=lambda x: -x[1])),
            assets_by_library=dict(sorted(by_lib.items(), key=lambda x: -x[1])),
            assets_by_confidence_level=dict(sorted(by_conf.items(), key=lambda x: -x[1])),
        )
