"""
QNetra Normalization Subsystem — Confidence Aggregation Engine
==============================================================

Provides deterministic, formulaic, and explainable confidence aggregation when
multiple RawFindings support a single canonical CryptoAsset.

Mathematical Model:
  Let findings F_1, ..., F_n have individual confidence scores s_1, ..., s_n.
  Anchor score: S_max = max(s_1, ..., s_n)
  Corroboration bonus: B = sum_{i != max} (0.05 * s_i)
  Aggregated Score: C_agg = min(1.0, S_max + B)

Properties:
  - Strictly monotonic: Corroborating evidence never lowers confidence.
  - Bounded in [0.0, 1.0].
  - 100% deterministic and explainable (RULE-002).
  - Preserves original finding-level confidence values as supporting evidence.

Contract Reference:
  - docs/05_ALGORITHMS.md
  - docs/06_API_AND_DATA_CONTRACTS.md
"""

from __future__ import annotations

from typing import Sequence

from scanners.framework.models import ConfidenceLevel, RawFinding


class ConfidenceAggregator:
    """
    Computes aggregated confidence scores and human-readable rationales
    for clusters of corroborating raw findings.
    """

    @staticmethod
    def aggregate(findings: Sequence[RawFinding]) -> tuple[float, ConfidenceLevel, str]:
        """
        Aggregate confidence across one or more raw findings.

        Args:
            findings: Non-empty sequence of RawFinding objects.

        Returns:
            Tuple of (confidence_score, confidence_level, confidence_rationale).
        """
        if not findings:
            return 0.0, ConfidenceLevel.VERY_LOW, "No findings provided"

        if len(findings) == 1:
            f = findings[0]
            score = round(f.confidence_score, 4)
            return score, f.confidence_level, f.confidence_rationale

        # Multiple findings: find anchor (max score)
        scores = [f.confidence_score for f in findings]
        max_idx = max(range(len(scores)), key=lambda i: scores[i])
        s_max = scores[max_idx]
        anchor_finding = findings[max_idx]

        # Calculate corroboration bonus
        bonus = 0.0
        for i, score in enumerate(scores):
            if i != max_idx:
                bonus += 0.05 * score

        c_agg = min(1.0, round(s_max + bonus, 4))

        # Derive descriptive confidence tier
        level = ConfidenceAggregator.derive_level(c_agg)

        # Build explainable rationale
        methods = sorted(set(f.discovery_method.value for f in findings))
        scanners = sorted(set(f.scanner_name for f in findings))
        rationale = (
            f"Multi-finding aggregated confidence ({len(findings)} findings across {', '.join(scanners)}): "
            f"base anchor {s_max:.2f} ({anchor_finding.discovery_method.value}) + "
            f"corroboration bonus (+{bonus:.2f} via {', '.join(methods)}) -> Final: {c_agg:.2f}"
        )

        return c_agg, level, rationale

    @staticmethod
    def derive_level(score: float) -> ConfidenceLevel:
        """Derive standard ConfidenceLevel from float score."""
        if score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        elif score >= 0.70:
            return ConfidenceLevel.HIGH
        elif score >= 0.45:
            return ConfidenceLevel.MEDIUM
        elif score >= 0.20:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
