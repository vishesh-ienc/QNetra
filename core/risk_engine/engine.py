"""
QNetra Risk Engine — Engine Orchestrator
=========================================

The primary entry point for Milestone 3.1 Risk Analysis.
Orchestrates single-asset assessments, batch evaluations, in-place asset enrichment,
and aggregate repository-level risk reporting.

Design Principles:
  - Deterministic: Output order and numerical values are strictly reproducible.
  - Side-effect Isolation: `assess()` and `assess_all()` are purely functional.
    In-place mutation is explicitly isolated to `assess_and_enrich()` and
    `assess_and_enrich_all()`.
  - Architecture Decoupling: Does not invoke scanners, normalization, CBOM serialization,
    Mosca timeline simulation, or recommendation mapping.

Usage:
    from core.risk_engine import RiskEngine

    engine = RiskEngine()

    # Pure single-asset assessment (no asset mutation)
    assessment = engine.assess(asset)

    # Pure batch assessment (deterministic sorting by asset_id)
    assessments = engine.assess_all(assets)

    # In-place enrichment (populates asset.risk_score and asset.risk_severity)
    enriched_assessments = engine.assess_and_enrich_all(assets)

    # Generate repository-level executive report
    report = engine.generate_report(assets)
"""

from __future__ import annotations

import logging
from typing import Optional

from core.classification.models import ClassicalSecurityStatus, QuantumSecurityStatus
from core.models import CryptoAsset
from core.risk_engine.knowledge import REPO_MAX_WEIGHT, REPO_MEAN_WEIGHT
from core.risk_engine.models import (
    AssetRiskDetail,
    RiskAssessment,
    RiskAssessmentReport,
    RiskSeverity,
)
from core.risk_engine.scorer import RiskScorer
from scanners.registry.crypto_algorithms import QuantumThreat

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Deterministic cryptographic risk scoring and reporting engine.
    """

    def __init__(self) -> None:
        pass

    def assess(self, asset: CryptoAsset) -> RiskAssessment:
        """
        Pure risk evaluation for a single CryptoAsset.
        Does NOT mutate the input asset.

        Args:
            asset: Enriched canonical CryptoAsset.

        Returns:
            RiskAssessment with bounded score, severity, and factor breakdown.
        """
        return RiskScorer.calculate_risk(asset)

    def assess_all(self, assets: list[CryptoAsset]) -> list[RiskAssessment]:
        """
        Pure batch risk evaluation for a list of CryptoAssets.
        Does NOT mutate the input assets.

        Returns assessments sorted deterministically by asset_id.

        Args:
            assets: List of canonical CryptoAssets.

        Returns:
            Deterministic list of RiskAssessment objects sorted by asset_id.
        """
        assessments = [self.assess(asset) for asset in assets]
        # Sort deterministically by asset_id
        assessments.sort(key=lambda a: a.asset_id)
        return assessments

    def assess_and_enrich(self, asset: CryptoAsset) -> RiskAssessment:
        """
        Evaluate risk score and enrich the input CryptoAsset in place.
        Populates asset.risk_score and asset.risk_severity.

        Args:
            asset: Canonical CryptoAsset to evaluate and update.

        Returns:
            RiskAssessment instance.
        """
        assessment = self.assess(asset)
        asset.risk_score = assessment.risk_score
        asset.risk_severity = assessment.severity.value
        return assessment

    def assess_and_enrich_all(self, assets: list[CryptoAsset]) -> list[RiskAssessment]:
        """
        Evaluate risk scores and enrich all input CryptoAssets in place.
        Populates risk_score and risk_severity on every asset.

        Returns assessments sorted deterministically by asset_id.

        Args:
            assets: List of canonical CryptoAssets to enrich.

        Returns:
            List of RiskAssessment objects sorted by asset_id.
        """
        assessments = [self.assess_and_enrich(asset) for asset in assets]
        assessments.sort(key=lambda a: a.asset_id)
        return assessments

    def generate_report(
        self,
        assets: list[CryptoAsset],
        assessments: Optional[list[RiskAssessment]] = None,
    ) -> RiskAssessmentReport:
        """
        Generate aggregate repository-level RiskAssessmentReport conforming to:
          - docs/06_API_AND_DATA_CONTRACTS.md Section 2.3
          - docs/10_API_CONTRACT.md Section 9

        Args:
            assets: List of evaluated or to-be-evaluated CryptoAssets.
            assessments: Optional pre-computed assessments. If None, computes them.

        Returns:
            Populated RiskAssessmentReport.
        """
        if assessments is None:
            assessments = self.assess_all(assets)

        total_assets = len(assets)
        if total_assets == 0:
            return RiskAssessmentReport(
                overall_risk_score=0.0,
                overall_severity=RiskSeverity.LOW,
                total_assets_discovered=0,
                vulnerable_assets_count=0,
                shor_vulnerable_count=0,
                grover_impacted_count=0,
                classically_broken_count=0,
                quantum_resistant_count=0,
                severity_distribution={
                    RiskSeverity.CRITICAL.value: 0,
                    RiskSeverity.HIGH.value: 0,
                    RiskSeverity.MEDIUM.value: 0,
                    RiskSeverity.LOW.value: 0,
                },
                asset_scores=[],
                assessments=[],
            )

        # Map asset_id to assessment for easy lookup
        assessment_map = {a.asset_id: a for a in assessments}

        # Calculate severity distribution
        severity_counts = {
            RiskSeverity.CRITICAL.value: 0,
            RiskSeverity.HIGH.value: 0,
            RiskSeverity.MEDIUM.value: 0,
            RiskSeverity.LOW.value: 0,
        }
        for a in assessments:
            severity_counts[a.severity.value] += 1

        # Calculate categorized counts
        shor_count = 0
        grover_count = 0
        classically_broken_count = 0
        quantum_resistant_count = 0
        vulnerable_count = 0

        for asset in assets:
            score = assessment_map[asset.asset_id].risk_score
            is_vuln = (
                score >= 60
                or asset.quantum_vulnerable is True
                or asset.classical_security_status == ClassicalSecurityStatus.BROKEN
            )
            if is_vuln:
                vulnerable_count += 1

            if asset.quantum_threat_type == QuantumThreat.SHOR_POLYNOMIAL_BREAK.value:
                shor_count += 1
            elif (
                asset.quantum_threat_type == QuantumThreat.GROVER_BIT_HALVING.value
                and asset.quantum_vulnerable is True
            ):
                grover_count += 1

            if (
                asset.classical_security_status == ClassicalSecurityStatus.BROKEN
                or asset.quantum_threat_type == QuantumThreat.CLASSICALLY_BROKEN.value
            ):
                classically_broken_count += 1

            if (
                asset.quantum_threat_type == QuantumThreat.QUANTUM_RESISTANT.value
                or (asset.quantum_vulnerable is False and asset.classical_security_status == ClassicalSecurityStatus.SECURE)
            ):
                quantum_resistant_count += 1

        # Calculate overall repository risk score
        # Formula: 0.7 * Max(Score) + 0.3 * Mean(Score) (bounded [0.0, 100.0])
        scores = [a.risk_score for a in assessments]
        max_score = max(scores)
        mean_score = sum(scores) / total_assets
        overall_score = round(
            max(0.0, min(100.0, REPO_MAX_WEIGHT * max_score + REPO_MEAN_WEIGHT * mean_score)),
            1,
        )
        overall_severity = RiskSeverity.from_score(overall_score)

        # Build lightweight AssetRiskDetail items (docs/06 Section 2.3 contract)
        asset_scores = [
            AssetRiskDetail(
                asset_id=a.asset_id,
                score=a.risk_score,
                severity=a.severity.value,
                rationale=a.rationale,
            )
            for a in assessments
        ]

        return RiskAssessmentReport(
            overall_risk_score=overall_score,
            overall_severity=overall_severity,
            total_assets_discovered=total_assets,
            vulnerable_assets_count=vulnerable_count,
            shor_vulnerable_count=shor_count,
            grover_impacted_count=grover_count,
            classically_broken_count=classically_broken_count,
            quantum_resistant_count=quantum_resistant_count,
            severity_distribution=severity_counts,
            asset_scores=asset_scores,
            assessments=assessments,
        )
