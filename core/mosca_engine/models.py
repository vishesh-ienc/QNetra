"""
QNetra Mosca Engine — Domain Models
=====================================

Defines the output data contracts for Milestone 3.2: Mosca Migration Engine:
  - MoscaUrgency: Migration urgency levels (IMMEDIATE, URGENT, PLANNED, MONITOR, NOT_REQUIRED, UNKNOWN).
  - HNDLExposure: Harvest Now, Decrypt Later exposure tiers (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN).
  - MoscaInput: Per-asset context inputs for Mosca evaluation (X, Y, Z, HNDL sensitivity, date).
  - MoscaAssessment: Per-asset Mosca result with inequality, HNDL, urgency, deadline, and explainability.
  - AssetMoscaDetail: Lightweight summary for API responses and downstream reports.
  - MoscaAssessmentReport: Aggregate repository-level Mosca/HNDL report.

Naming Convention (strictly follows docs/06_API_AND_DATA_CONTRACTS.md §2.4 and docs/09_KNOWLEDGE_BASE.md §2.1):
  X = Data Shelf Life (years data must remain confidential)
  Y = Migration Time (years to migrate systems)
  Z = Quantum Threat Horizon (years until CRQC arrival)
  Mosca Inequality: X + Y > Z

Contract References:
  - docs/05_ALGORITHMS.md (Alg-07: Michele Mosca Migration Inequality)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.4: MoscaAssessmentReport)
  - docs/09_KNOWLEDGE_BASE.md (Section 2.1: Mosca's Theorem)
  - docs/10_API_CONTRACT.md (Section 12: Mosca API)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Any, Optional


class MoscaUrgency(str, Enum):
    """
    Migration urgency classification derived from Mosca inequality and HNDL analysis.

    Tiers:
      IMMEDIATE    : X + Y > Z with short gap (≤ 2 yrs) or HNDL CRITICAL — begin NOW.
      URGENT       : X + Y > Z or HNDL HIGH — begin within months.
      PLANNED      : X + Y ≤ Z but migration window is narrow — schedule now.
      MONITOR      : Safe but future-facing migration warranted.
      NOT_REQUIRED : Asset is quantum-resistant or non-applicable — no migration needed.
      UNKNOWN      : Insufficient inputs to determine urgency.
    """
    IMMEDIATE = "IMMEDIATE"
    URGENT = "URGENT"
    PLANNED = "PLANNED"
    MONITOR = "MONITOR"
    NOT_REQUIRED = "NOT_REQUIRED"
    UNKNOWN = "UNKNOWN"


class HNDLExposure(str, Enum):
    """
    Harvest Now, Decrypt Later (HNDL) exposure tier.

    HNDL means adversaries may intercept and archive ciphertext today, intending to
    decrypt it when a Cryptographically Relevant Quantum Computer (CRQC) becomes available.

    Tiers:
      CRITICAL : Shor-vulnerable + protected lifetime far exceeds quantum horizon + HNDL sensitive
      HIGH     : Shor-vulnerable + protected lifetime extends past quantum horizon
      MEDIUM   : Shor-vulnerable + protected lifetime near quantum horizon threshold
      LOW      : Shor-vulnerable + protected lifetime well within quantum horizon
      NONE     : Quantum-resistant; no meaningful HNDL risk
      UNKNOWN  : Insufficient information to assess HNDL exposure
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


@dataclass
class MoscaInput:
    """
    Per-asset call-site context for Mosca evaluation.

    All timing fields are in decimal years.

    Fields:
      asset_id               : Must match CryptoAsset.asset_id.
      migration_time_years   : Y — override the engine's inferred migration time (optional).
      quantum_arrival_years  : Z — override the engine's configured quantum horizon (optional).
      protected_lifetime_years : X — how long the data must remain confidential.
                                 CRITICAL: If omitted, the engine returns UNKNOWN urgency
                                 and cannot compute the inequality. No default is fabricated.
      hndl_sensitive         : Explicit flag indicating the asset protects long-lived sensitive data.
                               None means "not specified" (engine uses structural inference).
      assessment_date        : Reference date for deadline calculations.
                               MUST be explicit — engine never reads datetime.now() internally.
    """
    asset_id: str
    migration_time_years: Optional[float] = None
    quantum_arrival_years: Optional[float] = None
    protected_lifetime_years: Optional[float] = None
    hndl_sensitive: Optional[bool] = None
    assessment_date: Optional[date] = None


@dataclass
class MoscaAssessment:
    """
    Deterministic Mosca migration urgency evaluation result for a single CryptoAsset.

    Explicitly exposes all Mosca inequality components for full transparency (RULE-002):
      asset_id                         : UUID of the evaluated CryptoAsset.
      x_data_lifetime_years            : X — data shelf life supplied or inferred.
      y_migration_time_years           : Y — migration effort in years.
      z_quantum_arrival_years          : Z — estimated years until CRQC (quantum horizon).
      x_plus_y                         : X + Y sum (None if X or Y missing).
      inequality_triggered             : True if X + Y > Z. None if inputs insufficient.
      exposure_gap_years               : max(0, (X+Y) - Z). None if not computable.
      urgency                          : MoscaUrgency classification.
      hndl_exposure                    : HNDLExposure classification.
      migration_deadline_years_from_now: Z - Y — years until last safe migration start.
      assessment_date                  : Reference date for deadline; None if not provided.
      mosca_applicable                 : False for Library/Random/PQC (NOT_APPLICABLE category).
      assumptions                      : List of documented assumptions made during evaluation.
      rationale                        : Ordered explanatory statements for this assessment.
    """
    asset_id: str
    x_data_lifetime_years: Optional[float]
    y_migration_time_years: Optional[float]
    z_quantum_arrival_years: Optional[float]
    x_plus_y: Optional[float]
    inequality_triggered: Optional[bool]
    exposure_gap_years: Optional[float]
    urgency: MoscaUrgency
    hndl_exposure: HNDLExposure
    migration_deadline_years_from_now: Optional[float]
    assessment_date: Optional[date]
    mosca_applicable: bool
    assumptions: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to API-compatible dictionary (docs/10 §12 and docs/06 §2.4)."""
        return {
            "asset_id": self.asset_id,
            "x_data_lifetime_years": self.x_data_lifetime_years,
            "y_migration_time_years": self.y_migration_time_years,
            "z_quantum_arrival_years": self.z_quantum_arrival_years,
            "x_plus_y": (
                round(self.x_plus_y, 4) if self.x_plus_y is not None else None
            ),
            "inequality_triggered": self.inequality_triggered,
            "exposure_gap_years": (
                round(self.exposure_gap_years, 4)
                if self.exposure_gap_years is not None
                else None
            ),
            "urgency": self.urgency.value,
            "hndl_exposure": self.hndl_exposure.value,
            "migration_deadline_years_from_now": (
                round(self.migration_deadline_years_from_now, 4)
                if self.migration_deadline_years_from_now is not None
                else None
            ),
            "assessment_date": (
                self.assessment_date.isoformat()
                if self.assessment_date is not None
                else None
            ),
            "mosca_applicable": self.mosca_applicable,
            "assumptions": list(self.assumptions),
            "rationale": list(self.rationale),
        }


@dataclass
class AssetMoscaDetail:
    """
    Lightweight Mosca summary record for use inside MoscaAssessmentReport.

    Conforms to the report detail list structure in docs/06 §2.4.
    """
    asset_id: str
    urgency: str
    hndl_exposure: str
    inequality_triggered: Optional[bool]
    mosca_applicable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "urgency": self.urgency,
            "hndl_exposure": self.hndl_exposure,
            "inequality_triggered": self.inequality_triggered,
            "mosca_applicable": self.mosca_applicable,
        }


@dataclass
class MoscaAssessmentReport:
    """
    Aggregate repository-level Mosca and HNDL assessment report.

    Conforms to:
      - docs/06_API_AND_DATA_CONTRACTS.md Section 2.4 (MoscaAssessmentReport)
      - docs/10_API_CONTRACT.md Section 12 (Mosca API)

    Fields:
      total_assets           : Total count of CryptoAssets evaluated.
      mosca_applicable_assets: Count of assets for which Mosca analysis applies.
      mosca_triggered_assets : Count where X + Y > Z (inequality is True).
      hndl_exposed_assets    : Count with HNDLExposure not NONE and not UNKNOWN.
      urgency_distribution   : Count per MoscaUrgency tier.
      hndl_distribution      : Count per HNDLExposure tier.
      highest_urgency_assets : Summary of the most urgent assets.
      assessments            : Full per-asset MoscaAssessment list.
    """
    total_assets: int
    mosca_applicable_assets: int
    mosca_triggered_assets: int
    hndl_exposed_assets: int
    urgency_distribution: dict[str, int]
    hndl_distribution: dict[str, int]
    highest_urgency_assets: list[AssetMoscaDetail]
    assessments: list[MoscaAssessment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize conforming to docs/06 §2.4 and docs/10 §12."""
        return {
            "total_assets": self.total_assets,
            "mosca_applicable_assets": self.mosca_applicable_assets,
            "mosca_triggered_assets": self.mosca_triggered_assets,
            "hndl_exposed_assets": self.hndl_exposed_assets,
            "urgency_distribution": dict(self.urgency_distribution),
            "hndl_distribution": dict(self.hndl_distribution),
            "highest_urgency_assets": [
                a.to_dict() for a in self.highest_urgency_assets
            ],
        }
