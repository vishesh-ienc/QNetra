"""
QNetra Risk Engine — Domain Models
===================================

Defines the output data contracts for Milestone 3.1: Deterministic Cryptographic Risk Engine:
  - RiskSeverity: 4-tier risk severity classification (CRITICAL, HIGH, MEDIUM, LOW).
  - RiskFactor: Itemized contributing risk factor with explainable rationale and source attribution.
  - RiskAssessment: Asset-level risk quantification (0–100 score, severity, factor breakdown).
  - AssetRiskDetail: Lightweight summary contract for downstream APIs and reports.
  - RiskAssessmentReport: Aggregate repository-level risk assessment report.

Contract References:
  - docs/05_ALGORITHMS.md (Alg-06: Deterministic Quantum Vulnerability Risk Scoring)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.3: RiskAssessmentReport)
  - docs/10_API_CONTRACT.md (Section 8: Crypto Assets API & Section 9: Risk API)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class RiskSeverity(str, Enum):
    """
    Standardized cryptographic risk severity tiers conforming to:
      - docs/05_ALGORITHMS.md Alg-06
      - docs/06_API_AND_DATA_CONTRACTS.md Section 2.3
      - docs/10_API_CONTRACT.md Section 9

    Tiers:
      CRITICAL : Score 80–100 (Shor-broken asymmetric, classically broken primitives)
      HIGH     : Score 60–79  (Symmetric < 256 bits, SHA-224, legacy TLS)
      MEDIUM   : Score 30–59  (SHA-256, unverified key parameters)
      LOW      : Score 0–29   (AES-256, SHA-384/512, NIST-approved PQC)
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float | int) -> RiskSeverity:
        """
        Derive severity tier from numerical risk score [0, 100].

        Thresholds (docs/05_ALGORITHMS.md Alg-06):
          >= 80 -> CRITICAL
          >= 60 -> HIGH
          >= 30 -> MEDIUM
          < 30  -> LOW
        """
        clamped = max(0.0, min(100.0, float(score)))
        if clamped >= 80.0:
            return cls.CRITICAL
        if clamped >= 60.0:
            return cls.HIGH
        if clamped >= 30.0:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class RiskFactor:
    """
    An individual explainable component of an asset's risk score.

    Every non-zero contribution to an asset's risk score is explicitly
    traced to a named RiskFactor, ensuring zero black-box logic (RULE-002).
    """
    name: str
    """Machine-readable factor identifier (e.g. 'quantum_vulnerability', 'parameter_modifier')."""

    score: float
    """Score contribution (may be positive or negative modifier)."""

    maximum: float
    """Maximum possible positive contribution of this factor category."""

    reason: str
    """Human-readable explanation of why this factor was applied."""

    source_field: str
    """Underlying CryptoAsset or Classification field that drove this factor."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize factor to dictionary."""
        return {
            "name": self.name,
            "score": round(self.score, 2),
            "maximum": round(self.maximum, 2),
            "reason": self.reason,
            "source_field": self.source_field,
        }


@dataclass
class RiskAssessment:
    """
    Deterministic risk evaluation result for a single CryptoAsset.

    Attributes:
      asset_id: UUID of the evaluated CryptoAsset.
      risk_score: Integer risk score bounded strictly within [0, 100].
      severity: Standardized severity tier (CRITICAL, HIGH, MEDIUM, LOW).
      factors: List of contributing RiskFactor instances explaining the score.
      rationale: Human-readable synthesis of the risk score calculation.
      confidence: Discovery confidence preserved as explanatory metadata (does NOT dilute risk).
    """
    asset_id: str
    risk_score: int
    severity: RiskSeverity
    factors: list[RiskFactor] = field(default_factory=list)
    rationale: str = ""
    confidence: Optional[float] = None

    def __post_init__(self) -> None:
        # Enforce [0, 100] bounding invariant
        if not (0 <= self.risk_score <= 100):
            raise ValueError(f"risk_score must be between 0 and 100; got {self.risk_score}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize assessment to API-compatible dictionary."""
        return {
            "asset_id": self.asset_id,
            "risk_score": self.risk_score,
            "severity": self.severity.value,
            "factors": [f.to_dict() for f in self.factors],
            "rationale": self.rationale,
            "confidence": round(self.confidence, 4) if self.confidence is not None else None,
        }


@dataclass
class AssetRiskDetail:
    """
    Lightweight asset risk record conforming strictly to
    docs/06_API_AND_DATA_CONTRACTS.md Section 2.3 `AssetRiskDetail`.
    """
    asset_id: str
    score: int
    severity: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "score": self.score,
            "severity": self.severity,
            "rationale": self.rationale,
        }


@dataclass
class RiskAssessmentReport:
    """
    Aggregate repository-level risk assessment report.

    Conforms to:
      - docs/06_API_AND_DATA_CONTRACTS.md Section 2.3 (`RiskAssessmentReport`)
      - docs/10_API_CONTRACT.md Section 9 (`GET /scans/{scan_id}/risk`)
    """
    overall_risk_score: float
    """Normalized aggregate repository risk score [0.0, 100.0]."""

    overall_severity: RiskSeverity
    """Overall repository risk severity tier."""

    total_assets_discovered: int
    """Total count of cryptographic assets discovered in the target."""

    vulnerable_assets_count: int
    """Count of assets deemed quantum or classically vulnerable (score >= 60 or quantum_vulnerable=True)."""

    shor_vulnerable_count: int
    """Count of asymmetric assets broken by Shor's polynomial-time algorithm."""

    grover_impacted_count: int
    """Count of symmetric / hash assets with degraded post-quantum security under Grover/BHT."""

    classically_broken_count: int
    """Count of assets with known classical cryptanalytic breaks (MD5, SHA-1, DES)."""

    quantum_resistant_count: int
    """Count of assets with adequate post-quantum security (AES-256, SHA-384/512, ML-KEM, ML-DSA)."""

    severity_distribution: dict[str, int] = field(default_factory=dict)
    """Count of assets in each severity tier: {'CRITICAL': n, 'HIGH': n, 'MEDIUM': n, 'LOW': n}."""

    asset_scores: list[AssetRiskDetail] = field(default_factory=list)
    """Itemized scores and rationales for each asset (docs/06 contract)."""

    assessments: list[RiskAssessment] = field(default_factory=list)
    """Full itemized RiskAssessment models with detailed factor breakdowns."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize report matching docs/06 and docs/10 schemas."""
        return {
            "overall_risk_score": round(self.overall_risk_score, 1),
            "overall_severity": self.overall_severity.value,
            "total_assets_discovered": self.total_assets_discovered,
            "vulnerable_assets_count": self.vulnerable_assets_count,
            "shor_vulnerable_count": self.shor_vulnerable_count,
            "grover_impacted_count": self.grover_impacted_count,
            "classically_broken_count": self.classically_broken_count,
            "quantum_resistant_count": self.quantum_resistant_count,
            "severity_distribution": self.severity_distribution,
            "asset_scores": [item.to_dict() for item in self.asset_scores],
        }
