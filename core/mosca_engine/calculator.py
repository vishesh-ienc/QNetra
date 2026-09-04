"""
QNetra Mosca Engine — Pure Calculation Functions
=================================================

All functions in this module are PURELY FUNCTIONAL (no side effects, no mutations).

Implements Alg-07: Michele Mosca Migration Inequality & Urgency Evaluation.

Mathematical Foundation:
  Mosca Inequality: X + Y > Z
    X = Data Shelf Life   (years)
    Y = Migration Time    (years)
    Z = Quantum Horizon   (years until CRQC)

Boundary Condition:
  X + Y == Z → inequality is FALSE. No margin, but not triggered.
  (Do NOT treat equality as triggered. See docs/05 Alg-07 §11.)

Invalid Input Rejection:
  Negative values → ValueError
  NaN, Infinity   → ValueError

Contract References:
  - docs/05_ALGORITHMS.md (Alg-07)
  - docs/09_KNOWLEDGE_BASE.md (§2.1)
"""

from __future__ import annotations

import math
from typing import Optional

from core.mosca_engine.knowledge import (
    HNDL_CRITICAL_BUFFER_YEARS,
    HNDL_HIGH_MARGIN_YEARS,
    HNDL_MEDIUM_THRESHOLD_YEARS,
    HNDL_MINIMUM_MEANINGFUL_LIFETIME,
    URGENCY_PLANNED_BUFFER_THRESHOLD,
    URGENCY_URGENT_GAP_THRESHOLD,
)
from core.mosca_engine.models import HNDLExposure, MoscaUrgency


def validate_duration(name: str, value: float) -> None:
    """
    Validate that a duration value is a finite, non-negative number.

    Args:
        name: Human-readable name for error messages.
        value: Duration in years to validate.

    Raises:
        ValueError: If value is negative, NaN, or infinite.
        TypeError:  If value is not a numeric type.
    """
    if not isinstance(value, (int, float)):
        raise TypeError(
            f"Duration '{name}' must be a numeric type; got {type(value).__name__}."
        )
    if math.isnan(value):
        raise ValueError(
            f"Duration '{name}' must not be NaN. Provide a valid non-negative number."
        )
    if math.isinf(value):
        raise ValueError(
            f"Duration '{name}' must not be infinite. Provide a bounded non-negative number."
        )
    if value < 0.0:
        raise ValueError(
            f"Duration '{name}' must be non-negative (≥ 0); got {value}."
        )


def evaluate_inequality(x: float, y: float, z: float) -> bool:
    """
    Evaluate the Mosca inequality: X + Y > Z.

    Mathematical convention (docs/05 Alg-07 §10–11):
      True  → X + Y > Z (HNDL exposure window exists)
      False → X + Y ≤ Z (includes exact equality: no margin, but not triggered)

    Args:
        x: Data shelf life in years (must be validated before calling).
        y: Migration time in years (must be validated before calling).
        z: Quantum threat horizon in years (must be validated before calling).

    Returns:
        True if X + Y strictly exceeds Z, False otherwise.
    """
    return (x + y) > z


def calculate_x_plus_y(x: float, y: float) -> float:
    """Calculate X + Y sum."""
    return x + y


def calculate_exposure_gap(x: float, y: float, z: float) -> float:
    """
    Calculate the HNDL exposure gap.

    Formula: max(0.0, (X + Y) - Z)
    A positive gap means the organization has more urgency than the quantum horizon allows.
    A zero gap means X + Y ≤ Z (no triggered exposure gap).

    Args:
        x: Data shelf life (years).
        y: Migration time (years).
        z: Quantum threat horizon (years).

    Returns:
        Exposure gap in years [0.0, ∞).
    """
    return max(0.0, (x + y) - z)


def calculate_deadline_years_from_now(z: float, y: float) -> float:
    """
    Calculate migration deadline as years from assessment date.

    Conceptual formula (docs/05 Alg-07 §15):
      migration_deadline ≈ quantum_horizon - migration_time
                         = Z - Y

    Rationale: If the CRQC arrives in Z years, and migration takes Y years,
    the latest safe migration start is Z - Y years from now.

    Args:
        z: Quantum threat horizon (years).
        y: Migration time (years).

    Returns:
        Years from assessment date until migration should be completed.
        May be negative if Z < Y (migration already overdue relative to horizon).
    """
    return z - y


def classify_hndl_exposure(
    quantum_vulnerable: Optional[bool],
    quantum_threat_type: Optional[str],
    hndl_sensitive: Optional[bool],
    protected_lifetime_years: Optional[float],
    quantum_arrival_years: float,
) -> HNDLExposure:
    """
    Determine HNDL exposure tier for a CryptoAsset.

    HNDL analysis (Harvest Now, Decrypt Later) applies when:
      1. The asset uses a Shor-vulnerable algorithm (RSA, ECC, DH, ECDSA, ECDH).
      2. The protected data has meaningful longevity extending toward the quantum horizon.

    Non-Shor assets (Grover-impacted symmetric, PQC, Library, etc.) receive:
      - PQC: NONE
      - Grover symmetric/hash: lower tiers than Shor-equivalent assessment
      - Library/Unknown: UNKNOWN if quantum vulnerability unknown, or LOW if explicitly safe

    IMPORTANT: HNDL is NOT automatically assumed for all quantum-vulnerable assets.
    A Shor-vulnerable RSA asset protecting 1-day session tokens has materially different
    HNDL implications from RSA protecting 20-year government records.

    Args:
        quantum_vulnerable: From CryptoAsset classification. None means unknown.
        quantum_threat_type: From CryptoAsset (e.g., 'SHOR_POLYNOMIAL_BREAK').
        hndl_sensitive: Explicit flag from MoscaInput; overrides structural inference if set.
        protected_lifetime_years: X — years data must remain confidential.
        quantum_arrival_years: Z — assumed quantum horizon.

    Returns:
        HNDLExposure enum value.
    """
    # Unknown quantum vulnerability → cannot assess HNDL
    if quantum_vulnerable is None:
        return HNDLExposure.UNKNOWN

    # Explicitly quantum-safe → no HNDL risk
    if quantum_vulnerable is False:
        return HNDLExposure.NONE

    # At this point, asset is quantum-vulnerable (quantum_vulnerable = True)

    # Grover-impacted symmetric/hash: HNDL is limited because the attack degrades
    # rather than fully breaks security. Conservative classification is LOW unless
    # explicitly flagged HNDL-sensitive.
    is_shor = (quantum_threat_type == "SHOR_POLYNOMIAL_BREAK")
    is_grover = (quantum_threat_type == "GROVER_BIT_HALVING")

    if not is_shor and not is_grover:
        # Some other or unknown quantum threat type
        return HNDLExposure.UNKNOWN

    if is_grover:
        # Grover halves symmetric security — data is weakened but not fully exposed.
        # HNDL concern is structurally lower.
        if hndl_sensitive is True:
            return HNDLExposure.MEDIUM
        return HNDLExposure.LOW

    # --- Shor-vulnerable path ---
    # Check if protected lifetime is known
    if protected_lifetime_years is None:
        # Cannot assess HNDL without knowing how long data must be protected
        if hndl_sensitive is True:
            # Explicit sensitivity flag: treat as HIGH (conservative)
            return HNDLExposure.HIGH
        return HNDLExposure.UNKNOWN

    # Protect lifetime below meaningful HNDL threshold
    if protected_lifetime_years < HNDL_MINIMUM_MEANINGFUL_LIFETIME:
        return HNDLExposure.LOW

    # Compute difference: (protected_lifetime - quantum_horizon)
    # Positive → data must stay secret longer than quantum arrives → HIGH/CRITICAL
    # Negative → data expires before quantum arrives → LOW/MEDIUM
    diff = protected_lifetime_years - quantum_arrival_years

    if diff > HNDL_CRITICAL_BUFFER_YEARS:
        # Protected lifetime far exceeds quantum horizon
        if hndl_sensitive is True or hndl_sensitive is None:
            return HNDLExposure.CRITICAL
        return HNDLExposure.HIGH
    elif diff > HNDL_HIGH_MARGIN_YEARS:
        # Protected lifetime exceeds quantum horizon (even by small amount)
        return HNDLExposure.HIGH
    elif diff > HNDL_MEDIUM_THRESHOLD_YEARS:
        # Protected lifetime is near the quantum horizon (within MEDIUM_THRESHOLD years)
        return HNDLExposure.MEDIUM
    else:
        # Protected lifetime well below the quantum horizon
        return HNDLExposure.LOW


def classify_urgency(
    mosca_applicable: bool,
    quantum_vulnerable: Optional[bool],
    quantum_threat_type: Optional[str],
    inequality_triggered: Optional[bool],
    hndl_exposure: HNDLExposure,
    exposure_gap_years: Optional[float],
    z_quantum_arrival_years: Optional[float],
    y_migration_time_years: Optional[float],
) -> MoscaUrgency:
    """
    Determine migration urgency tier from the Mosca result and HNDL assessment.

    Urgency is derived INDEPENDENTLY from Risk Score (RULE-002, and the explicit
    requirement in the user specification §3 and §25). Risk and Mosca measure
    different dimensions:
      Risk = "How dangerous is this cryptographic state?"
      Urgency = "Does the migration window require immediate action?"

    Urgency Derivation Logic:
      NOT_REQUIRED : mosca_applicable is False (Library, Random, PQC)
      UNKNOWN      : insufficient inputs (inequality_triggered is None)
      IMMEDIATE    : inequality_triggered True + HNDL CRITICAL, or tight gap
      URGENT       : inequality_triggered True + HNDL HIGH/MEDIUM
      PLANNED      : inequality_triggered False but migration window is narrow
      MONITOR      : quantum_vulnerable but sufficient time remains

    Args:
        mosca_applicable: False for Library/Random/PQC — results in NOT_REQUIRED.
        quantum_vulnerable: From asset classification.
        quantum_threat_type: From asset classification.
        inequality_triggered: True/False/None.
        hndl_exposure: Determined HNDL tier.
        exposure_gap_years: The X+Y-Z gap (None if not computable).
        z_quantum_arrival_years: Used for PLANNED threshold calculation.
        y_migration_time_years: Used for PLANNED threshold calculation.

    Returns:
        MoscaUrgency enum value.
    """
    # Not applicable assets (Library, Random, NIST-PQC)
    if not mosca_applicable:
        return MoscaUrgency.NOT_REQUIRED

    # Insufficient data to determine urgency
    if inequality_triggered is None:
        return MoscaUrgency.UNKNOWN

    # Inequality triggered (X + Y > Z)
    if inequality_triggered:
        # IMMEDIATE when HNDL is CRITICAL, or gap is small/zero
        if hndl_exposure == HNDLExposure.CRITICAL:
            return MoscaUrgency.IMMEDIATE
        if exposure_gap_years is not None and exposure_gap_years <= URGENCY_URGENT_GAP_THRESHOLD:
            return MoscaUrgency.IMMEDIATE
        # URGENT for remaining triggered cases
        return MoscaUrgency.URGENT

    # Inequality NOT triggered (X + Y ≤ Z) but asset is quantum-vulnerable
    if quantum_vulnerable is True:
        # Check how narrow the migration buffer is
        if (
            z_quantum_arrival_years is not None
            and y_migration_time_years is not None
        ):
            buffer = z_quantum_arrival_years - y_migration_time_years
            if buffer <= URGENCY_PLANNED_BUFFER_THRESHOLD:
                # Narrow window: planned migration should start now
                return MoscaUrgency.PLANNED
        # HNDL HIGH even without inequality → PLANNED
        if hndl_exposure in (HNDLExposure.HIGH, HNDLExposure.CRITICAL):
            return MoscaUrgency.PLANNED
        # Sufficient buffer exists
        return MoscaUrgency.MONITOR

    # Asset is explicitly quantum-safe or not evaluated
    if quantum_vulnerable is False:
        return MoscaUrgency.NOT_REQUIRED

    # Unknown vulnerability with non-triggered inequality
    return MoscaUrgency.UNKNOWN
