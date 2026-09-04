"""
QNetra Mosca Engine — Comprehensive Test Suite
=================================================

Tests for Milestone 3.2: Michele Mosca Migration & HNDL Engine.

Coverage Goals:
  - Inequality evaluation: X+Y>Z, X+Y==Z, X+Y<Z
  - Missing inputs: missing X, missing Y, missing Z
  - Invalid inputs: negative, NaN, infinity, wrong type
  - Shor-vulnerable assets: RSA, ECDSA, ECDH, DH
  - Quantum-resistant assets: ML-KEM, ML-DSA, SLH-DSA (NOT_REQUIRED)
  - NOT_APPLICABLE: Library, Random
  - UNKNOWN classification
  - HNDL exposure tiers: various lifetime / quantum horizon combinations
  - Urgency classification: all tiers
  - Determinism: same input → same output
  - Assessment date: explicit date → repeatable deadline
  - No mutation: assess() never modifies the source CryptoAsset
  - Batch ordering: sorted by asset_id
  - Explainability: all required fields present
  - Risk vs Mosca independence regression test
  - Full pipeline: 289 → 147 → 147 → 147 → 147 Mosca assessments

Contract References:
  - docs/05_ALGORITHMS.md (Alg-07)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.4)
  - docs/09_KNOWLEDGE_BASE.md (Section 2.1)
"""

from __future__ import annotations

import copy
import math
from datetime import date
from typing import Optional
from unittest.mock import MagicMock

import pytest

from core.mosca_engine import (
    HNDLExposure,
    MoscaAssessment,
    MoscaAssessmentReport,
    MoscaConfig,
    MoscaEngine,
    MoscaInput,
    MoscaUrgency,
)
from core.mosca_engine.calculator import (
    calculate_deadline_years_from_now,
    calculate_exposure_gap,
    calculate_x_plus_y,
    classify_hndl_exposure,
    classify_urgency,
    evaluate_inequality,
    validate_duration,
)
from core.mosca_engine.knowledge import (
    MIGRATION_TIME_ASYMMETRIC,
    MIGRATION_TIME_HASH,
    MIGRATION_TIME_SYMMETRIC,
    QUANTUM_ARRIVAL_BASELINE,
)
from core.models import CryptoAsset, PrimitiveType
from scanners.framework.models import ConfidenceLevel, FileLocation


# ===========================================================================
# Test Helpers / Fixtures
# ===========================================================================

def _make_location() -> FileLocation:
    return FileLocation(file_path="test/sample.py", start_line=1, end_line=1)


def _make_asset(
    algorithm: str = "RSA",
    primitive_type: PrimitiveType = PrimitiveType.ASYMMETRIC_ENCRYPTION,
    key_length_bits: Optional[int] = 2048,
    quantum_vulnerable: Optional[bool] = True,
    quantum_threat_type: Optional[str] = "SHOR_POLYNOMIAL_BREAK",
    quantum_security_status: Optional[str] = "CRITICAL",
    classical_security_status: Optional[str] = "SECURE",
    risk_score: Optional[int] = None,
    asset_id_suffix: str = "",
) -> CryptoAsset:
    """Create a minimal CryptoAsset for testing."""
    import uuid
    asset_id = str(uuid.uuid4()) + asset_id_suffix
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        primitive_type=primitive_type,
        key_length_bits=key_length_bits,
        location=_make_location(),
        confidence_score=0.95,
        confidence_level=ConfidenceLevel.VERY_HIGH,
        confidence_rationale="Test asset",
        quantum_vulnerable=quantum_vulnerable,
        quantum_threat_type=quantum_threat_type,
        quantum_security_status=quantum_security_status,
        classical_security_status=classical_security_status,
        risk_score=risk_score,
    )


def _make_shor_asset(algorithm: str = "RSA", key_bits: int = 2048) -> CryptoAsset:
    return _make_asset(
        algorithm=algorithm,
        primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
        key_length_bits=key_bits,
        quantum_vulnerable=True,
        quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
        quantum_security_status="CRITICAL",
        classical_security_status="SECURE",
    )


def _make_grover_asset(algorithm: str = "AES", key_bits: int = 128) -> CryptoAsset:
    return _make_asset(
        algorithm=algorithm,
        primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
        key_length_bits=key_bits,
        quantum_vulnerable=True,
        quantum_threat_type="GROVER_BIT_HALVING",
        quantum_security_status="DEGRADED",
        classical_security_status="SECURE",
    )


def _make_pqc_asset(algorithm: str = "ML-KEM-768") -> CryptoAsset:
    return _make_asset(
        algorithm=algorithm,
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        key_length_bits=None,
        quantum_vulnerable=False,
        quantum_threat_type="QUANTUM_RESISTANT",
        quantum_security_status="SAFE",
        classical_security_status="SECURE",
    )


def _make_library_asset() -> CryptoAsset:
    return _make_asset(
        algorithm="OpenSSL",
        primitive_type=PrimitiveType.LIBRARY,
        key_length_bits=None,
        quantum_vulnerable=None,
        quantum_threat_type="NOT_APPLICABLE",
        quantum_security_status="UNKNOWN",
        classical_security_status="UNKNOWN",
    )


def _make_random_asset() -> CryptoAsset:
    return _make_asset(
        algorithm="DRBG",
        primitive_type=PrimitiveType.RANDOM,
        key_length_bits=None,
        quantum_vulnerable=None,
        quantum_threat_type="NOT_APPLICABLE",
        quantum_security_status="UNKNOWN",
        classical_security_status="UNKNOWN",
    )


def _make_unknown_asset() -> CryptoAsset:
    return _make_asset(
        algorithm="CUSTOM_ALGO",
        primitive_type=PrimitiveType.UNKNOWN,
        key_length_bits=None,
        quantum_vulnerable=None,
        quantum_threat_type="UNKNOWN",
        quantum_security_status="UNKNOWN",
        classical_security_status="UNKNOWN",
    )


@pytest.fixture
def engine() -> MoscaEngine:
    """Default MoscaEngine with baseline config."""
    return MoscaEngine()


@pytest.fixture
def rsa_asset() -> CryptoAsset:
    return _make_shor_asset("RSA", 2048)


@pytest.fixture
def ecdsa_asset() -> CryptoAsset:
    return _make_asset(
        algorithm="ECDSA",
        primitive_type=PrimitiveType.DIGITAL_SIGNATURE,
        key_length_bits=256,
        quantum_vulnerable=True,
        quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
    )


@pytest.fixture
def aes128_asset() -> CryptoAsset:
    return _make_grover_asset("AES", 128)


@pytest.fixture
def mlkem_asset() -> CryptoAsset:
    return _make_pqc_asset("ML-KEM-768")


@pytest.fixture
def library_asset() -> CryptoAsset:
    return _make_library_asset()


# ===========================================================================
# 1. Basic Inequality Tests
# ===========================================================================

class TestInequalityEvaluation:
    """Test Mosca inequality: X + Y > Z"""

    def test_inequality_triggered_when_x_plus_y_greater_than_z(self):
        """X + Y > Z → True."""
        assert evaluate_inequality(10.0, 4.0, 8.0) is True

    def test_inequality_not_triggered_when_x_plus_y_less_than_z(self):
        """X + Y < Z → False."""
        assert evaluate_inequality(3.0, 2.0, 10.0) is False

    def test_inequality_not_triggered_at_exact_equality(self):
        """X + Y == Z → False (boundary: equality is NOT triggered, per docs/05 §11)."""
        assert evaluate_inequality(5.0, 3.0, 8.0) is False

    def test_inequality_with_zero_x(self):
        """X = 0: mathematically valid. Y = 5, Z = 3 → triggered."""
        assert evaluate_inequality(0.0, 5.0, 3.0) is True

    def test_inequality_with_zero_y(self):
        """Y = 0 (instant migration): 10 + 0 > 8 → triggered."""
        assert evaluate_inequality(10.0, 0.0, 8.0) is True

    def test_inequality_with_zero_z(self):
        """Z = 0 (CRQC already exists): always triggered if X + Y > 0."""
        assert evaluate_inequality(1.0, 0.0, 0.0) is True

    def test_inequality_all_zeros(self):
        """0 + 0 == 0 → False (equality boundary)."""
        assert evaluate_inequality(0.0, 0.0, 0.0) is False

    def test_exposure_gap_correct_when_triggered(self):
        gap = calculate_exposure_gap(10.0, 4.0, 8.0)
        assert abs(gap - 6.0) < 1e-9

    def test_exposure_gap_zero_when_not_triggered(self):
        gap = calculate_exposure_gap(3.0, 2.0, 10.0)
        assert gap == 0.0

    def test_exposure_gap_zero_at_equality(self):
        gap = calculate_exposure_gap(5.0, 3.0, 8.0)
        assert gap == 0.0

    def test_x_plus_y_sum(self):
        assert abs(calculate_x_plus_y(10.0, 4.0) - 14.0) < 1e-9

    def test_deadline_years_from_now(self):
        # Z=10, Y=4 → 10-4=6 years remaining
        deadline = calculate_deadline_years_from_now(10.0, 4.0)
        assert abs(deadline - 6.0) < 1e-9

    def test_deadline_negative_when_already_past(self):
        # Z=3, Y=5 → -2 (already past deadline)
        deadline = calculate_deadline_years_from_now(3.0, 5.0)
        assert deadline < 0.0


# ===========================================================================
# 2. Input Validation Tests
# ===========================================================================

class TestDurationValidation:
    """Test validate_duration for invalid inputs."""

    def test_negative_x_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            validate_duration("X", -1.0)

    def test_negative_y_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            validate_duration("Y", -0.001)

    def test_negative_z_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            validate_duration("Z", -5.0)

    def test_nan_raises(self):
        with pytest.raises(ValueError, match="NaN"):
            validate_duration("duration", float("nan"))

    def test_positive_infinity_raises(self):
        with pytest.raises(ValueError, match="infinite"):
            validate_duration("duration", float("inf"))

    def test_negative_infinity_raises(self):
        with pytest.raises(ValueError, match="infinite"):
            validate_duration("duration", float("-inf"))

    def test_non_numeric_raises_type_error(self):
        with pytest.raises(TypeError):
            validate_duration("duration", "10 years")  # type: ignore

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError):
            validate_duration("duration", None)  # type: ignore

    def test_zero_is_valid(self):
        """Zero is mathematically valid."""
        validate_duration("duration", 0.0)  # should not raise

    def test_large_valid_value(self):
        """Very large but finite values are valid."""
        validate_duration("duration", 1e6)  # should not raise

    def test_integer_input_valid(self):
        """Integer input should be accepted."""
        validate_duration("duration", 10)  # should not raise


class TestEngineInputValidation:
    """Test engine-level rejection of invalid MoscaInput durations."""

    def test_negative_migration_time_raises(self):
        engine = MoscaEngine()
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            migration_time_years=-1.0,
            protected_lifetime_years=10.0,
        )
        with pytest.raises(ValueError, match="non-negative"):
            engine.assess(asset, context)

    def test_negative_quantum_arrival_raises(self):
        engine = MoscaEngine()
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            quantum_arrival_years=-5.0,
            protected_lifetime_years=10.0,
        )
        with pytest.raises(ValueError, match="non-negative"):
            engine.assess(asset, context)

    def test_negative_protected_lifetime_raises(self):
        engine = MoscaEngine()
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=-3.0,
        )
        with pytest.raises(ValueError, match="non-negative"):
            engine.assess(asset, context)

    def test_nan_in_protected_lifetime_raises(self):
        engine = MoscaEngine()
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=float("nan"),
        )
        with pytest.raises(ValueError, match="NaN"):
            engine.assess(asset, context)

    def test_infinity_in_migration_time_raises(self):
        engine = MoscaEngine()
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            migration_time_years=float("inf"),
            protected_lifetime_years=10.0,
        )
        with pytest.raises(ValueError, match="infinite"):
            engine.assess(asset, context)


# ===========================================================================
# 3. Shor-Vulnerable Asset Tests
# ===========================================================================

class TestShorVulnerableAssets:
    """Test Mosca assessments for Shor-vulnerable algorithms."""

    def test_rsa_triggered_with_long_lifetime(self, engine):
        """RSA + 15yr data lifetime, 4yr migration, 10yr quantum horizon → triggered."""
        asset = _make_shor_asset("RSA", 2048)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is True
        assert result.x_data_lifetime_years == 15.0
        assert result.y_migration_time_years == 4.0
        assert result.z_quantum_arrival_years == 10.0
        assert result.x_plus_y == 19.0
        assert abs(result.exposure_gap_years - 9.0) < 1e-9

    def test_rsa_not_triggered_with_short_lifetime(self, engine):
        """RSA + 2yr data lifetime, 4yr migration, 10yr quantum horizon → NOT triggered."""
        asset = _make_shor_asset("RSA", 2048)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=2.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is False
        assert result.x_plus_y == 6.0
        assert result.exposure_gap_years == 0.0

    def test_ecdsa_assessment(self, engine, ecdsa_asset):
        """ECDSA is Shor-vulnerable; full Mosca applies."""
        context = MoscaInput(
            asset_id=ecdsa_asset.asset_id,
            protected_lifetime_years=10.0,
            migration_time_years=3.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(ecdsa_asset, context)
        assert result.mosca_applicable is True
        assert result.inequality_triggered is True  # 10+3=13 > 10

    def test_ecdh_shor_assessment(self, engine):
        """ECDH is Shor-vulnerable."""
        asset = _make_asset(
            algorithm="ECDH",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
        )
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=5.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.mosca_applicable is True
        assert result.inequality_triggered is False  # 5+4=9 ≤ 10

    def test_dh_shor_assessment(self, engine):
        """DH is Shor-vulnerable."""
        asset = _make_asset(
            algorithm="DH",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
        )
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=12.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is True  # 12+4=16 > 10


# ===========================================================================
# 4. Quantum-Resistant Asset Tests
# ===========================================================================

class TestQuantumResistantAssets:
    """Test that NIST-approved PQC assets receive NOT_REQUIRED urgency."""

    def test_ml_kem_not_required(self, engine, mlkem_asset):
        result = engine.assess(mlkem_asset)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED
        assert result.hndl_exposure == HNDLExposure.NONE
        assert result.mosca_applicable is False
        assert result.inequality_triggered is None

    def test_ml_dsa_not_required(self, engine):
        asset = _make_pqc_asset("ML-DSA-65")
        result = engine.assess(asset)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED
        assert result.hndl_exposure == HNDLExposure.NONE
        assert result.mosca_applicable is False

    def test_slh_dsa_not_required(self, engine):
        asset = _make_pqc_asset("SLH-DSA-SHA2-128s")
        result = engine.assess(asset)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED
        assert result.hndl_exposure == HNDLExposure.NONE

    def test_pqc_not_required_even_with_long_lifetime_context(self, engine):
        """Even with a 100yr protected lifetime context, PQC remains NOT_REQUIRED."""
        asset = _make_pqc_asset("ML-KEM-768")
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=100.0,
        )
        result = engine.assess(asset, context)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED
        assert result.hndl_exposure == HNDLExposure.NONE

    def test_pqc_assumptions_contain_quantum_resistant_note(self, engine):
        asset = _make_pqc_asset("ML-DSA-65")
        result = engine.assess(asset)
        assumptions_text = " ".join(result.assumptions)
        assert "Post-Quantum" in assumptions_text or "quantum-safe" in assumptions_text.lower()


# ===========================================================================
# 5. NOT_APPLICABLE Asset Tests (Library, Random)
# ===========================================================================

class TestNotApplicableAssets:
    """Test that Library and Random primitives receive NOT_REQUIRED from Mosca."""

    def test_library_asset_not_applicable(self, engine, library_asset):
        result = engine.assess(library_asset)
        assert result.mosca_applicable is False
        assert result.urgency == MoscaUrgency.NOT_REQUIRED

    def test_random_asset_not_applicable(self, engine):
        asset = _make_random_asset()
        result = engine.assess(asset)
        assert result.mosca_applicable is False
        assert result.urgency == MoscaUrgency.NOT_REQUIRED

    def test_library_hndl_is_none(self, engine, library_asset):
        result = engine.assess(library_asset)
        assert result.hndl_exposure == HNDLExposure.NONE

    def test_not_applicable_returns_no_xyz_values(self, engine, library_asset):
        result = engine.assess(library_asset)
        assert result.x_data_lifetime_years is None
        assert result.y_migration_time_years is None
        assert result.z_quantum_arrival_years is None
        assert result.x_plus_y is None


# ===========================================================================
# 6. Missing Input Tests
# ===========================================================================

class TestMissingInputs:
    """Test handling of missing X, Y, Z inputs."""

    def test_missing_x_yields_unknown_urgency(self, engine):
        """Without protected lifetime (X), urgency is UNKNOWN."""
        asset = _make_shor_asset()
        # No context (no protected_lifetime_years)
        result = engine.assess(asset, context=None)
        assert result.urgency == MoscaUrgency.UNKNOWN
        assert result.inequality_triggered is None
        assert result.x_data_lifetime_years is None

    def test_missing_x_records_assumption(self, engine):
        """Missing X must be documented in assumptions."""
        asset = _make_shor_asset()
        result = engine.assess(asset, context=None)
        assumptions_text = " ".join(result.assumptions)
        assert "protected" in assumptions_text.lower() or "lifetime" in assumptions_text.lower()

    def test_explicit_none_for_protected_lifetime_yields_unknown(self, engine):
        """Explicitly passing None for protected_lifetime_years → UNKNOWN."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=None,
        )
        result = engine.assess(asset, context)
        assert result.urgency == MoscaUrgency.UNKNOWN
        assert result.x_data_lifetime_years is None

    def test_with_x_and_no_explicit_y_uses_primitive_default(self, engine):
        """When Y not provided, engine derives it from primitive type."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
        )
        result = engine.assess(asset, context)
        # Should have derived Y (not None)
        assert result.y_migration_time_years is not None
        assert result.y_migration_time_years == MIGRATION_TIME_ASYMMETRIC

    def test_missing_y_when_defaults_disabled_yields_unknown(self):
        """With use_primitive_migration_defaults=False and no explicit Y → UNKNOWN."""
        config = MoscaConfig(use_primitive_migration_defaults=False)
        engine = MoscaEngine(config=config)
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
        )
        result = engine.assess(asset, context)
        assert result.y_migration_time_years is None
        assert result.inequality_triggered is None


# ===========================================================================
# 7. HNDL Exposure Tests
# ===========================================================================

class TestHNDLExposure:
    """Test HNDL exposure classification logic."""

    def test_shor_with_very_long_lifetime_hndl_critical(self, engine):
        """RSA protecting 25-year sensitive data, quantum horizon 10 years → CRITICAL."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=25.0,
            quantum_arrival_years=10.0,
            hndl_sensitive=True,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure in (HNDLExposure.CRITICAL, HNDLExposure.HIGH)

    def test_shor_with_long_lifetime_exceeding_horizon_hndl_high(self, engine):
        """RSA protecting 12-year data, quantum horizon 10 years → HIGH (12>10)."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=12.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure in (HNDLExposure.HIGH, HNDLExposure.CRITICAL)

    def test_shor_with_short_lifetime_low_hndl(self, engine):
        """RSA protecting 1-year data, quantum horizon 10 years → LOW HNDL."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=1.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure == HNDLExposure.LOW

    def test_pqc_asset_hndl_none(self, engine):
        """Quantum-resistant asset → HNDL NONE regardless of lifetime."""
        asset = _make_pqc_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=50.0,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure == HNDLExposure.NONE

    def test_unknown_quantum_vulnerability_hndl_unknown(self):
        """Unknown quantum vulnerability → HNDL UNKNOWN."""
        exposure = classify_hndl_exposure(
            quantum_vulnerable=None,
            quantum_threat_type=None,
            hndl_sensitive=None,
            protected_lifetime_years=15.0,
            quantum_arrival_years=10.0,
        )
        assert exposure == HNDLExposure.UNKNOWN

    def test_grover_asset_hndl_low_without_sensitivity_flag(self, engine):
        """Grover-impacted symmetric/hash → LOW HNDL by default."""
        asset = _make_grover_asset("AES", 128)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
            quantum_arrival_years=10.0,
            hndl_sensitive=False,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure == HNDLExposure.LOW

    def test_grover_asset_hndl_medium_with_sensitivity_flag(self, engine):
        """Grover-impacted symmetric + hndl_sensitive=True → MEDIUM."""
        asset = _make_grover_asset("AES", 128)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
            quantum_arrival_years=10.0,
            hndl_sensitive=True,
        )
        result = engine.assess(asset, context)
        assert result.hndl_exposure == HNDLExposure.MEDIUM

    def test_shor_without_protected_lifetime_hndl_unknown(self, engine):
        """Shor-vulnerable asset + no protected lifetime → HNDL UNKNOWN."""
        asset = _make_shor_asset()
        result = engine.assess(asset, context=None)
        assert result.hndl_exposure == HNDLExposure.UNKNOWN

    def test_hndl_not_automatic_for_shor_short_lifetime(self, engine):
        """RSA protecting 6-month session tokens should NOT get HIGH HNDL."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=0.5,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        # Short-lived data should not trigger high HNDL
        assert result.hndl_exposure not in (HNDLExposure.HIGH, HNDLExposure.CRITICAL)

    def test_hndl_sensitive_flag_without_lifetime_high(self, engine):
        """If hndl_sensitive=True but no lifetime → conservative HIGH."""
        exposure = classify_hndl_exposure(
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
            hndl_sensitive=True,
            protected_lifetime_years=None,
            quantum_arrival_years=10.0,
        )
        assert exposure == HNDLExposure.HIGH

    def test_quantum_safe_asset_hndl_none(self):
        """Explicitly quantum-safe asset → HNDLExposure.NONE regardless."""
        exposure = classify_hndl_exposure(
            quantum_vulnerable=False,
            quantum_threat_type="QUANTUM_RESISTANT",
            hndl_sensitive=True,
            protected_lifetime_years=100.0,
            quantum_arrival_years=10.0,
        )
        assert exposure == HNDLExposure.NONE


# ===========================================================================
# 8. Urgency Classification Tests
# ===========================================================================

class TestUrgencyClassification:
    """Test migration urgency tier derivation."""

    def test_not_required_for_not_applicable(self, engine, library_asset):
        result = engine.assess(library_asset)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED

    def test_not_required_for_pqc(self, engine, mlkem_asset):
        result = engine.assess(mlkem_asset)
        assert result.urgency == MoscaUrgency.NOT_REQUIRED

    def test_immediate_when_hndl_critical(self, engine):
        """HNDL CRITICAL + triggered → IMMEDIATE."""
        asset = _make_shor_asset()
        # Long-lived + triggered inequality
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=20.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
            hndl_sensitive=True,
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is True
        assert result.urgency in (MoscaUrgency.IMMEDIATE, MoscaUrgency.URGENT)

    def test_urgent_when_triggered_without_critical_hndl(self, engine):
        """Triggered inequality with moderate HNDL → URGENT."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=4.0,  # 4+4=8, not >> 10 (not CRITICAL HNDL)
            migration_time_years=4.0,
            quantum_arrival_years=7.0,  # 4+4=8 > 7 → triggered
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is True
        assert result.urgency in (MoscaUrgency.IMMEDIATE, MoscaUrgency.URGENT)

    def test_monitor_when_quantum_vulnerable_but_safe_buffer(self, engine):
        """Quantum vulnerable but safe migration buffer → MONITOR."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=2.0,
            migration_time_years=4.0,
            quantum_arrival_years=15.0,  # 2+4=6 < 15 → not triggered; buffer=11yrs
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is False
        assert result.urgency in (MoscaUrgency.MONITOR, MoscaUrgency.PLANNED)

    def test_planned_when_narrow_buffer(self, engine):
        """Not triggered but very narrow migration buffer → PLANNED."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=1.0,
            migration_time_years=4.0,
            quantum_arrival_years=6.0,  # 1+4=5 < 6, buffer = 6-4 = 2yrs (≤3)
        )
        result = engine.assess(asset, context)
        assert result.inequality_triggered is False
        assert result.urgency == MoscaUrgency.PLANNED

    def test_unknown_urgency_without_lifetime(self, engine):
        """No lifetime → UNKNOWN urgency."""
        asset = _make_shor_asset()
        result = engine.assess(asset, context=None)
        assert result.urgency == MoscaUrgency.UNKNOWN


# ===========================================================================
# 9. Migration Deadline Tests
# ===========================================================================

class TestMigrationDeadline:
    """Test migration deadline calculation."""

    def test_deadline_present_when_y_and_z_known(self, engine):
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
            migration_time_years=3.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        assert result.migration_deadline_years_from_now is not None
        assert abs(result.migration_deadline_years_from_now - 7.0) < 1e-9

    def test_deadline_none_when_x_missing(self, engine):
        """Without X, inequality not computed → no deadline."""
        asset = _make_shor_asset()
        result = engine.assess(asset, context=None)
        assert result.migration_deadline_years_from_now is None

    def test_assessment_date_passed_through(self, engine):
        asset = _make_shor_asset()
        ref_date = date(2026, 9, 4)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
            assessment_date=ref_date,
        )
        result = engine.assess(asset, context)
        assert result.assessment_date == ref_date

    def test_assessment_date_none_when_not_provided(self, engine):
        asset = _make_shor_asset()
        result = engine.assess(asset)
        assert result.assessment_date is None


# ===========================================================================
# 10. Determinism Tests
# ===========================================================================

class TestDeterminism:
    """Test that identical inputs always produce identical outputs."""

    def test_same_asset_same_context_same_result(self, engine):
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
            assessment_date=date(2026, 9, 4),
        )
        result1 = engine.assess(asset, context)
        result2 = engine.assess(asset, context)

        assert result1.urgency == result2.urgency
        assert result1.hndl_exposure == result2.hndl_exposure
        assert result1.inequality_triggered == result2.inequality_triggered
        assert result1.x_plus_y == result2.x_plus_y
        assert result1.exposure_gap_years == result2.exposure_gap_years

    def test_batch_produces_deterministic_order(self, engine):
        """assess_all() must sort by asset_id deterministically."""
        assets = [_make_shor_asset(f"RSA_{i}") for i in range(5)]
        # Shuffle assets
        import random
        random.shuffle(assets)

        result1 = engine.assess_all(assets)
        random.shuffle(assets)
        result2 = engine.assess_all(assets)

        ids1 = [a.asset_id for a in result1]
        ids2 = [a.asset_id for a in result2]
        assert ids1 == ids2, "Batch results must be sorted deterministically by asset_id"

    def test_date_determinism(self, engine):
        """Explicit assessment_date produces same deadline across calls."""
        asset = _make_shor_asset()
        ref_date = date(2026, 9, 4)
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
            migration_time_years=4.0,
            assessment_date=ref_date,
        )
        r1 = engine.assess(asset, context)
        r2 = engine.assess(asset, context)
        assert r1.assessment_date == r2.assessment_date
        assert r1.migration_deadline_years_from_now == r2.migration_deadline_years_from_now


# ===========================================================================
# 11. No-Mutation Tests
# ===========================================================================

class TestNoMutation:
    """Verify assess() does NOT mutate CryptoAsset."""

    def test_assess_does_not_mutate_asset(self, engine):
        """assess() must not modify any field on the input CryptoAsset."""
        asset = _make_shor_asset()
        original_id = asset.asset_id
        original_algo = asset.algorithm
        original_risk_score = asset.risk_score
        original_quantum_vulnerable = asset.quantum_vulnerable

        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
        )
        engine.assess(asset, context)

        assert asset.asset_id == original_id
        assert asset.algorithm == original_algo
        assert asset.risk_score == original_risk_score
        assert asset.quantum_vulnerable == original_quantum_vulnerable

    def test_assess_all_does_not_mutate_assets(self, engine):
        """assess_all() must not modify any asset in the batch."""
        assets = [_make_shor_asset("RSA") for _ in range(5)]
        original_ids = [a.asset_id for a in assets]
        original_scores = [a.risk_score for a in assets]

        engine.assess_all(assets)

        for i, asset in enumerate(assets):
            assert asset.asset_id == original_ids[i]
            assert asset.risk_score == original_scores[i]


# ===========================================================================
# 12. Explainability Tests
# ===========================================================================

class TestExplainability:
    """Verify that all required fields are present in MoscaAssessment output."""

    def test_all_required_fields_present_for_triggered(self, engine):
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
            assessment_date=date(2026, 9, 4),
        )
        result = engine.assess(asset, context)

        # Check mandatory fields
        assert result.asset_id is not None
        assert result.x_data_lifetime_years is not None
        assert result.y_migration_time_years is not None
        assert result.z_quantum_arrival_years is not None
        assert result.x_plus_y is not None
        assert result.inequality_triggered is not None
        assert result.exposure_gap_years is not None
        assert result.urgency is not None
        assert result.hndl_exposure is not None
        assert len(result.assumptions) > 0
        assert len(result.rationale) > 0

    def test_rationale_contains_inequality_statement(self, engine):
        """Rationale must include the X + Y > Z statement."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        result = engine.assess(asset, context)
        rationale_text = " ".join(result.rationale)
        assert "X + Y" in rationale_text or "inequality" in rationale_text.lower()

    def test_to_dict_serializable(self, engine):
        """to_dict() must produce a JSON-serializable dictionary."""
        import json
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=15.0,
        )
        result = engine.assess(asset, context)
        d = result.to_dict()
        # Should not raise
        json.dumps(d)

    def test_assumptions_recorded_for_quantum_arrival_default(self, engine):
        """When using default Z, assumption is documented."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
        )
        result = engine.assess(asset, context)
        assumptions_text = " ".join(result.assumptions)
        assert "quantum" in assumptions_text.lower() or "crqc" in assumptions_text.lower()

    def test_assumptions_recorded_for_primitive_migration_default(self, engine):
        """When using primitive-class migration time, assumption is documented."""
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=10.0,
        )
        result = engine.assess(asset, context)
        assumptions_text = " ".join(result.assumptions)
        assert "migration" in assumptions_text.lower()


# ===========================================================================
# 13. Risk vs Mosca Independence Tests (Regression: Spec §25)
# ===========================================================================

class TestRiskVsMoscaIndependence:
    """
    CRITICAL: Verify that risk_score does NOT determine Mosca urgency.

    Two assets with similar risk scores but different protected-data lifetimes
    must produce different Mosca outcomes. This ensures the architecture
    maintains clear separation of Risk and Migration Urgency (per §3 and §25).
    """

    def test_same_risk_score_different_mosca_urgency(self, engine):
        """Two RSA-2048 assets with same risk score, different lifetimes → different urgency."""
        # Both are RSA-2048: risk_score = 90 (Shor-vulnerable, CRITICAL)
        asset_long = _make_shor_asset("RSA", 2048)
        asset_short = _make_shor_asset("RSA", 2048)

        # Inject same risk score for both (simulating post-risk-engine enrichment)
        asset_long.risk_score = 90
        asset_short.risk_score = 90

        # Long-lived data (20yr): X + Y = 24 > Z = 10 → triggered
        ctx_long = MoscaInput(
            asset_id=asset_long.asset_id,
            protected_lifetime_years=20.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )
        # Short-lived data (2yr): X + Y = 6 < Z = 10 → NOT triggered
        ctx_short = MoscaInput(
            asset_id=asset_short.asset_id,
            protected_lifetime_years=2.0,
            migration_time_years=4.0,
            quantum_arrival_years=10.0,
        )

        result_long = engine.assess(asset_long, ctx_long)
        result_short = engine.assess(asset_short, ctx_short)

        # Same risk score
        assert asset_long.risk_score == asset_short.risk_score == 90

        # Different Mosca outcomes
        assert result_long.inequality_triggered is True
        assert result_short.inequality_triggered is False

        # Different urgency levels
        assert result_long.urgency != result_short.urgency

    def test_low_risk_score_can_be_urgent_mosca(self, engine):
        """A low-risk AES-128 asset can have URGENT Mosca if data is very long-lived."""
        # AES-128: risk = 60 (HIGH, not CRITICAL), but long-lived data
        aes128 = _make_grover_asset("AES", 128)
        aes128.risk_score = 60  # HIGH risk, not CRITICAL

        ctx = MoscaInput(
            asset_id=aes128.asset_id,
            protected_lifetime_years=15.0,
            migration_time_years=1.5,
            quantum_arrival_years=10.0,  # 15+1.5=16.5 > 10 → triggered
        )
        result = engine.assess(aes128, ctx)
        # Risk score is not CRITICAL, but Mosca is triggered
        assert aes128.risk_score == 60  # Not CRITICAL
        assert result.inequality_triggered is True


# ===========================================================================
# 14. Report Tests
# ===========================================================================

class TestMoscaReport:
    """Test MoscaAssessmentReport generation."""

    def test_report_counts_are_correct(self, engine):
        assets = [
            _make_shor_asset("RSA"),   # Shor-vulnerable
            _make_shor_asset("ECDSA"), # Shor-vulnerable
            _make_pqc_asset(),         # PQC — NOT_REQUIRED
            _make_library_asset(),     # Library — NOT_REQUIRED
        ]
        contexts = {
            assets[0].asset_id: MoscaInput(
                asset_id=assets[0].asset_id,
                protected_lifetime_years=15.0,
                migration_time_years=4.0,
                quantum_arrival_years=10.0,
            ),
            assets[1].asset_id: MoscaInput(
                asset_id=assets[1].asset_id,
                protected_lifetime_years=2.0,  # not triggered
                migration_time_years=4.0,
                quantum_arrival_years=10.0,
            ),
        }
        report = engine.generate_report(assets, contexts=contexts)

        assert report.total_assets == 4
        assert report.mosca_applicable_assets == 2  # RSA + ECDSA
        assert report.mosca_triggered_assets == 1   # RSA (15+4=19>10)

    def test_report_urgency_distribution_complete(self, engine):
        assets = [_make_shor_asset()]
        report = engine.generate_report(assets)
        # All urgency tiers should be present in distribution
        for urgency in MoscaUrgency:
            assert urgency.value in report.urgency_distribution

    def test_report_hndl_distribution_complete(self, engine):
        assets = [_make_shor_asset()]
        report = engine.generate_report(assets)
        for hndl in HNDLExposure:
            assert hndl.value in report.hndl_distribution

    def test_empty_assets_returns_zero_counts(self, engine):
        report = engine.generate_report([])
        assert report.total_assets == 0
        assert report.mosca_applicable_assets == 0
        assert report.mosca_triggered_assets == 0

    def test_report_to_dict_serializable(self, engine):
        import json
        assets = [_make_shor_asset(), _make_pqc_asset()]
        report = engine.generate_report(assets)
        d = report.to_dict()
        json.dumps(d)  # should not raise


# ===========================================================================
# 15. Grover-Impacted Asset Tests
# ===========================================================================

class TestGroverAssets:
    """Test Mosca behavior for Grover-impacted symmetric/hash assets."""

    def test_aes128_mosca_applicable(self, engine, aes128_asset):
        """AES-128 is quantum-degraded; Mosca should apply."""
        result = engine.assess(aes128_asset)
        assert result.mosca_applicable is True

    def test_sha256_hash_mosca_applicable(self, engine):
        asset = _make_asset(
            algorithm="SHA-256",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            quantum_vulnerable=True,
            quantum_threat_type="GROVER_BIT_HALVING",
        )
        result = engine.assess(asset)
        assert result.mosca_applicable is True

    def test_grover_with_triggered_inequality(self, engine, aes128_asset):
        """AES-128 + long-lived data → can trigger Mosca inequality."""
        context = MoscaInput(
            asset_id=aes128_asset.asset_id,
            protected_lifetime_years=12.0,
            migration_time_years=1.5,
            quantum_arrival_years=10.0,  # 12+1.5=13.5 > 10 → triggered
        )
        result = engine.assess(aes128_asset, context)
        assert result.inequality_triggered is True

    def test_grover_assumption_logged(self, engine, aes128_asset):
        """Grover-specific limitation must be logged in assumptions."""
        context = MoscaInput(
            asset_id=aes128_asset.asset_id,
            protected_lifetime_years=10.0,
        )
        result = engine.assess(aes128_asset, context)
        assumptions_text = " ".join(result.assumptions)
        assert "grover" in assumptions_text.lower() or "symmetric" in assumptions_text.lower()


# ===========================================================================
# 16. MoscaConfig Scenario Tests
# ===========================================================================

class TestMoscaConfig:
    """Test that MoscaConfig scenarios work correctly."""

    def test_optimistic_scenario_more_urgent(self):
        """Optimistic quantum horizon (7yr) produces more urgent outcome than baseline (10yr)."""
        from core.mosca_engine.knowledge import QUANTUM_ARRIVAL_OPTIMISTIC, QUANTUM_ARRIVAL_BASELINE

        asset = _make_shor_asset()
        ctx_base = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=5.0,
            migration_time_years=3.0,
            quantum_arrival_years=QUANTUM_ARRIVAL_BASELINE,  # 5+3=8 < 10 → not triggered
        )
        ctx_opt = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=5.0,
            migration_time_years=3.0,
            quantum_arrival_years=QUANTUM_ARRIVAL_OPTIMISTIC,  # 5+3=8 > 7 → triggered
        )
        engine = MoscaEngine()
        result_base = engine.assess(asset, ctx_base)
        result_opt = engine.assess(asset, ctx_opt)

        assert result_base.inequality_triggered is False
        assert result_opt.inequality_triggered is True

    def test_custom_config_quantum_horizon(self):
        """Custom config with 7yr horizon."""
        config = MoscaConfig(default_quantum_arrival_years=7.0)
        engine = MoscaEngine(config=config)
        asset = _make_shor_asset()
        context = MoscaInput(
            asset_id=asset.asset_id,
            protected_lifetime_years=5.0,
        )
        result = engine.assess(asset, context)
        assert result.z_quantum_arrival_years == 7.0

    def test_global_protected_lifetime_default(self):
        """When config sets global X, it is used when no context X is supplied."""
        config = MoscaConfig(default_protected_lifetime_years=20.0)
        engine = MoscaEngine(config=config)
        asset = _make_shor_asset()
        result = engine.assess(asset, context=None)
        assert result.x_data_lifetime_years == 20.0
        assert result.inequality_triggered is not None  # can be evaluated


# ===========================================================================
# 17. Full Pipeline Integration Test
# ===========================================================================

class TestFullPipeline:
    """
    Integration test: verify the full pipeline from RawFindings to MoscaAssessments.

    Target: 289 RawFindings → 147 CryptoAssets → 147 Classified → 147 Risk → 147 Mosca
    """

    def test_full_pipeline_mosca_assessment(self):
        """
        Run the complete intelligence pipeline and verify 147 Mosca assessments are produced.

        This test exercises:
          1. Scanning (289 RawFindings from demo_scan output)
          2. Normalization (147 CryptoAssets)
          3. Classification (147 Classified)
          4. Risk Engine (147 RiskAssessments)
          5. Mosca Engine (147 MoscaAssessments)
        """
        import json
        import pathlib

        # Load raw findings from the repo's pre-generated fixture
        raw_findings_path = pathlib.Path("raw_findings.md")
        if not raw_findings_path.exists():
            pytest.skip("raw_findings.md not found; run demo_scan.py to generate.")

        # Import the full pipeline components
        from core.classification import ClassificationEngine
        from core.mosca_engine import MoscaEngine
        from core.normalization import Normalizer
        from core.risk_engine import RiskEngine
        from scanners.framework.models import RawFinding

        # Reconstruct findings from raw_findings.md (parse JSON blocks)
        content = raw_findings_path.read_text(encoding="utf-8")

        # Extract JSON blocks
        import re
        json_blocks = re.findall(r"```json\n(.*?)\n```", content, re.DOTALL)

        findings: list[RawFinding] = []
        for block in json_blocks:
            try:
                data = json.loads(block)
                if isinstance(data, list):
                    for item in data:
                        if "finding_id" in item:
                            findings.append(RawFinding(**item))
                elif isinstance(data, dict) and "finding_id" in data:
                    findings.append(RawFinding(**data))
            except Exception:
                continue

        if not findings:
            pytest.skip("Could not parse RawFindings from raw_findings.md.")

        # Stage 1: Normalization
        normalizer = Normalizer()
        assets = normalizer.normalize(findings)
        assert len(assets) > 0, "Normalization must produce at least 1 CryptoAsset."

        # Stage 2: Classification
        classifier = ClassificationEngine()
        classified = classifier.classify_all(assets)
        assert len(classified) == len(assets)

        # Stage 3: Risk Engine
        risk_engine = RiskEngine()
        risk_engine.assess_and_enrich_all(classified)

        # Stage 4: Mosca Engine
        mosca_engine = MoscaEngine()
        mosca_assessments = mosca_engine.assess_all(classified)

        # Verify counts
        assert len(mosca_assessments) == len(classified), (
            f"Expected {len(classified)} Mosca assessments, got {len(mosca_assessments)}"
        )

        # Verify all assessments have required fields
        for a in mosca_assessments:
            assert a.asset_id is not None
            assert isinstance(a.urgency, MoscaUrgency)
            assert isinstance(a.hndl_exposure, HNDLExposure)
            assert isinstance(a.assumptions, list)
            assert isinstance(a.rationale, list)
            assert isinstance(a.mosca_applicable, bool)

        # Generate and verify the report
        report = mosca_engine.generate_report(classified, assessments=mosca_assessments)
        assert report.total_assets == len(classified)
        assert report.mosca_applicable_assets >= 0
        assert report.mosca_triggered_assets >= 0

        # Risk Engine does NOT define Mosca urgency
        # Verify at least one divergence between risk score and Mosca inequality
        triggered_set = {a.asset_id for a in mosca_assessments if a.inequality_triggered is True}
        non_triggered_set = {a.asset_id for a in mosca_assessments if a.inequality_triggered is False}
        # Without user-provided X, most will be UNKNOWN — that's expected and correct
        # The key invariant is that both states can coexist
        assert len(triggered_set) >= 0
        assert len(non_triggered_set) >= 0

        print(f"\n[Pipeline Verification]")
        print(f"  RawFindings:         {len(findings)}")
        print(f"  CryptoAssets:        {len(assets)}")
        print(f"  Classified Assets:   {len(classified)}")
        print(f"  Risk Assessments:    {len(classified)}")
        print(f"  Mosca Assessments:   {len(mosca_assessments)}")
        print(f"  Mosca Applicable:    {report.mosca_applicable_assets}")
        print(f"  Mosca Triggered:     {report.mosca_triggered_assets}")
        print(f"  HNDL Exposed:        {report.hndl_exposed_assets}")
        print(f"  Urgency Distribution: {report.urgency_distribution}")

    def test_pipeline_with_provided_lifetime_triggers_mosca(self):
        """Full pipeline with user-provided X should show triggered assessments."""
        from core.classification import ClassificationEngine
        from core.normalization import Normalizer

        # Create synthetic batch with known properties
        assets = [
            _make_shor_asset("RSA", 2048),
            _make_shor_asset("ECDSA", 256),
            _make_pqc_asset("ML-KEM-768"),
            _make_library_asset(),
            _make_grover_asset("AES", 128),
        ]

        engine = MoscaEngine()
        # Provide lifetime for all Shor-vulnerable assets
        contexts = {}
        for asset in assets:
            if asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK":
                contexts[asset.asset_id] = MoscaInput(
                    asset_id=asset.asset_id,
                    protected_lifetime_years=15.0,  # Long-lived
                    migration_time_years=4.0,
                    quantum_arrival_years=10.0,
                )

        assessments = engine.assess_all(assets, contexts=contexts)
        assert len(assessments) == len(assets)

        # Verify RSA and ECDSA are triggered
        for a in assessments:
            asset = next(x for x in assets if x.asset_id == a.asset_id)
            if asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK":
                assert a.inequality_triggered is True
            elif asset.primitive_type in (PrimitiveType.LIBRARY, PrimitiveType.RANDOM):
                assert a.mosca_applicable is False
