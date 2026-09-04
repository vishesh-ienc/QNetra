"""
QNetra Risk Engine Test Suite — Milestone 3.1
==============================================

Comprehensive test suite verifying:
  1. Package imports and model invariants
  2. Basic algorithm scoring: AES-128, AES-256, RSA-2048, RSA-1024, RSA-4096,
     ECDSA P-256, SHA-256, SHA-384, SHA-512, MD5, SHA-1, 3DES, ML-KEM
  3. Quantum risk classification dimensions:
     - Shor-vulnerable (RSA, ECC, DH)
     - Grover-impacted (AES-128, 3DES, SHA-256)
     - Quantum-resistant PQC (ML-KEM, ML-DSA, SLH-DSA)
     - Non-applicable / Non-crypto (Library, Random)
  4. Parameter weakness & No-Fabrication tests:
     - Known vs. unknown RSA key sizes
     - Known vs. unknown AES key sizes
     - Known vs. unknown ECC curves
     - Cipher modes (ECB penalty)
     - Padding modifiers (PKCS1 v1.5)
  5. Classical security states: SECURE, WEAK, BROKEN, UNKNOWN
  6. Mathematical invariants:
     - Bounded strictly within [0, 100]
     - Severity tier mapping accuracy
  7. Determinism:
     - Same input produces identical output
     - assess_all() produces stable sorting by asset_id
  8. Purity vs. In-Place Enrichment:
     - assess() does NOT mutate the input asset
     - assess_and_enrich() correctly populates asset.risk_score and asset.risk_severity
  9. Explainability & Factor Attribution:
     - Every non-zero contribution has name, score, reason, source_field
  10. Double-Counting Prevention:
      - Classically broken algorithms do not receive redundant quantum penalties
      - Shor-vulnerable algorithms do not receive redundant classical penalties
  11. Aggregate Report Generation:
      - RiskAssessmentReport overall score, distribution, and counts
  12. Full End-to-End Pipeline Integration:
      - 289 RawFindings → 147 CryptoAssets → 147 Classified → 147 Risk Assessments
"""

from __future__ import annotations

import os
import uuid
import pytest

from core.classification import ClassificationEngine
from core.classification.models import ClassicalSecurityStatus, QuantumSecurityStatus
from core.models import CryptoAsset, PrimitiveType
from core.normalization import Normalizer
from core.risk_engine import (
    AssetRiskDetail,
    RiskAssessment,
    RiskAssessmentReport,
    RiskEngine,
    RiskFactor,
    RiskScorer,
    RiskSeverity,
)
from scanners.framework.models import ConfidenceLevel, FileLocation
from scanners.registry.crypto_algorithms import QuantumThreat


# ===========================================================================
# Fixture Helpers
# ===========================================================================

def make_file_loc(path: str = "src/crypto.py", line: int = 10) -> FileLocation:
    return FileLocation(file_path=path, start_line=line, end_line=line, snippet="crypto.call()")


def make_test_asset(
    algorithm: str = "RSA",
    algorithm_family: str | None = "RSA",
    primitive_type: PrimitiveType = PrimitiveType.ASYMMETRIC_ENCRYPTION,
    key_length_bits: int | None = 2048,
    curve: str | None = None,
    mode: str | None = None,
    padding: str | None = None,
    classical_security_status: ClassicalSecurityStatus = ClassicalSecurityStatus.SECURE,
    quantum_threat_type: str = QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
    quantum_security_status: QuantumSecurityStatus = QuantumSecurityStatus.CRITICAL,
    quantum_vulnerable: bool | None = True,
    effective_classical_bits: int | None = 112,
    effective_quantum_bits: int | None = None,
    classification_notes: str | None = "Test asset notes",
    confidence_score: float = 0.95,
    asset_id: str | None = None,
) -> CryptoAsset:
    """Construct an enriched CryptoAsset for risk engine testing."""
    if asset_id is None:
        asset_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"test:{algorithm}:{key_length_bits}:{curve}:{mode}"))

    loc = make_file_loc()
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        algorithm_family=algorithm_family,
        primitive_type=primitive_type,
        key_length_bits=key_length_bits,
        curve=curve,
        mode=mode,
        padding=padding,
        implementation_library="test_lib",
        location=loc,
        locations=[loc],
        supporting_finding_ids=["find-001"],
        supporting_findings=[],
        confidence_score=confidence_score,
        confidence_level=ConfidenceLevel.HIGH,
        confidence_rationale="AST detected cryptographic call",
        classical_security_status=classical_security_status.value if hasattr(classical_security_status, "value") else classical_security_status,
        quantum_threat_type=quantum_threat_type,
        quantum_security_status=quantum_security_status.value if hasattr(quantum_security_status, "value") else quantum_security_status,
        quantum_vulnerable=quantum_vulnerable,
        effective_classical_security_bits=effective_classical_bits,
        effective_quantum_security_bits=effective_quantum_bits,
        classification_notes=classification_notes,
    )


# ===========================================================================
# 1. Package Structure & Models
# ===========================================================================

class TestPackageStructure:
    def test_imports(self):
        from core.risk_engine import (
            RiskEngine,
            RiskAssessment,
            RiskAssessmentReport,
            RiskFactor,
            RiskSeverity,
            AssetRiskDetail,
            RiskScorer,
        )
        assert RiskEngine is not None
        assert RiskAssessment is not None
        assert RiskAssessmentReport is not None

    def test_severity_tier_mapping(self):
        assert RiskSeverity.from_score(100) == RiskSeverity.CRITICAL
        assert RiskSeverity.from_score(80) == RiskSeverity.CRITICAL
        assert RiskSeverity.from_score(79) == RiskSeverity.HIGH
        assert RiskSeverity.from_score(60) == RiskSeverity.HIGH
        assert RiskSeverity.from_score(59) == RiskSeverity.MEDIUM
        assert RiskSeverity.from_score(30) == RiskSeverity.MEDIUM
        assert RiskSeverity.from_score(29) == RiskSeverity.LOW
        assert RiskSeverity.from_score(0) == RiskSeverity.LOW

    def test_risk_assessment_post_init_validation(self):
        with pytest.raises(ValueError, match="risk_score must be between 0 and 100"):
            RiskAssessment(asset_id="test", risk_score=105, severity=RiskSeverity.CRITICAL)

        with pytest.raises(ValueError, match="risk_score must be between 0 and 100"):
            RiskAssessment(asset_id="test", risk_score=-5, severity=RiskSeverity.LOW)


# ===========================================================================
# 2. Representative Cryptographic Algorithms Scoring
# ===========================================================================

class TestRepresentativeAlgorithms:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_rsa_2048_critical_risk(self):
        """RSA-2048: Shor-vulnerable asymmetric baseline -> Score 90, CRITICAL."""
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=2048,
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 90
        assert assessment.severity == RiskSeverity.CRITICAL
        assert any("Shor" in f.reason for f in assessment.factors)

    def test_rsa_1024_maximum_risk(self):
        """RSA-1024: Shor-vulnerable (90) + below 2048 modifier (+10) -> Score 100, CRITICAL."""
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=1024,
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            classical_security_status=ClassicalSecurityStatus.WEAK,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL
        assert any(f.name == "parameter_key_length" and f.score == 10.0 for f in assessment.factors)

    def test_rsa_4096_reduced_critical_risk(self):
        """RSA-4096: Shor-vulnerable (90) + maximum key modifier (-5) -> Score 85, CRITICAL."""
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=4096,
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 85
        assert assessment.severity == RiskSeverity.CRITICAL
        assert any(f.name == "parameter_key_length" and f.score == -5.0 for f in assessment.factors)

    def test_ecdsa_p256_critical_risk(self):
        """ECDSA P-256: Shor-vulnerable signature -> Score 90, CRITICAL."""
        asset = make_test_asset(
            algorithm="ECDSA",
            algorithm_family="ECC",
            primitive_type=PrimitiveType.DIGITAL_SIGNATURE,
            curve="secp256r1",
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 90
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_aes_128_high_risk(self):
        """AES-128: Grover degraded symmetric (60) + 128-bit key modifier (+10) -> Score 70, HIGH."""
        asset = make_test_asset(
            algorithm="AES",
            algorithm_family="AES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=128,
            mode="GCM",
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
            effective_quantum_bits=64,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 70
        assert assessment.severity == RiskSeverity.HIGH
        assert any("Grover" in f.reason for f in assessment.factors)

    def test_aes_256_low_risk(self):
        """AES-256: Quantum-resistant classical base (20) + 256-bit modifier (-10) -> Score 10, LOW."""
        asset = make_test_asset(
            algorithm="AES",
            algorithm_family="AES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=256,
            mode="GCM",
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
            effective_quantum_bits=128,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 10
        assert assessment.severity == RiskSeverity.LOW

    def test_sha_256_medium_risk(self):
        """SHA-256: Grover/BHT collision degraded (40) -> Score 40, MEDIUM."""
        asset = make_test_asset(
            algorithm="SHA-256",
            algorithm_family="SHA",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
            effective_quantum_bits=85,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 40
        assert assessment.severity == RiskSeverity.MEDIUM

    def test_sha_384_low_risk(self):
        """SHA-384: Quantum-resistant hash (effective quantum bits >= 128) -> Score 15, LOW."""
        asset = make_test_asset(
            algorithm="SHA-384",
            algorithm_family="SHA",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.QUANTUM_RESISTANT.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
            effective_quantum_bits=128,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 15
        assert assessment.severity == RiskSeverity.LOW

    def test_sha_512_low_risk(self):
        """SHA-512: Quantum-resistant hash -> Score 15, LOW."""
        asset = make_test_asset(
            algorithm="SHA-512",
            algorithm_family="SHA",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.QUANTUM_RESISTANT.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
            effective_quantum_bits=171,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 15
        assert assessment.severity == RiskSeverity.LOW

    def test_md5_classically_broken(self):
        """MD5: Classically broken -> Score 100, CRITICAL."""
        asset = make_test_asset(
            algorithm="MD5",
            algorithm_family="MD5",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type=QuantumThreat.CLASSICALLY_BROKEN.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_sha1_classically_broken(self):
        """SHA-1: Classically broken -> Score 100, CRITICAL."""
        asset = make_test_asset(
            algorithm="SHA-1",
            algorithm_family="SHA",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type=QuantumThreat.CLASSICALLY_BROKEN.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_des_classically_broken(self):
        """DES: Classically broken cipher -> Score 100, CRITICAL."""
        asset = make_test_asset(
            algorithm="DES",
            algorithm_family="DES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=56,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type=QuantumThreat.CLASSICALLY_BROKEN.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_nist_pqc_ml_kem_zero_risk(self):
        """ML-KEM-768: Standardized PQC algorithm -> Score 0, LOW."""
        asset = make_test_asset(
            algorithm="ML-KEM-768",
            algorithm_family="ML-KEM",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.QUANTUM_RESISTANT.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 0
        assert assessment.severity == RiskSeverity.LOW

    def test_3des_high_risk(self):
        """3DES: Deprecated classical WEAK (Sweet32) + Grover degraded -> Score 75, HIGH."""
        asset = make_test_asset(
            algorithm="3DES",
            algorithm_family="DES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=168,
            classical_security_status=ClassicalSecurityStatus.WEAK,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 75
        assert assessment.severity == RiskSeverity.HIGH


# ===========================================================================
# 3. Parameter Weakness & No-Fabrication Policy
# ===========================================================================

class TestParametersAndNoFabrication:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_rsa_unknown_key_size_no_fabrication(self):
        """RSA with unknown key length: receives base 90, NO modifier fabricated."""
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=None,
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 90
        assert assessment.severity == RiskSeverity.CRITICAL
        # Verify factor states parameter is unverified
        param_factor = next(f for f in assessment.factors if f.name == "parameter_key_length")
        assert param_factor.score == 0.0
        assert "unverified" in param_factor.reason.lower()

    def test_aes_unknown_key_size_no_fabrication(self):
        """AES with unknown key length: receives moderate quantum uncertainty (50), no key guess."""
        asset = make_test_asset(
            algorithm="AES",
            key_length_bits=None,
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 50
        assert assessment.severity == RiskSeverity.MEDIUM
        assert any(f.name == "parameter_uncertainty" for f in assessment.factors)

    def test_ecb_mode_penalty(self):
        """AES-256 with ECB mode receives pattern leakage penalty (+15)."""
        asset = make_test_asset(
            algorithm="AES",
            key_length_bits=256,
            mode="ECB",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
        )
        assessment = self.engine.assess(asset)
        # Base 20 - 10 (key) + 15 (ECB) = 25
        assert assessment.risk_score == 25
        assert any(f.name == "parameter_cipher_mode" and f.score == 15.0 for f in assessment.factors)

    def test_pkcs1_padding_penalty(self):
        """RSA with PKCS1 padding receives Bleichenbacher penalty (+5)."""
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=4096,
            padding="PKCS1v15",
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        # Base 90 - 5 (4096) + 5 (PKCS1) = 90
        assert assessment.risk_score == 90
        assert any(f.name == "parameter_padding" and f.score == 5.0 for f in assessment.factors)


# ===========================================================================
# 4. Double-Counting Prevention
# ===========================================================================

class TestDoubleCountPrevention:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_classically_broken_zeros_out_quantum(self):
        """
        MD5 is classically broken (100). The quantum vulnerability factor MUST be
        recorded as 0.0 (superseded) to prevent double counting 100 + 90 = 190.
        """
        asset = make_test_asset(
            algorithm="MD5",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type=QuantumThreat.CLASSICALLY_BROKEN.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        q_factor = next(f for f in assessment.factors if f.name == "quantum_vulnerability")
        assert q_factor.score == 0.0
        assert "superseded" in q_factor.reason.lower()

    def test_rsa_shor_does_not_duplicate_classical_status(self):
        """
        RSA-2048 is Shor-vulnerable (90). Its classical status SECURE does not
        add redundant factors.
        """
        asset = make_test_asset(
            algorithm="RSA",
            key_length_bits=2048,
            classical_security_status=ClassicalSecurityStatus.SECURE,
            quantum_threat_type=QuantumThreat.SHOR_POLYNOMIAL_BREAK.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 90
        # Only quantum and parameter factors exist
        factor_names = [f.name for f in assessment.factors]
        assert "classical_vulnerability" not in factor_names


# ===========================================================================
# 5. Operational Artifacts (Library, Random, Unknown)
# ===========================================================================

class TestOperationalArtifacts:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_library_detection_zero_risk(self):
        """PrimitiveType.LIBRARY carries zero risk score."""
        asset = make_test_asset(
            algorithm="pycryptodome",
            primitive_type=PrimitiveType.LIBRARY,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            quantum_threat_type="NOT_APPLICABLE",
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=False,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 0
        assert assessment.severity == RiskSeverity.LOW

    def test_drbg_random_zero_risk(self):
        """PrimitiveType.RANDOM carries zero risk score."""
        asset = make_test_asset(
            algorithm="SecureRandom",
            primitive_type=PrimitiveType.RANDOM,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.SECURE,
            quantum_threat_type="NOT_APPLICABLE",
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 0
        assert assessment.severity == RiskSeverity.LOW

    def test_completely_unknown_algorithm(self):
        """Unknown algorithm receives baseline 50 (MEDIUM)."""
        asset = make_test_asset(
            algorithm="UNKNOWN_PROPRIETARY",
            primitive_type=PrimitiveType.UNKNOWN,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            quantum_threat_type="UNKNOWN",
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 50
        assert assessment.severity == RiskSeverity.MEDIUM

    def test_sha_224_high_risk(self):
        """SHA-224 is a legacy digest length resulting in HIGH risk (65)."""
        asset = make_test_asset(
            algorithm="SHA-224",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            key_length_bits=None,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 65
        assert assessment.severity == RiskSeverity.HIGH

    def test_hmac_sha1_broken_hash(self):
        """HMAC with SHA-1 receives CRITICAL 100 risk due to underlying broken hash."""
        asset = make_test_asset(
            algorithm="HMAC-SHA1",
            primitive_type=PrimitiveType.MAC,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type=QuantumThreat.CLASSICALLY_BROKEN.value,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_pbkdf2_approved_kdf(self):
        """Standard PBKDF2 receives MEDIUM 30 risk."""
        asset = make_test_asset(
            algorithm="PBKDF2",
            primitive_type=PrimitiveType.KDF,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.SECURE,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 30
        assert assessment.severity == RiskSeverity.MEDIUM

    def test_protocol_broken_sslv3(self):
        """Deprecated protocol (SSLv3) receives CRITICAL 100 risk."""
        asset = make_test_asset(
            algorithm="SSLv3",
            primitive_type=PrimitiveType.PROTOCOL,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.BROKEN,
            quantum_threat_type="NOT_APPLICABLE",
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 100
        assert assessment.severity == RiskSeverity.CRITICAL

    def test_protocol_weak_tls10(self):
        """Weak protocol (TLS 1.0) receives HIGH 70 risk."""
        asset = make_test_asset(
            algorithm="TLSv1.0",
            primitive_type=PrimitiveType.PROTOCOL,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.WEAK,
            quantum_threat_type="NOT_APPLICABLE",
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 70
        assert assessment.severity == RiskSeverity.HIGH

    def test_protocol_modern_tls13(self):
        """Modern protocol (TLS 1.3) receives LOW 25 risk."""
        asset = make_test_asset(
            algorithm="TLSv1.3",
            primitive_type=PrimitiveType.PROTOCOL,
            key_length_bits=None,
            classical_security_status=ClassicalSecurityStatus.SECURE,
            quantum_threat_type="NOT_APPLICABLE",
            quantum_security_status=QuantumSecurityStatus.SAFE,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 25
        assert assessment.severity == RiskSeverity.LOW

    def test_aes_192_medium_risk(self):
        """AES-192 receives MEDIUM 55 risk."""
        asset = make_test_asset(
            algorithm="AES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=192,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 55
        assert assessment.severity == RiskSeverity.MEDIUM

    def test_aes_unknown_key_ecb_penalty(self):
        """AES with unknown key + ECB mode receives 50 + 15 = 65 HIGH risk."""
        asset = make_test_asset(
            algorithm="AES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=None,
            mode="ECB",
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
        )
        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 65
        assert assessment.severity == RiskSeverity.HIGH



# ===========================================================================
# 6. Purity, Side-Effects & Determinism
# ===========================================================================

class TestPurityAndDeterminism:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_assess_is_pure_no_mutation(self):
        """assess() must NOT mutate asset.risk_score or asset.risk_severity."""
        asset = make_test_asset(algorithm="RSA", key_length_bits=2048)
        assert asset.risk_score is None
        assert asset.risk_severity is None

        assessment = self.engine.assess(asset)
        assert assessment.risk_score == 90
        # Original asset remains untouched!
        assert asset.risk_score is None
        assert asset.risk_severity is None

    def test_assess_and_enrich_mutates_asset(self):
        """assess_and_enrich() correctly populates asset fields."""
        asset = make_test_asset(algorithm="RSA", key_length_bits=2048)
        assessment = self.engine.assess_and_enrich(asset)
        assert asset.risk_score == 90
        assert asset.risk_severity == "CRITICAL"
        assert assessment.risk_score == 90

    def test_determinism_identical_runs(self):
        """Same input asset must produce bit-for-bit identical RiskAssessment."""
        asset = make_test_asset(algorithm="AES", key_length_bits=128)
        res1 = self.engine.assess(asset)
        res2 = self.engine.assess(asset)

        assert res1.risk_score == res2.risk_score
        assert res1.severity == res2.severity
        assert res1.rationale == res2.rationale
        assert len(res1.factors) == len(res2.factors)
        assert res1.to_dict() == res2.to_dict()

    def test_assess_all_deterministic_ordering(self):
        """assess_all() returns assessments sorted deterministically by asset_id."""
        a1 = make_test_asset(algorithm="RSA", asset_id="zzz-uuid")
        a2 = make_test_asset(algorithm="AES", asset_id="aaa-uuid")
        a3 = make_test_asset(algorithm="SHA-256", asset_id="mmm-uuid")

        # Forward order
        list1 = self.engine.assess_all([a1, a2, a3])
        # Reversed order
        list2 = self.engine.assess_all([a3, a2, a1])

        ids1 = [a.asset_id for a in list1]
        ids2 = [a.asset_id for a in list2]
        assert ids1 == ["aaa-uuid", "mmm-uuid", "zzz-uuid"]
        assert ids1 == ids2


# ===========================================================================
# 7. Aggregate Report Generation
# ===========================================================================

class TestAggregateReport:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_empty_assets_report(self):
        report = self.engine.generate_report([])
        assert report.overall_risk_score == 0.0
        assert report.overall_severity == RiskSeverity.LOW
        assert report.total_assets_discovered == 0
        assert report.vulnerable_assets_count == 0

    def test_report_schema_and_counts(self):
        a_rsa = make_test_asset(algorithm="RSA", key_length_bits=2048) # 90
        a_aes = make_test_asset(
            algorithm="AES",
            algorithm_family="AES",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            key_length_bits=128,
            quantum_threat_type=QuantumThreat.GROVER_BIT_HALVING.value,
            quantum_security_status=QuantumSecurityStatus.DEGRADED,
            quantum_vulnerable=True,
            effective_quantum_bits=64,
        )  # 70
        a_pqc = make_test_asset(                                        # 0
            algorithm="ML-KEM-768",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
            quantum_threat_type=QuantumThreat.QUANTUM_RESISTANT.value,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
        )

        assets = [a_rsa, a_aes, a_pqc]
        report = self.engine.generate_report(assets)

        assert report.total_assets_discovered == 3
        assert report.shor_vulnerable_count == 1
        assert report.grover_impacted_count == 1
        assert report.quantum_resistant_count == 1
        assert report.severity_distribution["CRITICAL"] == 1
        assert report.severity_distribution["HIGH"] == 1
        assert report.severity_distribution["LOW"] == 1

        # Max is 90, mean is (90 + 70 + 0)/3 = 53.333
        # Overall: 0.7 * 90 + 0.3 * 53.333 = 63.0 + 16.0 = 79.0
        expected_overall = round(0.7 * 90.0 + 0.3 * (160.0 / 3.0), 1)
        assert report.overall_risk_score == expected_overall
        assert report.overall_severity == RiskSeverity.HIGH

        # Verify to_dict() contract
        d = report.to_dict()
        assert "overall_risk_score" in d
        assert "overall_severity" in d
        assert "asset_scores" in d
        assert len(d["asset_scores"]) == 3
        assert d["asset_scores"][0]["score"] in (0, 70, 90)


# ===========================================================================
# 8. Full Pipeline Integration: 289 RawFindings → 147 Assets → 147 Risk Assessments
# ===========================================================================

class TestFullPipelineIntegration:
    def test_full_pipeline_289_to_147_to_147_assessments(self):
        """
        End-to-End Pipeline Integration Test:
          289 RawFindings
                ↓ (Normalizer)
          147 Canonical CryptoAssets
                ↓ (ClassificationEngine)
          147 Classified CryptoAssets
                ↓ (RiskEngine)
          147 Risk Assessments

        Verifies that:
          1. Exact 289 findings are discovered from fixtures.
          2. Exact 147 canonical assets are produced.
          3. Exact 147 risk assessments are generated without error.
          4. Every risk score is strictly bounded [0, 100].
          5. Overall repository report is computed.
        """
        from pathlib import Path
        REPO_ROOT = Path(__file__).resolve().parent.parent.parent
        SAMPLES = REPO_ROOT / "samples"

        from scanners.framework.models import ScanTarget, TargetType
        from scanners.repository.scanner import RepositoryScanner
        from scanners.container.scanner import ContainerScanner
        from scanners.binary.scanner import BinaryScanner

        fixtures = [
            (RepositoryScanner(), ScanTarget(path=str(SAMPLES / "repository_samples" / "python_crypto"), target_type=TargetType.REPOSITORY)),
            (RepositoryScanner(), ScanTarget(path=str(SAMPLES / "repository_samples" / "javascript_crypto"), target_type=TargetType.REPOSITORY)),
            (RepositoryScanner(), ScanTarget(path=str(SAMPLES / "repository_samples" / "java_crypto"), target_type=TargetType.REPOSITORY)),
            (RepositoryScanner(), ScanTarget(path=str(SAMPLES / "repository_samples" / "cpp_crypto"), target_type=TargetType.REPOSITORY)),
            (ContainerScanner(),  ScanTarget(path=str(SAMPLES / "container_sample"), target_type=TargetType.CONTAINER_FS)),
            (BinaryScanner(),     ScanTarget(path=str(SAMPLES / "binary_samples" / "sample_crypto_binary.elf"), target_type=TargetType.BINARY)),
        ]

        # Stage 1: Discovery
        raw_findings = []
        for scanner, target in fixtures:
            res = scanner.scan(target)
            raw_findings.extend(res.findings)
        assert len(raw_findings) == 289, f"Expected 289 RawFindings, got {len(raw_findings)}"

        # Stage 2: Normalization
        normalizer = Normalizer()
        assets = normalizer.normalize(raw_findings)
        assert len(assets) == 147, f"Expected 147 CryptoAssets, got {len(assets)}"

        # Stage 3: Classification
        classifier = ClassificationEngine()
        classified = classifier.classify(assets)
        assert len(classified) == 147, f"Expected 147 Classified Assets, got {len(classified)}"

        # Stage 4: Risk Scoring
        risk_engine = RiskEngine()
        assessments = risk_engine.assess_and_enrich_all(classified)
        assert len(assessments) == 147, f"Expected 147 Risk Assessments, got {len(assessments)}"

        # Verify invariants across all 147 assessments
        for assessment in assessments:
            assert 0 <= assessment.risk_score <= 100, f"Score out of bounds: {assessment.risk_score}"
            assert assessment.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH, RiskSeverity.MEDIUM, RiskSeverity.LOW)
            assert len(assessment.factors) > 0
            assert assessment.rationale != ""

        # Verify asset enrichment occurred
        for asset in classified:
            assert asset.risk_score is not None
            assert asset.risk_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

        # Generate repository-level report
        report = risk_engine.generate_report(classified, assessments)
        assert report.total_assets_discovered == 147
        assert 0.0 <= report.overall_risk_score <= 100.0
        assert report.overall_severity == RiskSeverity.CRITICAL  # Since repository has critical Shor/DES assets
        assert report.vulnerable_assets_count > 0
        assert report.shor_vulnerable_count > 0

        total_distributed = sum(report.severity_distribution.values())
        assert total_distributed == 147, f"Severity distribution sum ({total_distributed}) != 147"
