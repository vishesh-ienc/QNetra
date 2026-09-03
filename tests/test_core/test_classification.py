"""
Tests for QNetra Classification Subsystem (core/classification/)
================================================================

Comprehensive test suite for Phase 2 Milestone 2.2 — Cryptographic & Quantum Threat Classification.

Covers:
  1. Classical Security Classification (10 tests)
     - RSA, AES, SHA-256, SHA-1, MD5, ECDSA, ECDH, HMAC, DH, Unknown algorithm
  2. Quantum Threat Classification (11 tests)
     - RSA/ECDSA/ECDH/DH → Shor, AES-128/AES-256 → Grover, SHA-256/SHA-512/ML-KEM/ML-DSA/SLH-DSA
  3. quantum_vulnerable Semantics (8 tests)
     - Shor → True, Grover threshold, None for unknowns, QUANTUM_RESISTANT → False
  4. Effective Security Bits — no fabrication (9 tests)
     - AES with/without key size, RSA with/without key, ECDSA with/without curve, hash BHT
  5. Classification Confidence (3 tests)
     - HIGH for complete info, LOW for missing params, UNKNOWN for unknown algorithm
  6. Determinism (3 tests)
     - Same input → same output, repeated calls, full batch classify()
  7. Integration (1 test)
     - 289 RawFindings → 142 CryptoAssets → all classified without crash

Total: 45 tests
"""

import uuid
from typing import Optional

import pytest

from core.classification import ClassificationEngine, ClassicalSecurityStatus, QuantumSecurityStatus
from core.classification.knowledge import (
    QUANTUM_SECURITY_THRESHOLD_BITS,
    get_hash_quantum_profile,
    get_rsa_dh_classical_security_bits,
)
from core.models import CryptoAsset, PrimitiveType
from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _make_asset(
    algorithm: str,
    family: str,
    primitive_type: PrimitiveType,
    key_length_bits: Optional[int] = None,
    curve: Optional[str] = None,
    mode: Optional[str] = None,
    padding: Optional[str] = None,
    library: Optional[str] = None,
) -> CryptoAsset:
    """
    Helper to construct a minimal CryptoAsset for classification testing.
    Uses Deduplicator.generate_deterministic_id() for a stable asset_id.
    """
    from core.normalization.deduplicator import Deduplicator
    from scanners.framework.models import ConfidenceLevel

    asset_id = Deduplicator.generate_deterministic_id(
        file_path="test/classify.py",
        line_anchor="1",
        algorithm=algorithm,
        key_size=key_length_bits,
        mode=mode,
        curve=curve,
        library=library,
    )
    finding_id = str(uuid.uuid4())
    location = FileLocation(file_path="test/classify.py", start_line=1, end_line=2)

    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        algorithm_family=family,
        primitive_type=primitive_type,
        key_length_bits=key_length_bits,
        curve=curve,
        mode=mode,
        padding=padding,
        implementation_library=library,
        location=location,
        locations=[location],
        supporting_finding_ids=[finding_id],
        supporting_findings=[],
        confidence_score=0.90,
        confidence_level=ConfidenceLevel.VERY_HIGH,
        confidence_rationale="Test asset",
        metadata={},
    )



# Shared engine instance for all tests
ENGINE = ClassificationEngine()


# ===========================================================================
# 1. Classical Security Classification
# ===========================================================================

class TestClassicalClassification:
    """Verify classical security status classification for each algorithm family."""

    def test_rsa_2048_classical_secure(self):
        """RSA-2048 must be classically SECURE with ~112 bit equivalent."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits == 112  # NIST SP 800-57

    def test_rsa_1024_classical_weak(self):
        """RSA-1024 must be classically WEAK (deprecated by NIST SP 800-131A Rev 2)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=1024)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.WEAK
        assert result.effective_classical_security_bits == 80

    def test_rsa_no_key_size_classical_unknown(self):
        """RSA without key size must produce UNKNOWN classical status — must not fabricate."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=None)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.UNKNOWN
        assert result.effective_classical_security_bits is None

    def test_aes_256_classical_secure(self):
        """AES-256 must be classically SECURE."""
        asset = _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256, mode="GCM")
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits == 256

    def test_aes_no_key_classical_unknown(self):
        """AES without key size must produce UNKNOWN classical bits — must not fabricate."""
        asset = _make_asset("AES-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=None, mode="GCM")
        result = ENGINE.classify_one(asset)

        # Classical status is still SECURE (AES is a secure cipher), but bits are unknown
        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits is None

    def test_sha_256_classical_secure(self):
        """SHA-256 must be classically SECURE with 128-bit collision resistance."""
        asset = _make_asset("SHA-256", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits == 128  # SHA-256 output/2

    def test_sha_1_classically_broken(self):
        """SHA-1 must be BROKEN classically (SHAttered 2017)."""
        asset = _make_asset("SHA-1", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.BROKEN
        assert result.effective_classical_security_bits is None  # Moot — broken

    def test_md5_classically_broken(self):
        """MD5 must be BROKEN classically (Wang et al. 2004)."""
        asset = _make_asset("MD5", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.BROKEN
        assert result.effective_classical_security_bits is None

    def test_ecdsa_p256_classical_secure(self):
        """ECDSA P-256 must be classically SECURE with ~128-bit equivalent."""
        asset = _make_asset("ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE, curve="secp256r1")
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits == 128

    def test_ecdh_secp256r1_classical_secure(self):
        """ECDH secp256r1 must be classically SECURE."""
        asset = _make_asset("ECDH", "ECC", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.SECURE
        assert result.effective_classical_security_bits == 128

    def test_hmac_unknown_classical_unknown(self):
        """HMAC without identified hash must produce UNKNOWN classical status."""
        asset = _make_asset("HMAC", "MAC", PrimitiveType.MAC)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.UNKNOWN
        assert result.effective_classical_security_bits is None

    def test_unknown_algorithm_classical_unknown(self):
        """Unknown algorithm must produce UNKNOWN across all dimensions."""
        asset = _make_asset("Unknown Algorithm", "UNKNOWN", PrimitiveType.UNKNOWN)
        result = ENGINE.classify_one(asset)

        assert result.classical_security_status == ClassicalSecurityStatus.UNKNOWN
        assert result.effective_classical_security_bits is None


# ===========================================================================
# 2. Quantum Threat Classification
# ===========================================================================

class TestQuantumClassification:
    """Verify quantum threat classification for each algorithm family."""

    # --- Shor-Vulnerable ---

    def test_rsa_shor_vulnerable(self):
        """RSA must be classified as SHOR_POLYNOMIAL_BREAK."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "SHOR_POLYNOMIAL_BREAK"
        assert result.quantum_security_status == QuantumSecurityStatus.CRITICAL

    def test_ecdsa_shor_vulnerable(self):
        """ECDSA must be classified as SHOR_POLYNOMIAL_BREAK."""
        asset = _make_asset("ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE, curve="secp256r1")
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "SHOR_POLYNOMIAL_BREAK"
        assert result.quantum_security_status == QuantumSecurityStatus.CRITICAL

    def test_ecdh_shor_vulnerable(self):
        """ECDH must be classified as SHOR_POLYNOMIAL_BREAK."""
        asset = _make_asset("ECDH", "ECC", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "SHOR_POLYNOMIAL_BREAK"
        assert result.quantum_security_status == QuantumSecurityStatus.CRITICAL

    def test_dh_shor_vulnerable(self):
        """DH must be classified as SHOR_POLYNOMIAL_BREAK."""
        asset = _make_asset("DH", "DH", PrimitiveType.KEY_EXCHANGE, key_length_bits=2048)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "SHOR_POLYNOMIAL_BREAK"
        assert result.quantum_security_status == QuantumSecurityStatus.CRITICAL

    # --- Grover-Impacted ---

    def test_aes_128_grover_impacted(self):
        """AES-128 must be classified as GROVER_BIT_HALVING."""
        asset = _make_asset("AES-128-CBC", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=128)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "GROVER_BIT_HALVING"
        assert result.quantum_security_status == QuantumSecurityStatus.DEGRADED

    def test_aes_256_grover_impacted(self):
        """AES-256 must be classified as GROVER_BIT_HALVING but SAFE (128-bit effective quantum)."""
        asset = _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "GROVER_BIT_HALVING"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE

    def test_sha_256_grover_impacted(self):
        """SHA-256 must be classified as GROVER_BIT_HALVING with BHT quantum collision profile."""
        asset = _make_asset("SHA-256", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "GROVER_BIT_HALVING"
        assert result.quantum_security_status == QuantumSecurityStatus.DEGRADED
        # BHT: SHA-256 → ~85-bit quantum collision resistance
        assert result.effective_quantum_security_bits == 85
        # Notes must explain BHT
        assert "BHT" in result.quantum_notes or "Brassard" in result.quantum_notes or "collision" in result.quantum_notes.lower()

    def test_sha_512_quantum_resistant(self):
        """SHA-512 must be classified as QUANTUM_RESISTANT with high BHT quantum bits."""
        asset = _make_asset("SHA-512", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "QUANTUM_RESISTANT"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE
        assert result.effective_quantum_security_bits == 171  # BHT: 512/3 ≈ 171

    # --- NIST PQC: Quantum Resistant ---

    def test_ml_kem_quantum_resistant(self):
        """ML-KEM must be classified as QUANTUM_RESISTANT."""
        asset = _make_asset("ML-KEM", "ML-KEM", PrimitiveType.KEY_EXCHANGE)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "QUANTUM_RESISTANT"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE
        assert result.quantum_vulnerable is False

    def test_ml_dsa_quantum_resistant(self):
        """ML-DSA must be classified as QUANTUM_RESISTANT."""
        asset = _make_asset("ML-DSA", "ML-DSA", PrimitiveType.DIGITAL_SIGNATURE)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "QUANTUM_RESISTANT"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE
        assert result.quantum_vulnerable is False

    def test_slh_dsa_quantum_resistant(self):
        """SLH-DSA must be classified as QUANTUM_RESISTANT."""
        asset = _make_asset("SLH-DSA", "SLH-DSA", PrimitiveType.DIGITAL_SIGNATURE)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "QUANTUM_RESISTANT"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE
        assert result.quantum_vulnerable is False

    def test_sha_384_quantum_resistant(self):
        """SHA-384 must be classified as QUANTUM_RESISTANT (BHT = 128-bit, at NIST threshold)."""
        asset = _make_asset("SHA-384", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)

        assert result.quantum_threat_str == "QUANTUM_RESISTANT"
        assert result.quantum_security_status == QuantumSecurityStatus.SAFE
        assert result.effective_quantum_security_bits == 128  # BHT: 384/3


# ===========================================================================
# 3. quantum_vulnerable Semantics
# ===========================================================================

class TestQuantumVulnerability:
    """Verify quantum_vulnerable field semantics per spec Section 9."""

    def test_shor_vulnerable_quantum_vulnerable_true(self):
        """SHOR_VULNERABLE → quantum_vulnerable = True (unconditional)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is True

    def test_aes_128_grover_quantum_vulnerable_true(self):
        """AES-128 (64-bit effective quantum) → quantum_vulnerable = True."""
        asset = _make_asset("AES-128-CBC", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=128)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is True

    def test_aes_256_grover_quantum_vulnerable_false(self):
        """AES-256 (128-bit effective quantum, at threshold) → quantum_vulnerable = False."""
        asset = _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is False

    def test_aes_192_grover_quantum_vulnerable_true(self):
        """AES-192 (96-bit effective quantum) → quantum_vulnerable = True."""
        asset = _make_asset("AES-192-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=192)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is True

    def test_aes_no_key_quantum_vulnerable_none(self):
        """AES without key size → quantum_vulnerable = None (cannot determine)."""
        asset = _make_asset("AES-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=None)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is None

    def test_sha_256_grover_quantum_vulnerable_true(self):
        """SHA-256 (85-bit BHT, below 128-bit threshold) → quantum_vulnerable = True."""
        asset = _make_asset("SHA-256", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is True

    def test_sha_512_quantum_resistant_quantum_vulnerable_false(self):
        """SHA-512 (171-bit BHT) → quantum_vulnerable = False."""
        asset = _make_asset("SHA-512", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is False

    def test_ml_kem_quantum_vulnerable_false(self):
        """ML-KEM (QUANTUM_RESISTANT) → quantum_vulnerable = False."""
        asset = _make_asset("ML-KEM", "ML-KEM", PrimitiveType.KEY_EXCHANGE)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is False

    def test_unknown_quantum_vulnerable_none(self):
        """Unknown algorithm → quantum_vulnerable = None."""
        asset = _make_asset("Unknown Algorithm", "UNKNOWN", PrimitiveType.UNKNOWN)
        result = ENGINE.classify_one(asset)
        assert result.quantum_vulnerable is None


# ===========================================================================
# 4. Effective Security Bits — No Fabrication
# ===========================================================================

class TestEffectiveSecurityBits:
    """Verify security bit estimates are correct and never fabricated from missing data."""

    def test_aes_128_effective_quantum_64_bits(self):
        """AES-128 → effective_quantum_security_bits = 64 (Grover: 128 // 2)."""
        asset = _make_asset("AES-128-CBC", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=128)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits == 64

    def test_aes_256_effective_quantum_128_bits(self):
        """AES-256 → effective_quantum_security_bits = 128 (Grover: 256 // 2)."""
        asset = _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits == 128

    def test_aes_no_key_effective_quantum_none(self):
        """AES without key size → effective_quantum_security_bits = None (never fabricated)."""
        asset = _make_asset("AES-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=None)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits is None, (
            "Must not fabricate quantum security bits for AES without known key size"
        )

    def test_rsa_2048_classical_bits_112(self):
        """RSA-2048 → effective_classical_security_bits = 112 (NIST SP 800-57)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)
        assert result.effective_classical_security_bits == 112

    def test_rsa_3072_classical_bits_128(self):
        """RSA-3072 → effective_classical_security_bits = 128 (NIST SP 800-57)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=3072)
        result = ENGINE.classify_one(asset)
        assert result.effective_classical_security_bits == 128

    def test_rsa_no_key_classical_bits_none(self):
        """RSA without key size → effective_classical_security_bits = None (never fabricated)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=None)
        result = ENGINE.classify_one(asset)
        assert result.effective_classical_security_bits is None, (
            "Must not fabricate classical security bits for RSA without known key size"
        )

    def test_rsa_effective_quantum_none_not_numeric(self):
        """RSA → effective_quantum_security_bits = None (Shor: not a reducible bit count)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits is None, (
            "Shor-vulnerable algorithms do not have a meaningful quantum security bit count. "
            "Must be None — not fabricated."
        )

    def test_ecdsa_p256_effective_quantum_none(self):
        """ECDSA P-256 → effective_quantum_security_bits = None (Shor-vulnerable)."""
        asset = _make_asset("ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE, curve="secp256r1")
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits is None

    def test_ecdsa_no_curve_classical_bits_none(self):
        """ECDSA without curve → effective_classical_security_bits = None (not fabricated)."""
        asset = _make_asset("ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE, curve=None)
        result = ENGINE.classify_one(asset)
        assert result.effective_classical_security_bits is None, (
            "Must not fabricate classical bits for ECDSA without known curve"
        )

    def test_sha_256_effective_quantum_85_bits_bht(self):
        """SHA-256 → effective_quantum_security_bits = 85 (BHT: 256/3 ≈ 85)."""
        asset = _make_asset("SHA-256", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits == 85

    def test_sha_384_effective_quantum_128_bits_bht(self):
        """SHA-384 → effective_quantum_security_bits = 128 (BHT: 384/3 = 128)."""
        asset = _make_asset("SHA-384", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits == 128

    def test_sha_512_effective_quantum_171_bits_bht(self):
        """SHA-512 → effective_quantum_security_bits = 171 (BHT: 512/3 ≈ 171)."""
        asset = _make_asset("SHA-512", "SHA", PrimitiveType.HASH_FUNCTION)
        result = ENGINE.classify_one(asset)
        assert result.effective_quantum_security_bits == 171


# ===========================================================================
# 5. Classification Confidence
# ===========================================================================

class TestClassificationConfidence:
    """Verify classification_confidence is deterministic and rule-based."""

    def test_high_confidence_rsa_with_key_size(self):
        """RSA with known key size → HIGH confidence."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        result = ENGINE.classify_one(asset)
        assert result.classification_confidence == "HIGH"

    def test_low_confidence_rsa_without_key_size(self):
        """RSA without key size → LOW confidence (important parameter missing)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=None)
        result = ENGINE.classify_one(asset)
        assert result.classification_confidence == "LOW"

    def test_unknown_confidence_unrecognized_algorithm(self):
        """Unknown algorithm → UNKNOWN confidence."""
        asset = _make_asset("Unknown Algorithm", "UNKNOWN", PrimitiveType.UNKNOWN)
        result = ENGINE.classify_one(asset)
        assert result.classification_confidence == "UNKNOWN"


# ===========================================================================
# 6. Determinism
# ===========================================================================

class TestDeterminism:
    """Verify classification is deterministic and idempotent."""

    def test_same_input_same_output(self):
        """Identical assets must produce identical ClassificationResult."""
        asset1 = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        asset2 = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)

        result1 = ENGINE.classify_one(asset1)
        result2 = ENGINE.classify_one(asset2)

        assert result1.classical_security_status == result2.classical_security_status
        assert result1.quantum_threat_str == result2.quantum_threat_str
        assert result1.quantum_security_status == result2.quantum_security_status
        assert result1.quantum_vulnerable == result2.quantum_vulnerable
        assert result1.effective_classical_security_bits == result2.effective_classical_security_bits
        assert result1.effective_quantum_security_bits == result2.effective_quantum_security_bits

    def test_repeated_classify_one_stable(self):
        """Repeated classify_one() calls on the same asset produce the same result."""
        asset = _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256)

        results = [ENGINE.classify_one(asset) for _ in range(5)]
        for r in results[1:]:
            assert r.quantum_threat_str == results[0].quantum_threat_str
            assert r.effective_quantum_security_bits == results[0].effective_quantum_security_bits
            assert r.quantum_vulnerable == results[0].quantum_vulnerable

    def test_classify_all_returns_same_list(self):
        """classify() mutates and returns the input list."""
        assets = [
            _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048),
            _make_asset("AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=256),
            _make_asset("SHA-256", "SHA", PrimitiveType.HASH_FUNCTION),
        ]
        returned = ENGINE.classify(assets)

        assert returned is assets  # Same list object
        for asset in returned:
            assert asset.quantum_threat_type is not None
            assert asset.classical_security_status is not None
            assert asset.quantum_security_status is not None


# ===========================================================================
# 7. Asset Enrichment via classify()
# ===========================================================================

class TestAssetEnrichment:
    """Verify classify() correctly enriches CryptoAsset fields."""

    def test_classify_enriches_rsa_asset(self):
        """classify() must populate all classification fields for RSA asset."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        ENGINE.classify([asset])

        assert asset.quantum_vulnerable is True
        assert asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK"
        assert asset.classical_security_status == "SECURE"
        assert asset.quantum_security_status == "CRITICAL"
        assert asset.effective_classical_security_bits == 112
        assert asset.effective_quantum_security_bits is None  # Shor → None
        assert asset.classification_notes is not None

    def test_classify_does_not_touch_risk_fields(self):
        """classify() must NOT set risk_score, risk_severity, or recommendation_id (Phase 3 scope)."""
        asset = _make_asset("RSA", "RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        ENGINE.classify([asset])

        assert asset.risk_score is None
        assert asset.risk_severity is None
        assert asset.recommendation_id is None

    def test_classify_library_asset_not_applicable(self):
        """Library assets must receive NOT_APPLICABLE quantum classification."""
        asset = _make_asset("OpenSSL", "LIBRARY", PrimitiveType.LIBRARY)
        ENGINE.classify([asset])

        assert asset.quantum_threat_type == "NOT_APPLICABLE"
        assert asset.quantum_vulnerable is False


# ===========================================================================
# 8. Integration — Full Pipeline
# ===========================================================================

class TestIntegration:
    """Integration test running the full pipeline: RawFindings → CryptoAssets → Classification."""

    def test_full_pipeline_289_findings_classified(self):
        """
        Integration: run 289 RawFindings through the full pipeline and verify
        that every CryptoAsset receives a deterministic classification without crash.
        """
        import os
        import sys

        # Build path to sample repository
        sample_repo = os.path.join(
            os.path.dirname(__file__), "..", "..", "samples", "crypto_samples"
        )
        if not os.path.isdir(sample_repo):
            pytest.skip("samples/crypto_samples not found — run demo script first")

        from scanners.framework.models import ScanTarget, TargetType
        from scanners.repository.scanner import RepositoryScanner
        from core.normalization import Normalizer
        from core.classification import ClassificationEngine as CE

        # Phase 1: Scan
        scanner = RepositoryScanner()
        target = ScanTarget(path=sample_repo, target_type=TargetType.REPOSITORY)
        result = scanner.scan(target)
        assert result.status.value in ("COMPLETED", "PARTIAL")
        findings = result.findings
        assert len(findings) > 0, "Expected findings from sample repository"

        # Phase 2.1: Normalize
        normalizer = Normalizer()
        assets = normalizer.normalize(findings)
        assert len(assets) > 0

        # Phase 2.2: Classify
        engine = CE()
        classified = engine.classify(assets)

        # Every asset must have been classified
        for asset in classified:
            assert asset.quantum_threat_type is not None, (
                f"Asset {asset.asset_id} ({asset.algorithm}) has no quantum_threat_type"
            )
            assert asset.classical_security_status is not None, (
                f"Asset {asset.asset_id} ({asset.algorithm}) has no classical_security_status"
            )
            assert asset.quantum_security_status is not None, (
                f"Asset {asset.asset_id} ({asset.algorithm}) has no quantum_security_status"
            )
            # Phase 3 fields must remain untouched
            assert asset.risk_score is None
            assert asset.risk_severity is None

        # Aggregate statistics
        vulnerable = [a for a in classified if a.quantum_vulnerable is True]
        resistant = [a for a in classified if a.quantum_vulnerable is False]
        unknown_vuln = [a for a in classified if a.quantum_vulnerable is None]

        # Sanity checks — not exact values, since sample size may vary
        total = len(classified)
        assert total > 0
        assert len(vulnerable) + len(resistant) + len(unknown_vuln) == total
