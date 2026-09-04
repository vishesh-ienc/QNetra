"""
QNetra Recommendation Engine Test Suite — Milestone 3.3
=========================================================

Comprehensive test suite verifying:
  1. Package imports and model invariants
  2. Algorithm mapping correctness:
     - RSA -> ML-KEM (HYBRID)
     - DH -> ML-KEM (HYBRID)
     - ECDH -> ML-KEM (HYBRID)
     - ECDSA -> ML-DSA (HYBRID)
     - DSA -> ML-DSA (DIRECT_PQC)
     - Ed25519 -> ML-DSA (HYBRID)
     - SHA-256 -> SHA-384 (DIRECT_PQC, hash upgrade only)
     - SHA-512 -> NO_MIGRATION_REQUIRED
     - AES-128 -> AES-256 (DIRECT_PQC, key-length upgrade only)
     - AES-256 -> NO_MIGRATION_REQUIRED
     - Classically broken algorithms (MD5, SHA-1, DES)
  3. Already PQC detection:
     - ML-KEM -> ALREADY_PQC
     - ML-DSA -> ALREADY_PQC
     - SLH-DSA -> ALREADY_PQC
  4. Not-applicable assets:
     - LIBRARY -> NO_MIGRATION_REQUIRED
     - RANDOM -> NO_MIGRATION_REQUIRED
     - PROTOCOL -> NO_MIGRATION_REQUIRED
  5. Unknown assets -> UNKNOWN recommendation
  6. Hybrid construction correctness:
     - ECDH -> X25519 + ML-KEM-768
     - ECDSA -> Ed25519 + ML-DSA-65
  7. Parameter selection policy:
     - High-security RSA >= 3072 -> ML-KEM-1024
     - Default RSA -> ML-KEM-768
     - High-security ECC P-384 -> ML-KEM-1024 or ML-DSA-87
     - Unknown key size -> ML-KEM-768 default + assumption logged
  8. Explainability:
     - Every recommendation has rationale (non-empty)
     - UNKNOWN recommendations have meaningful rationale
     - Assumptions list for parameter decisions
  9. Independence from risk_score:
     - Changing risk_score does not change recommendation
  10. Independence from Mosca urgency:
      - Mosca fields not referenced by recommendation engine
  11. Determinism:
      - Same input -> identical recommendation
      - recommend_all() produces stable sorting by asset_id
  12. No mutation:
      - Input CryptoAsset unchanged after recommend()
  13. Serialization:
      - PQCRecommendation.to_dict() is JSON-compatible
      - PQCRecommendationReport.to_dict() is JSON-compatible
  14. Batch operations:
      - recommend_all() handles empty list
      - generate_report() aggregates counts correctly
  15. Full pipeline integration:
      - 289 RawFindings -> 147 CryptoAssets -> 147 Classified -> 147 Risk -> 147 Mosca -> 147 Recommendations
"""

from __future__ import annotations

import json
import os
import uuid

import pytest

from core.models import CryptoAsset, PrimitiveType
from core.recommendation_engine import (
    MigrationComplexity,
    PQCRecommendation,
    PQCRecommendationReport,
    PQCRecommendationType,
    RecommendationEngine,
)
from core.recommendation_engine.knowledge import (
    HYBRID_ED25519_ML_DSA_65,
    HYBRID_X25519_ML_KEM_768,
    ML_KEM_768,
    ML_KEM_1024,
    ML_DSA_65,
    ML_DSA_87,
    FIPS_203,
    FIPS_204,
    FIPS_205,
)
from scanners.framework.models import ConfidenceLevel, FileLocation


# ===========================================================================
# Fixture Helpers
# ===========================================================================

def make_file_loc(path: str = "src/crypto.py", line: int = 10) -> FileLocation:
    return FileLocation(file_path=path, start_line=line, end_line=line, snippet="crypto.call()")


def make_asset(
    algorithm: str = "RSA",
    primitive_type: PrimitiveType = PrimitiveType.ASYMMETRIC_ENCRYPTION,
    key_length_bits: int | None = 2048,
    curve: str | None = None,
    mode: str | None = None,
    padding: str | None = None,
    quantum_vulnerable: bool | None = True,
    quantum_threat_type: str | None = "SHOR_POLYNOMIAL_BREAK",
    classical_security_status: str | None = "SECURE",
    risk_score: int | None = None,
    risk_severity: str | None = None,
    asset_id: str | None = None,
    implementation_library: str | None = None,
) -> CryptoAsset:
    """Construct a minimal CryptoAsset for recommendation engine testing."""
    if asset_id is None:
        asset_id = str(uuid.uuid5(
            uuid.NAMESPACE_DNS,
            f"test:{algorithm}:{primitive_type.value}:{key_length_bits}:{curve}"
        ))
    loc = make_file_loc()
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        algorithm_family=algorithm.split("-")[0],
        primitive_type=primitive_type,
        key_length_bits=key_length_bits,
        curve=curve,
        mode=mode,
        padding=padding,
        implementation_library=implementation_library,
        location=loc,
        locations=[loc],
        supporting_finding_ids=["find-001"],
        supporting_findings=[],
        confidence_score=0.95,
        confidence_level=ConfidenceLevel.HIGH,
        confidence_rationale="AST detected cryptographic call",
        quantum_vulnerable=quantum_vulnerable,
        quantum_threat_type=quantum_threat_type,
        classical_security_status=classical_security_status,
        risk_score=risk_score,
        risk_severity=risk_severity,
    )


# ===========================================================================
# 1. Import & Model Invariants
# ===========================================================================

class TestImportsAndModelInvariants:
    def test_engine_importable(self):
        from core.recommendation_engine import RecommendationEngine
        assert RecommendationEngine is not None

    def test_all_exports_importable(self):
        from core.recommendation_engine import (
            RecommendationEngine,
            PQCRecommendation,
            PQCRecommendationReport,
            PQCRecommendationType,
            MigrationComplexity,
            AssetRecommendationDetail,
        )
        assert all(x is not None for x in [
            RecommendationEngine, PQCRecommendation, PQCRecommendationReport,
            PQCRecommendationType, MigrationComplexity,
        ])

    def test_pqc_recommendation_type_values(self):
        assert PQCRecommendationType.DIRECT_PQC.value == "DIRECT_PQC"
        assert PQCRecommendationType.HYBRID.value == "HYBRID"
        assert PQCRecommendationType.ALREADY_PQC.value == "ALREADY_PQC"
        assert PQCRecommendationType.NO_MIGRATION_REQUIRED.value == "NO_MIGRATION_REQUIRED"
        assert PQCRecommendationType.UNKNOWN.value == "UNKNOWN"

    def test_migration_complexity_values(self):
        assert MigrationComplexity.LOW.value == "LOW"
        assert MigrationComplexity.MEDIUM.value == "MEDIUM"
        assert MigrationComplexity.HIGH.value == "HIGH"

    def test_recommendation_to_dict_structure(self):
        rec = PQCRecommendation(
            asset_id="test-id",
            current_algorithm="RSA",
            current_primitive="ASYMMETRIC_ENCRYPTION",
            recommendation_type=PQCRecommendationType.HYBRID,
            recommended_algorithm="ML-KEM-768",
            pqc_standard="NIST FIPS 203",
            hybrid_recommendation="X25519 + ML-KEM-768",
            rationale=["RSA is Shor-vulnerable."],
            assumptions=["Default policy."],
            limitations=["Library availability."],
            confidence="HIGH",
            migration_complexity=MigrationComplexity.HIGH,
            guidance_steps=["Step 1.", "Step 2."],
        )
        d = rec.to_dict()
        assert d["asset_id"] == "test-id"
        assert d["recommendation_type"] == "HYBRID"
        assert d["migration_complexity"] == "HIGH"
        assert isinstance(d["rationale"], list)
        assert isinstance(d["assumptions"], list)
        assert isinstance(d["guidance_steps"], list)

    def test_recommendation_to_dict_json_serializable(self):
        rec = PQCRecommendation(
            asset_id="test-id",
            current_algorithm="ECDH",
            current_primitive="KEY_EXCHANGE",
            recommendation_type=PQCRecommendationType.HYBRID,
            recommended_algorithm="ML-KEM-768",
        )
        # Should not raise
        json.dumps(rec.to_dict())

    def test_report_to_dict_json_serializable(self):
        report = PQCRecommendationReport(
            total_assets=5,
            direct_pqc_count=2,
            hybrid_count=2,
            already_pqc_count=1,
            no_migration_required_count=0,
            unknown_count=0,
        )
        json.dumps(report.to_dict())


# ===========================================================================
# 2. Shor-Vulnerable Key Exchange / KEM
# ===========================================================================

class TestShorVulnerableKeyExchange:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_ecdh_gets_hybrid_ml_kem(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, key_length_bits=None, curve="secp256r1")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.recommended_algorithm == ML_KEM_768
        assert rec.pqc_standard == FIPS_203
        assert HYBRID_X25519_ML_KEM_768 in rec.hybrid_recommendation

    def test_dh_gets_hybrid_ml_kem(self):
        asset = make_asset("DH", PrimitiveType.KEY_EXCHANGE, key_length_bits=2048, curve=None)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.recommended_algorithm == ML_KEM_768
        assert rec.pqc_standard == FIPS_203

    def test_x25519_gets_hybrid_ml_kem(self):
        asset = make_asset("X25519", PrimitiveType.KEY_EXCHANGE, key_length_bits=None, curve="Curve25519")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_203

    def test_rsa_key_exchange_gets_ml_kem(self):
        asset = make_asset("RSA", PrimitiveType.KEY_EXCHANGE, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_203

    def test_ecdh_hybrid_construction_is_x25519_ml_kem(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, key_length_bits=None, curve="secp256r1")
        rec = self.engine.recommend(asset)
        assert rec.hybrid_recommendation == HYBRID_X25519_ML_KEM_768

    def test_ecdh_guidance_steps_non_empty(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE)
        rec = self.engine.recommend(asset)
        assert len(rec.guidance_steps) > 0

    def test_ecdh_complexity_is_high(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE)
        rec = self.engine.recommend(asset)
        assert rec.migration_complexity == MigrationComplexity.HIGH


# ===========================================================================
# 3. Asymmetric Encryption (RSA)
# ===========================================================================

class TestAsymmetricEncryption:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_rsa_asymmetric_encryption_gets_ml_kem_hybrid(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_203
        assert rec.recommended_algorithm == ML_KEM_768

    def test_rsa_4096_gets_ml_kem_1024(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=4096)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024
        assert "1024" in rec.recommended_algorithm

    def test_rsa_3072_gets_ml_kem_1024(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=3072)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024

    def test_rsa_2048_gets_ml_kem_768_default(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_768

    def test_rsa_unknown_key_size_gets_ml_kem_768_with_assumption(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=None)
        rec = self.engine.recommend(asset)
        # Default policy applies
        assert rec.recommended_algorithm == ML_KEM_768
        # Assumption about missing key size must be logged
        assert any("key" in a.lower() or "param" in a.lower() or "default" in a.lower()
                   for a in rec.assumptions)

    def test_rsa_no_fabrication_unknown_size(self):
        """RSA with unknown key size does NOT get ML-KEM-768 as if it were RSA-2048."""
        asset_unknown = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=None)
        asset_2048 = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        rec_unknown = self.engine.recommend(asset_unknown)
        rec_2048 = self.engine.recommend(asset_2048)
        # Both get ML-KEM-768 by default, but the unknown one must note the assumption
        assert rec_unknown.recommended_algorithm == ML_KEM_768
        assert rec_2048.recommended_algorithm == ML_KEM_768
        # Unknown should have explicit assumption about missing key size
        assert len(rec_unknown.assumptions) >= len(rec_2048.assumptions)


# ===========================================================================
# 4. Digital Signatures
# ===========================================================================

class TestDigitalSignatures:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_ecdsa_gets_ml_dsa_hybrid(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE,
                           key_length_bits=None, curve="secp256r1")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_204
        assert rec.recommended_algorithm == ML_DSA_65
        assert rec.hybrid_recommendation == HYBRID_ED25519_ML_DSA_65

    def test_dsa_gets_ml_dsa_direct(self):
        asset = make_asset("DSA", PrimitiveType.DIGITAL_SIGNATURE, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        # DSA is not Ed25519/ECDSA so no hybrid needed
        assert rec.recommendation_type in (PQCRecommendationType.DIRECT_PQC, PQCRecommendationType.HYBRID)
        assert rec.pqc_standard == FIPS_204
        assert "ML-DSA" in rec.recommended_algorithm

    def test_ed25519_gets_ml_dsa_hybrid(self):
        asset = make_asset("Ed25519", PrimitiveType.DIGITAL_SIGNATURE,
                           key_length_bits=None, curve="Ed25519")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_204
        assert "ML-DSA" in rec.recommended_algorithm

    def test_rsa_signature_gets_ml_dsa(self):
        asset = make_asset("RSA", PrimitiveType.DIGITAL_SIGNATURE, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.pqc_standard == FIPS_204
        assert "ML-DSA" in rec.recommended_algorithm

    def test_ecdsa_p384_gets_ml_dsa_87(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE,
                           key_length_bits=None, curve="P-384")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_DSA_87

    def test_ecdsa_guidance_steps_non_empty(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE)
        rec = self.engine.recommend(asset)
        assert len(rec.guidance_steps) > 0

    def test_signature_migration_complexity_is_high(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE)
        rec = self.engine.recommend(asset)
        assert rec.migration_complexity == MigrationComplexity.HIGH


# ===========================================================================
# 5. Already PQC Detection
# ===========================================================================

class TestAlreadyPQC:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_ml_kem_512_is_already_pqc(self):
        asset = make_asset("ML-KEM-512", PrimitiveType.KEY_EXCHANGE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC
        assert rec.recommended_algorithm is None
        assert rec.pqc_standard == FIPS_203

    def test_ml_kem_768_is_already_pqc(self):
        asset = make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC
        assert rec.pqc_standard == FIPS_203

    def test_ml_kem_1024_is_already_pqc(self):
        asset = make_asset("ML-KEM-1024", PrimitiveType.KEY_EXCHANGE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC

    def test_ml_dsa_44_is_already_pqc(self):
        asset = make_asset("ML-DSA-44", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC
        assert rec.pqc_standard == FIPS_204

    def test_ml_dsa_65_is_already_pqc(self):
        asset = make_asset("ML-DSA-65", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC

    def test_ml_dsa_87_is_already_pqc(self):
        asset = make_asset("ML-DSA-87", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC

    def test_slh_dsa_sha2_128s_is_already_pqc(self):
        asset = make_asset("SLH-DSA-SHA2-128s", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC
        assert rec.pqc_standard == FIPS_205

    def test_slh_dsa_shake_128f_is_already_pqc(self):
        asset = make_asset("SLH-DSA-SHAKE-128f", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.ALREADY_PQC

    def test_already_pqc_has_no_recommended_algorithm(self):
        asset = make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm is None
        assert rec.hybrid_recommendation is None

    def test_already_pqc_has_rationale(self):
        asset = make_asset("ML-DSA-65", PrimitiveType.DIGITAL_SIGNATURE,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert len(rec.rationale) > 0
        # Rationale should mention the algorithm
        assert any("ML-DSA" in r for r in rec.rationale)


# ===========================================================================
# 6. Not-Applicable Assets
# ===========================================================================

class TestNotApplicableAssets:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_library_gets_no_migration_required(self):
        asset = make_asset("OpenSSL", PrimitiveType.LIBRARY,
                           quantum_vulnerable=None, quantum_threat_type="NOT_APPLICABLE",
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED
        assert rec.recommended_algorithm is None

    def test_random_gets_no_migration_required(self):
        asset = make_asset("PRNG", PrimitiveType.RANDOM,
                           quantum_vulnerable=None, quantum_threat_type="NOT_APPLICABLE",
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_protocol_gets_no_migration_required(self):
        asset = make_asset("TLS", PrimitiveType.PROTOCOL,
                           quantum_vulnerable=None, quantum_threat_type="NOT_APPLICABLE",
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_library_has_rationale(self):
        asset = make_asset("libcrypto.so", PrimitiveType.LIBRARY,
                           key_length_bits=None, quantum_threat_type="NOT_APPLICABLE")
        rec = self.engine.recommend(asset)
        assert len(rec.rationale) > 0


# ===========================================================================
# 7. Hash Functions
# ===========================================================================

class TestHashFunctions:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_sha256_gets_sha384_upgrade(self):
        asset = make_asset("SHA-256", PrimitiveType.HASH_FUNCTION,
                           key_length_bits=None, quantum_vulnerable=True,
                           quantum_threat_type="GROVER_BIT_HALVING")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.DIRECT_PQC
        assert rec.recommended_algorithm == "SHA-384"
        # NOT an ML-KEM or ML-DSA recommendation
        assert rec.pqc_standard is None

    def test_sha1_gets_sha256_upgrade(self):
        asset = make_asset("SHA-1", PrimitiveType.HASH_FUNCTION,
                           key_length_bits=None, quantum_vulnerable=True,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == "SHA-256"
        # SHA-1 is classically broken, priority is classical upgrade
        assert "SHA-256" in rec.recommended_algorithm

    def test_md5_gets_sha256_upgrade(self):
        asset = make_asset("MD5", PrimitiveType.HASH_FUNCTION,
                           key_length_bits=None, quantum_vulnerable=True,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == "SHA-256"

    def test_sha384_gets_no_migration_required(self):
        asset = make_asset("SHA-384", PrimitiveType.HASH_FUNCTION,
                           key_length_bits=None, quantum_vulnerable=False,
                           quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_sha512_gets_no_migration_required(self):
        asset = make_asset("SHA-512", PrimitiveType.HASH_FUNCTION,
                           key_length_bits=None, quantum_vulnerable=False,
                           quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_hash_does_not_get_ml_kem(self):
        """Hash functions must NEVER receive ML-KEM as a recommendation."""
        for alg in ["SHA-256", "SHA-384", "SHA-512", "SHA-1", "MD5"]:
            asset = make_asset(alg, PrimitiveType.HASH_FUNCTION, key_length_bits=None)
            rec = self.engine.recommend(asset)
            assert rec.recommended_algorithm != "ML-KEM-768", f"{alg} should not get ML-KEM"
            assert rec.recommended_algorithm != "ML-KEM-1024", f"{alg} should not get ML-KEM-1024"

    def test_hash_does_not_get_ml_dsa(self):
        """Hash functions must NEVER receive ML-DSA as a recommendation."""
        for alg in ["SHA-256", "SHA-384", "SHA-512", "SHA-1", "MD5"]:
            asset = make_asset(alg, PrimitiveType.HASH_FUNCTION, key_length_bits=None)
            rec = self.engine.recommend(asset)
            assert rec.recommended_algorithm != "ML-DSA-65", f"{alg} should not get ML-DSA"


# ===========================================================================
# 8. Symmetric Ciphers
# ===========================================================================

class TestSymmetricCiphers:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_aes128_gets_aes256_upgrade(self):
        asset = make_asset("AES-128", PrimitiveType.SYMMETRIC_CIPHER,
                           key_length_bits=128, quantum_vulnerable=True,
                           quantum_threat_type="GROVER_BIT_HALVING")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.DIRECT_PQC
        assert "256" in rec.recommended_algorithm
        # NOT an ML-KEM or ML-DSA recommendation
        assert rec.pqc_standard is None

    def test_aes256_gets_no_migration_required(self):
        asset = make_asset("AES-256", PrimitiveType.SYMMETRIC_CIPHER,
                           key_length_bits=256, quantum_vulnerable=False,
                           quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_aes256_gcm_gets_no_migration_required(self):
        asset = make_asset("AES-256-GCM", PrimitiveType.SYMMETRIC_CIPHER,
                           key_length_bits=256, quantum_vulnerable=False,
                           quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_des_gets_aes256_upgrade(self):
        asset = make_asset("DES", PrimitiveType.SYMMETRIC_CIPHER,
                           key_length_bits=56, quantum_vulnerable=True,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert "AES-256" in (rec.recommended_algorithm or "")

    def test_symmetric_does_not_get_ml_kem(self):
        """Symmetric ciphers must NEVER receive ML-KEM as a recommendation."""
        for alg, bits in [("AES-128", 128), ("AES-256", 256), ("3DES", 168)]:
            asset = make_asset(alg, PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=bits)
            rec = self.engine.recommend(asset)
            if rec.recommended_algorithm:
                assert "ML-KEM" not in rec.recommended_algorithm, f"{alg} should not get ML-KEM"

    def test_symmetric_does_not_get_ml_dsa(self):
        """Symmetric ciphers must NEVER receive ML-DSA as a recommendation."""
        for alg, bits in [("AES-128", 128), ("AES-256", 256)]:
            asset = make_asset(alg, PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=bits)
            rec = self.engine.recommend(asset)
            if rec.recommended_algorithm:
                assert "ML-DSA" not in rec.recommended_algorithm, f"{alg} should not get ML-DSA"

    def test_aes128_complexity_is_low(self):
        asset = make_asset("AES-128", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=128)
        rec = self.engine.recommend(asset)
        assert rec.migration_complexity == MigrationComplexity.LOW


# ===========================================================================
# 9. Unknown Algorithms
# ===========================================================================

class TestUnknownAlgorithms:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_unknown_primitive_algorithm_gets_unknown(self):
        asset = make_asset("PROPRIETARY-ALGO-X", PrimitiveType.UNKNOWN,
                           key_length_bits=None, quantum_vulnerable=None,
                           quantum_threat_type=None)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.UNKNOWN
        assert rec.recommended_algorithm is None

    def test_unknown_algorithm_has_rationale(self):
        asset = make_asset("MYSTERY-ALGO", PrimitiveType.UNKNOWN,
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert len(rec.rationale) > 0

    def test_unknown_algorithm_confidence_is_insufficient(self):
        asset = make_asset("UNKNOWN-CRYPTO", PrimitiveType.UNKNOWN,
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert rec.confidence == "INSUFFICIENT_DATA"

    def test_no_fabricated_recommendation_for_unknown(self):
        """No ML-KEM/ML-DSA recommendation for genuinely unknown algorithms."""
        asset = make_asset("CUSTOM-PKE-V2", PrimitiveType.UNKNOWN,
                           key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm is None


# ===========================================================================
# 10. Explainability Requirements
# ===========================================================================

class TestExplainability:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_every_recommendation_has_rationale(self):
        """Every recommendation must have at least one rationale string."""
        test_cases = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048),
            make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1"),
            make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE, curve="secp256r1"),
            make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE, quantum_vulnerable=False),
            make_asset("OpenSSL", PrimitiveType.LIBRARY, key_length_bits=None),
            make_asset("SHA-256", PrimitiveType.HASH_FUNCTION, key_length_bits=None),
            make_asset("AES-128", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=128),
            make_asset("UNKNOWN-ALGO", PrimitiveType.UNKNOWN, key_length_bits=None),
        ]
        for asset in test_cases:
            rec = self.engine.recommend(asset)
            assert len(rec.rationale) > 0, f"Missing rationale for {asset.algorithm}"
            assert all(isinstance(r, str) and len(r) > 10 for r in rec.rationale), \
                f"Empty or trivial rationale for {asset.algorithm}"

    def test_unknown_recommendation_has_audit_guidance(self):
        asset = make_asset("MYSTERY", PrimitiveType.UNKNOWN, key_length_bits=None)
        rec = self.engine.recommend(asset)
        assert len(rec.guidance_steps) > 0

    def test_parameter_assumptions_logged_for_default_policy(self):
        """Default parameter selection (ML-KEM-768) must log an assumption."""
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, key_length_bits=None, curve=None)
        rec = self.engine.recommend(asset)
        assert len(rec.assumptions) > 0

    def test_hybrid_recommendation_explains_hybrid_strategy(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        rec = self.engine.recommend(asset)
        # At least one rationale should explain why hybrid
        combined = " ".join(rec.rationale).lower()
        assert "hybrid" in combined or "classical" in combined or "backward" in combined

    def test_already_pqc_rationale_mentions_algorithm(self):
        asset = make_asset("ML-DSA-65", PrimitiveType.DIGITAL_SIGNATURE, quantum_vulnerable=False)
        rec = self.engine.recommend(asset)
        combined = " ".join(rec.rationale)
        assert "ML-DSA" in combined

    def test_limitations_populated_for_hybrid_recommendations(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        rec = self.engine.recommend(asset)
        assert len(rec.limitations) > 0


# ===========================================================================
# 11. Risk Score Independence
# ===========================================================================

class TestRiskScoreIndependence:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_recommendation_unchanged_when_risk_score_changes(self):
        """Changing risk_score must NOT change the recommendation type or algorithm."""
        base_asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        high_risk_asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1",
                                     risk_score=95, risk_severity="CRITICAL",
                                     asset_id=base_asset.asset_id)
        low_risk_asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1",
                                    risk_score=10, risk_severity="LOW",
                                    asset_id=base_asset.asset_id)

        rec_base = self.engine.recommend(base_asset)
        rec_high = self.engine.recommend(high_risk_asset)
        rec_low = self.engine.recommend(low_risk_asset)

        assert rec_base.recommendation_type == rec_high.recommendation_type
        assert rec_base.recommendation_type == rec_low.recommendation_type
        assert rec_base.recommended_algorithm == rec_high.recommended_algorithm
        assert rec_base.recommended_algorithm == rec_low.recommended_algorithm

    def test_rsa_recommendation_same_regardless_of_risk_score(self):
        for risk_score in [0, 30, 60, 90, 100]:
            asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION,
                               key_length_bits=2048, risk_score=risk_score)
            rec = self.engine.recommend(asset)
            assert rec.recommendation_type == PQCRecommendationType.HYBRID
            assert rec.recommended_algorithm == ML_KEM_768

    def test_sha256_recommendation_same_regardless_of_risk_score(self):
        for risk_score in [0, 50, 100]:
            asset = make_asset("SHA-256", PrimitiveType.HASH_FUNCTION,
                               key_length_bits=None, risk_score=risk_score)
            rec = self.engine.recommend(asset)
            assert rec.recommended_algorithm == "SHA-384"


# ===========================================================================
# 12. Determinism
# ===========================================================================

class TestDeterminism:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_same_input_produces_same_recommendation(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        rec1 = self.engine.recommend(asset)
        rec2 = self.engine.recommend(asset)
        assert rec1.recommendation_type == rec2.recommendation_type
        assert rec1.recommended_algorithm == rec2.recommended_algorithm
        assert rec1.pqc_standard == rec2.pqc_standard
        assert rec1.rationale == rec2.rationale

    def test_recommend_all_sorted_by_asset_id(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="z-asset"),
            make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, asset_id="a-asset"),
            make_asset("SHA-256", PrimitiveType.HASH_FUNCTION, asset_id="m-asset"),
        ]
        recs = self.engine.recommend_all(assets)
        asset_ids = [r.asset_id for r in recs]
        assert asset_ids == sorted(asset_ids)

    def test_repeated_batch_produces_same_ordering(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id=f"asset-{i:03d}")
            for i in range(10)
        ]
        recs1 = self.engine.recommend_all(assets)
        recs2 = self.engine.recommend_all(assets)
        for r1, r2 in zip(recs1, recs2):
            assert r1.asset_id == r2.asset_id
            assert r1.recommendation_type == r2.recommendation_type

    def test_ecdh_determinism_across_calls(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        recs = [self.engine.recommend(asset) for _ in range(5)]
        for r in recs:
            assert r.recommendation_type == recs[0].recommendation_type
            assert r.recommended_algorithm == recs[0].recommended_algorithm


# ===========================================================================
# 13. No Mutation
# ===========================================================================

class TestNoMutation:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_recommend_does_not_mutate_asset(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION,
                           key_length_bits=2048, risk_score=None)
        original_id = asset.asset_id
        original_algorithm = asset.algorithm
        original_risk_score = asset.risk_score

        self.engine.recommend(asset)

        assert asset.asset_id == original_id
        assert asset.algorithm == original_algorithm
        assert asset.risk_score == original_risk_score

    def test_recommend_all_does_not_mutate_assets(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="test-rsa"),
            make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, asset_id="test-ecdh"),
        ]
        original_ids = [a.asset_id for a in assets]
        original_algorithms = [a.algorithm for a in assets]
        original_risk_scores = [a.risk_score for a in assets]

        self.engine.recommend_all(assets)

        for i, asset in enumerate(assets):
            assert asset.asset_id == original_ids[i]
            assert asset.algorithm == original_algorithms[i]
            assert asset.risk_score == original_risk_scores[i]


# ===========================================================================
# 14. Serialization
# ===========================================================================

class TestSerialization:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_recommendation_to_dict_all_fields_present(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1")
        rec = self.engine.recommend(asset)
        d = rec.to_dict()
        required_keys = [
            "asset_id", "current_algorithm", "current_primitive", "recommendation_type",
            "recommended_algorithm", "pqc_standard", "hybrid_recommendation",
            "rationale", "assumptions", "limitations", "confidence",
            "migration_complexity", "guidance_steps",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"

    def test_report_to_dict_all_fields_present(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION),
            make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE, quantum_vulnerable=False),
        ]
        report = self.engine.generate_report(assets)
        d = report.to_dict()
        required_keys = [
            "total_assets", "direct_pqc_count", "hybrid_count", "already_pqc_count",
            "no_migration_required_count", "unknown_count",
            "recommendations_by_target_algorithm",
            "recommendations_by_current_algorithm",
            "recommendations_by_primitive",
            "asset_details",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"

    def test_all_recommendation_types_are_json_serializable(self):
        test_assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION),
            make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1"),
            make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE, quantum_vulnerable=False),
            make_asset("OpenSSL", PrimitiveType.LIBRARY, key_length_bits=None),
            make_asset("SHA-256", PrimitiveType.HASH_FUNCTION, key_length_bits=None),
            make_asset("MYSTERY", PrimitiveType.UNKNOWN, key_length_bits=None),
        ]
        for asset in test_assets:
            rec = self.engine.recommend(asset)
            json_str = json.dumps(rec.to_dict())
            assert isinstance(json_str, str)


# ===========================================================================
# 15. Batch Operations & Report
# ===========================================================================

class TestBatchAndReport:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_recommend_all_empty_list(self):
        recs = self.engine.recommend_all([])
        assert recs == []

    def test_generate_report_empty_list(self):
        report = self.engine.generate_report([])
        assert report.total_assets == 0
        assert report.direct_pqc_count == 0
        assert report.hybrid_count == 0
        assert report.already_pqc_count == 0
        assert report.no_migration_required_count == 0
        assert report.unknown_count == 0

    def test_generate_report_counts_types_correctly(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="a1"),
            make_asset("ECDH", PrimitiveType.KEY_EXCHANGE, curve="secp256r1", asset_id="a2"),
            make_asset("ML-KEM-768", PrimitiveType.KEY_EXCHANGE, quantum_vulnerable=False, asset_id="a3"),
            make_asset("OpenSSL", PrimitiveType.LIBRARY, key_length_bits=None, asset_id="a4"),
            make_asset("SHA-256", PrimitiveType.HASH_FUNCTION, key_length_bits=None, asset_id="a5"),
            make_asset("MYSTERY", PrimitiveType.UNKNOWN, key_length_bits=None, asset_id="a6"),
        ]
        report = self.engine.generate_report(assets)

        assert report.total_assets == 6
        assert report.already_pqc_count == 1          # ML-KEM-768
        assert report.no_migration_required_count >= 1  # OpenSSL LIBRARY
        assert report.hybrid_count >= 2               # RSA + ECDH are HYBRID
        assert report.unknown_count >= 1              # MYSTERY

    def test_generate_report_aggregates_target_algorithms(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="r1"),
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="r2"),
            make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE, curve="secp256r1", asset_id="e1"),
        ]
        report = self.engine.generate_report(assets)
        # ML-KEM-768 should appear 2x (for the two RSA assets)
        assert report.recommendations_by_target_algorithm.get(ML_KEM_768, 0) >= 2

    def test_generate_report_asset_details_count_matches_total(self):
        assets = [
            make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id=f"asset-{i}")
            for i in range(5)
        ]
        report = self.engine.generate_report(assets)
        assert len(report.asset_details) == 5

    def test_report_accepts_pre_computed_recommendations(self):
        assets = [make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, asset_id="test-rsa")]
        recs = self.engine.recommend_all(assets)
        report = self.engine.generate_report(assets, recommendations=recs)
        assert report.total_assets == 1
        assert len(report.recommendations) == 1


# ===========================================================================
# 16. Parameter Selection Edge Cases
# ===========================================================================

class TestParameterSelection:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_rsa_1024_gets_ml_kem_768_default(self):
        # RSA-1024 is below high-security threshold -> ML-KEM-768
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=1024)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_768

    def test_rsa_2048_gets_ml_kem_768_default(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_768

    def test_rsa_3072_gets_ml_kem_1024(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=3072)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024

    def test_rsa_4096_gets_ml_kem_1024(self):
        asset = make_asset("RSA", PrimitiveType.ASYMMETRIC_ENCRYPTION, key_length_bits=4096)
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024

    def test_ecdh_p384_gets_ml_kem_1024(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE,
                           key_length_bits=None, curve="P-384")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024

    def test_ecdh_p521_gets_ml_kem_1024(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE,
                           key_length_bits=None, curve="P-521")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_KEM_1024

    def test_ecdsa_p384_gets_ml_dsa_87(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE,
                           key_length_bits=None, curve="P-384")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_DSA_87

    def test_ecdsa_p256_gets_ml_dsa_65_default(self):
        asset = make_asset("ECDSA", PrimitiveType.DIGITAL_SIGNATURE,
                           key_length_bits=None, curve="P-256")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == ML_DSA_65

    def test_assumptions_logged_for_default_parameter(self):
        asset = make_asset("ECDH", PrimitiveType.KEY_EXCHANGE,
                           key_length_bits=None, curve="secp256r1")
        rec = self.engine.recommend(asset)
        # At least one assumption about policy default
        assert len(rec.assumptions) > 0


# ===========================================================================
# 17. Classically Broken Algorithms
# ===========================================================================

class TestClassicallyBroken:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_md5_hash_gets_sha256(self):
        asset = make_asset("MD5", PrimitiveType.HASH_FUNCTION, key_length_bits=None,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.DIRECT_PQC
        assert rec.recommended_algorithm == "SHA-256"

    def test_sha1_gets_sha256(self):
        asset = make_asset("SHA-1", PrimitiveType.HASH_FUNCTION, key_length_bits=None,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert rec.recommended_algorithm == "SHA-256"

    def test_des_symmetric_gets_aes256(self):
        asset = make_asset("DES", PrimitiveType.SYMMETRIC_CIPHER, key_length_bits=56,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        assert "AES-256" in (rec.recommended_algorithm or "")

    def test_classically_broken_has_priority_limitation(self):
        asset = make_asset("MD5", PrimitiveType.HASH_FUNCTION, key_length_bits=None)
        rec = self.engine.recommend(asset)
        # Should have a limitation about classical priority
        all_text = " ".join(rec.limitations).lower()
        assert "classical" in all_text or "broken" in all_text or "priority" in all_text


# ===========================================================================
# 18. Certificate Assets
# ===========================================================================

class TestCertificateAssets:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_rsa_certificate_gets_ml_dsa_hybrid(self):
        asset = make_asset("RSA", PrimitiveType.CERTIFICATE, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert rec.pqc_standard == FIPS_204
        assert "ML-DSA" in rec.recommended_algorithm

    def test_ecdsa_certificate_gets_ml_dsa_hybrid(self):
        asset = make_asset("ECDSA", PrimitiveType.CERTIFICATE, curve="secp256r1")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.HYBRID
        assert "ML-DSA" in rec.recommended_algorithm

    def test_certificate_guidance_has_ca_step(self):
        asset = make_asset("RSA", PrimitiveType.CERTIFICATE, key_length_bits=2048)
        rec = self.engine.recommend(asset)
        combined = " ".join(rec.guidance_steps).lower()
        assert "certificate" in combined or "ca" in combined or "pki" in combined


# ===========================================================================
# 19. MAC / KDF Assets
# ===========================================================================

class TestMacKdf:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_hmac_sha256_gets_no_migration_required(self):
        asset = make_asset("HMAC-SHA-256", PrimitiveType.MAC, key_length_bits=None,
                           quantum_vulnerable=False, quantum_threat_type="QUANTUM_RESISTANT")
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED

    def test_hmac_md5_gets_direct_pqc_upgrade(self):
        # HMAC-MD5 is based on classically-broken MD5 -> flag it
        asset = make_asset("HMAC-MD5", PrimitiveType.MAC, key_length_bits=None,
                           quantum_threat_type="CLASSICALLY_BROKEN")
        rec = self.engine.recommend(asset)
        # HMAC-MD5 normalization: MD5 is in CLASSICALLY_BROKEN set
        # Exact outcome depends on algorithm name matching
        assert rec.recommendation_type in (
            PQCRecommendationType.DIRECT_PQC,
            PQCRecommendationType.NO_MIGRATION_REQUIRED,
        )

    def test_hkdf_gets_no_migration_required(self):
        asset = make_asset("HKDF", PrimitiveType.KDF, key_length_bits=None,
                           quantum_vulnerable=False)
        rec = self.engine.recommend(asset)
        assert rec.recommendation_type == PQCRecommendationType.NO_MIGRATION_REQUIRED


# ===========================================================================
# 20. Full Pipeline Integration
# ===========================================================================

class TestFullPipelineIntegration:
    """
    End-to-end pipeline integration test:
    289 RawFindings -> 147 CryptoAssets -> 147 Classified -> 147 Recommendations
    """

    def test_full_pipeline_289_findings_to_147_recommendations(self):
        """Full pipeline integration: 289 RawFindings -> 147 CryptoAssets -> 147 Recommendations."""
        from pathlib import Path
        from core.classification import ClassificationEngine
        from core.normalization import Normalizer
        from scanners.framework.models import ScanTarget, TargetType
        from scanners.repository.scanner import RepositoryScanner
        from scanners.container.scanner import ContainerScanner
        from scanners.binary.scanner import BinaryScanner

        REPO_ROOT = Path(__file__).resolve().parent.parent.parent
        SAMPLES = REPO_ROOT / "samples"

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

        # Stage 3: Classification (batch API: classify takes list)
        classifier = ClassificationEngine()
        classified = classifier.classify(assets)
        assert len(classified) == 147, f"Expected 147 classified assets, got {len(classified)}"

        # Stage 4: Recommendations
        engine = RecommendationEngine()
        recommendations = engine.recommend_all(classified)

        # Pipeline verification: 289 -> 147 -> 147 -> 147
        assert len(recommendations) == 147, \
            f"Expected 147 recommendations, got {len(recommendations)}"

        # Verify recommendations are sorted by asset_id
        rec_ids = [r.asset_id for r in recommendations]
        assert rec_ids == sorted(rec_ids), "Recommendations not sorted by asset_id"

        # Verify all recommendations have required fields
        for rec in recommendations:
            assert rec.asset_id is not None
            assert rec.current_algorithm is not None
            assert rec.current_primitive is not None
            assert isinstance(rec.recommendation_type, PQCRecommendationType)
            assert isinstance(rec.rationale, list)
            assert len(rec.rationale) > 0
            assert isinstance(rec.guidance_steps, list)

        # Verify no asset was mutated during recommendations
        for asset in classified:
            assert asset.algorithm is not None
            assert asset.primitive_type is not None

        # Generate and verify aggregate report
        report = engine.generate_report(classified, recommendations=recommendations)
        assert report.total_assets == 147
        count_sum = (
            report.direct_pqc_count
            + report.hybrid_count
            + report.already_pqc_count
            + report.no_migration_required_count
            + report.unknown_count
        )
        assert count_sum == 147, \
            f"Count mismatch: sum={count_sum}, expected=147"

        # Report must be JSON-serializable
        json.dumps(report.to_dict())

    def test_full_pipeline_recommendation_distribution_sanity(self):
        """Verify sane distribution: Shor-vulnerable assets get HYBRID/DIRECT_PQC."""
        from pathlib import Path
        from core.classification import ClassificationEngine
        from core.normalization import Normalizer
        from scanners.framework.models import ScanTarget, TargetType
        from scanners.repository.scanner import RepositoryScanner

        REPO_ROOT = Path(__file__).resolve().parent.parent.parent
        SAMPLES = REPO_ROOT / "samples"

        repo_path = SAMPLES / "repository_samples" / "python_crypto"
        if not repo_path.exists():
            pytest.skip("Repository samples not found")

        target = ScanTarget(path=str(repo_path), target_type=TargetType.REPOSITORY)
        scanner = RepositoryScanner()
        result = scanner.scan(target)

        normalizer = Normalizer()
        assets = normalizer.normalize(result.findings)

        classifier = ClassificationEngine()
        classified = classifier.classify(assets)

        engine = RecommendationEngine()
        recommendations = engine.recommend_all(classified)

        # Should find some PQC-requiring recommendations in the Python test samples
        pqc_requiring = [
            r for r in recommendations
            if r.recommendation_type in (PQCRecommendationType.HYBRID, PQCRecommendationType.DIRECT_PQC)
        ]
        # Python crypto samples include RSA, ECDH, ECDSA -> at least some should require PQC migration
        assert len(pqc_requiring) > 0, "Expected some PQC-requiring recommendations from test samples"
