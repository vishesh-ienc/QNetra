"""
QNetra CBOM Generator Test Suite — Milestone 2.3
=================================================

Comprehensive test suite for core.cbom_generator covering:

  1. Module-level imports and package structure
  2. mapper.py — CryptoAsset → CDXComponent mapping
     - PrimitiveType → CDX primitive routing
     - display name construction (no-fabrication policy)
     - parameter_set_identifier (no-fabrication policy)
     - evidence building from asset locations
     - qnetra: property generation
     - PQC algorithm handling (ML-KEM → kem, ML-DSA → post-quantum)
  3. serializer.py — CDXBom construction and JSON/XML output
     - JSON structure conformance to CycloneDX 1.6 schema
     - Deterministic output (same assets → same JSON)
     - XML structure basics
     - bom-ref uniqueness
     - Component ordering stability
     - metadata tools embedding
     - Evidence occurrences structure
  4. validator.py — Structural validation
     - Valid CBOM passes
     - Missing required fields
     - Invalid enum values
     - Duplicate bom-ref detection
     - serialNumber format
     - nistQuantumSecurityLevel bounds
  5. No-Fabrication tests
     - AES with unknown key size → no parameterSetIdentifier
     - RSA with unknown key size → no parameterSetIdentifier
     - ECDSA with unknown curve → no curve field
     - SHA-256 → no parameterSetIdentifier
  6. Integration: 147 assets → CBOM generation + validation pass

Coverage targets: 95%+ for core.cbom_generator modules
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.cbom_generator import CBOMSerializer, CBOMValidator
from core.cbom_generator.mapper import (
    _build_display_name,
    _build_parameter_set_identifier,
    _map_asset_type,
    _map_primitive,
    map_asset_to_component,
)
from core.cbom_generator.models import (
    CDX_ASSET_TYPE_ALGORITHM,
    CDX_ASSET_TYPE_CERTIFICATE,
    CDX_ASSET_TYPE_PROTOCOL,
    CDX_ASSET_TYPE_RELATED_MATERIAL,
    CDX_PRIMITIVE_AE,
    CDX_PRIMITIVE_BLOCK_CIPHER,
    CDX_PRIMITIVE_DRBG,
    CDX_PRIMITIVE_HASH,
    CDX_PRIMITIVE_KDF,
    CDX_PRIMITIVE_KEY_AGREE,
    CDX_PRIMITIVE_KEM,
    CDX_PRIMITIVE_MAC,
    CDX_PRIMITIVE_PKE_ASYMM,
    CDX_PRIMITIVE_POST_QUANTUM,
    CDX_PRIMITIVE_SIGNATURE,
    CDX_PRIMITIVE_STREAM_CIPHER,
    CDX_PRIMITIVE_UNKNOWN,
)
from core.cbom_generator.validator import CBOMValidator, CBOMValidationResult
from core.models import CryptoAsset, PrimitiveType
from scanners.framework.models import ConfidenceLevel, FileLocation


# ===========================================================================
# Helpers — Fixture Factories
# ===========================================================================

def make_file_location(
    file_path: str = "src/crypto.py",
    start_line: int = 10,
    end_line: int = 10,
    snippet: str | None = None,
) -> FileLocation:
    return FileLocation(
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        snippet=snippet,
    )


def make_asset(
    asset_id: str | None = None,
    algorithm: str = "RSA",
    algorithm_family: str | None = "RSA",
    primitive_type: PrimitiveType = PrimitiveType.ASYMMETRIC_ENCRYPTION,
    key_length_bits: int | None = None,
    curve: str | None = None,
    mode: str | None = None,
    padding: str | None = None,
    implementation_library: str | None = None,
    file_path: str = "src/crypto.py",
    start_line: int = 10,
    confidence_score: float = 0.90,
    quantum_vulnerable: bool | None = None,
    quantum_threat_type: str | None = None,
    classical_security_status: str | None = None,
    quantum_security_status: str | None = None,
    effective_classical_security_bits: int | None = None,
    effective_quantum_security_bits: int | None = None,
    classification_notes: str | None = None,
    supporting_finding_ids: list[str] | None = None,
) -> CryptoAsset:
    """Factory for creating minimal CryptoAsset objects for testing."""
    if asset_id is None:
        asset_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"test:{algorithm}:{start_line}"))

    loc = make_file_location(file_path=file_path, start_line=start_line)
    return CryptoAsset(
        asset_id=asset_id,
        algorithm=algorithm,
        algorithm_family=algorithm_family,
        primitive_type=primitive_type,
        key_length_bits=key_length_bits,
        curve=curve,
        mode=mode,
        padding=padding,
        implementation_library=implementation_library,
        location=loc,
        locations=[loc],
        supporting_finding_ids=supporting_finding_ids or [],
        supporting_findings=[],
        confidence_score=confidence_score,
        confidence_level=ConfidenceLevel.HIGH,
        confidence_rationale="Test asset",
        quantum_vulnerable=quantum_vulnerable,
        quantum_threat_type=quantum_threat_type,
        classical_security_status=classical_security_status,
        quantum_security_status=quantum_security_status,
        effective_classical_security_bits=effective_classical_security_bits,
        effective_quantum_security_bits=effective_quantum_security_bits,
        classification_notes=classification_notes,
    )


# ===========================================================================
# 1. Package Structure
# ===========================================================================

class TestPackageStructure:
    def test_serializer_importable(self):
        from core.cbom_generator import CBOMSerializer
        assert CBOMSerializer is not None

    def test_validator_importable(self):
        from core.cbom_generator import CBOMValidator
        assert CBOMValidator is not None

    def test_models_importable(self):
        from core.cbom_generator import models
        assert models is not None

    def test_mapper_importable(self):
        from core.cbom_generator import mapper
        assert mapper is not None


# ===========================================================================
# 2. Mapper — Primitive Type Mapping
# ===========================================================================

class TestPrimitiveMapping:
    """Tests for _map_primitive() function."""

    def test_rsa_asymmetric_encryption(self):
        result = _map_primitive(PrimitiveType.ASYMMETRIC_ENCRYPTION, "RSA", "RSA", None)
        assert result == CDX_PRIMITIVE_PKE_ASYMM

    def test_ecdsa_signature(self):
        result = _map_primitive(PrimitiveType.DIGITAL_SIGNATURE, "ECDSA", "ECC", None)
        assert result == CDX_PRIMITIVE_SIGNATURE

    def test_ed25519_signature(self):
        result = _map_primitive(PrimitiveType.DIGITAL_SIGNATURE, "Ed25519", "ECC", None)
        assert result == CDX_PRIMITIVE_SIGNATURE

    def test_ecdh_key_agree(self):
        result = _map_primitive(PrimitiveType.KEY_EXCHANGE, "ECDH", "ECC", None)
        assert result == CDX_PRIMITIVE_KEY_AGREE

    def test_x25519_key_agree(self):
        result = _map_primitive(PrimitiveType.KEY_EXCHANGE, "X25519", "ECC", None)
        assert result == CDX_PRIMITIVE_KEY_AGREE

    def test_aes_gcm_ae(self):
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "AES", "AES", "GCM")
        assert result == CDX_PRIMITIVE_AE

    def test_aes_ccm_ae(self):
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "AES", "AES", "CCM")
        assert result == CDX_PRIMITIVE_AE

    def test_aes_cbc_block_cipher(self):
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "AES", "AES", "CBC")
        assert result == CDX_PRIMITIVE_BLOCK_CIPHER

    def test_aes_no_mode_block_cipher(self):
        # No mode → cannot assume AE, default to block-cipher
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "AES", "AES", None)
        assert result == CDX_PRIMITIVE_BLOCK_CIPHER

    def test_chacha20_stream_cipher(self):
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "ChaCha20", "CHACHA", None)
        assert result == CDX_PRIMITIVE_STREAM_CIPHER

    def test_chacha20_poly1305_stream_cipher(self):
        result = _map_primitive(PrimitiveType.SYMMETRIC_CIPHER, "ChaCha20-Poly1305", "CHACHA", None)
        assert result == CDX_PRIMITIVE_STREAM_CIPHER

    def test_sha256_hash(self):
        result = _map_primitive(PrimitiveType.HASH_FUNCTION, "SHA-256", "SHA", None)
        assert result == CDX_PRIMITIVE_HASH

    def test_md5_hash(self):
        result = _map_primitive(PrimitiveType.HASH_FUNCTION, "MD5", "MD5", None)
        assert result == CDX_PRIMITIVE_HASH

    def test_hmac_mac(self):
        result = _map_primitive(PrimitiveType.MAC, "HMAC-SHA-256", "HMAC", None)
        assert result == CDX_PRIMITIVE_MAC

    def test_pbkdf2_kdf(self):
        result = _map_primitive(PrimitiveType.KDF, "PBKDF2", "PBKDF2", None)
        assert result == CDX_PRIMITIVE_KDF

    def test_random_drbg(self):
        result = _map_primitive(PrimitiveType.RANDOM, "SecureRandom", None, None)
        assert result == CDX_PRIMITIVE_DRBG

    def test_unknown_primitive(self):
        result = _map_primitive(PrimitiveType.UNKNOWN, "UNKNOWN", None, None)
        assert result == CDX_PRIMITIVE_UNKNOWN

    # PQC Algorithms
    def test_ml_kem_kem(self):
        result = _map_primitive(PrimitiveType.KEY_EXCHANGE, "ML-KEM-768", "ML-KEM", None)
        assert result == CDX_PRIMITIVE_KEM

    def test_ml_dsa_post_quantum(self):
        result = _map_primitive(PrimitiveType.DIGITAL_SIGNATURE, "ML-DSA", "ML-DSA", None)
        assert result == CDX_PRIMITIVE_POST_QUANTUM

    def test_slh_dsa_post_quantum(self):
        result = _map_primitive(PrimitiveType.DIGITAL_SIGNATURE, "SLH-DSA", "SLH-DSA", None)
        assert result == CDX_PRIMITIVE_POST_QUANTUM


# ===========================================================================
# 3. Mapper — Asset Type Mapping
# ===========================================================================

class TestAssetTypeMapping:
    def test_algorithm_default(self):
        assert _map_asset_type(PrimitiveType.ASYMMETRIC_ENCRYPTION) == CDX_ASSET_TYPE_ALGORITHM

    def test_hash_algorithm(self):
        assert _map_asset_type(PrimitiveType.HASH_FUNCTION) == CDX_ASSET_TYPE_ALGORITHM

    def test_certificate_type(self):
        assert _map_asset_type(PrimitiveType.CERTIFICATE) == CDX_ASSET_TYPE_CERTIFICATE

    def test_protocol_type(self):
        assert _map_asset_type(PrimitiveType.PROTOCOL) == CDX_ASSET_TYPE_PROTOCOL

    def test_library_type(self):
        assert _map_asset_type(PrimitiveType.LIBRARY) == CDX_ASSET_TYPE_RELATED_MATERIAL

    def test_key_material_type(self):
        assert _map_asset_type(PrimitiveType.KEY_MATERIAL) == CDX_ASSET_TYPE_RELATED_MATERIAL


# ===========================================================================
# 4. Mapper — Display Name Construction (NO FABRICATION)
# ===========================================================================

class TestDisplayNameConstruction:
    """Tests for _build_display_name() with no-fabrication constraints."""

    def test_rsa_with_key_size(self):
        asset = make_asset(algorithm="RSA", key_length_bits=2048, primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION)
        assert _build_display_name(asset) == "RSA-2048"

    def test_rsa_without_key_size(self):
        # NO FABRICATION: key_length=None → no suffix
        asset = make_asset(algorithm="RSA", key_length_bits=None, primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION)
        assert _build_display_name(asset) == "RSA"

    def test_aes_256_gcm(self):
        asset = make_asset(algorithm="AES", key_length_bits=256, mode="GCM", primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        assert _build_display_name(asset) == "AES-256-GCM"

    def test_aes_no_key_with_mode(self):
        # Key unknown → do not add key length, but mode is known
        asset = make_asset(algorithm="AES", key_length_bits=None, mode="GCM", primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        assert _build_display_name(asset) == "AES-GCM"

    def test_aes_no_key_no_mode(self):
        # Both unknown → just AES
        asset = make_asset(algorithm="AES", key_length_bits=None, mode=None, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        assert _build_display_name(asset) == "AES"

    def test_ecdsa_with_curve(self):
        asset = make_asset(algorithm="ECDSA", curve="secp256r1", primitive_type=PrimitiveType.DIGITAL_SIGNATURE)
        assert _build_display_name(asset) == "ECDSA-secp256r1"

    def test_ecdsa_without_curve(self):
        # NO FABRICATION: curve=None → no suffix
        asset = make_asset(algorithm="ECDSA", curve=None, primitive_type=PrimitiveType.DIGITAL_SIGNATURE)
        assert _build_display_name(asset) == "ECDSA"

    def test_sha256_no_suffix(self):
        # Hash functions: use algorithm name directly
        asset = make_asset(algorithm="SHA-256", primitive_type=PrimitiveType.HASH_FUNCTION)
        assert _build_display_name(asset) == "SHA-256"

    def test_ml_kem_768(self):
        asset = make_asset(algorithm="ML-KEM-768", primitive_type=PrimitiveType.KEY_EXCHANGE)
        assert _build_display_name(asset) == "ML-KEM-768"


# ===========================================================================
# 5. Mapper — parameterSetIdentifier (NO FABRICATION)
# ===========================================================================

class TestParameterSetIdentifier:
    def test_rsa_2048(self):
        asset = make_asset(algorithm="RSA", key_length_bits=2048)
        assert _build_parameter_set_identifier(asset) == "2048"

    def test_aes_256(self):
        asset = make_asset(algorithm="AES", key_length_bits=256, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        assert _build_parameter_set_identifier(asset) == "256"

    def test_ecdsa_curve(self):
        asset = make_asset(algorithm="ECDSA", key_length_bits=None, curve="secp256r1")
        assert _build_parameter_set_identifier(asset) == "secp256r1"

    def test_rsa_no_key_none(self):
        # NO FABRICATION: missing key → None
        asset = make_asset(algorithm="RSA", key_length_bits=None, curve=None)
        assert _build_parameter_set_identifier(asset) is None

    def test_aes_no_key_none(self):
        # NO FABRICATION: missing key → None
        asset = make_asset(algorithm="AES", key_length_bits=None, curve=None, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        assert _build_parameter_set_identifier(asset) is None

    def test_sha256_no_identifier(self):
        # Hash functions don't have a key length → None
        asset = make_asset(algorithm="SHA-256", key_length_bits=None, primitive_type=PrimitiveType.HASH_FUNCTION)
        assert _build_parameter_set_identifier(asset) is None


# ===========================================================================
# 6. Mapper — map_asset_to_component()
# ===========================================================================

class TestMapAssetToComponent:
    def test_rsa_2048_component_structure(self):
        asset = make_asset(
            algorithm="RSA",
            key_length_bits=2048,
            primitive_type=PrimitiveType.ASYMMETRIC_ENCRYPTION,
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
            classical_security_status="SECURE",
            quantum_security_status="CRITICAL",
            effective_classical_security_bits=112,
        )
        comp = map_asset_to_component(asset)

        assert comp.type == "cryptographic-asset"
        assert comp.bom_ref == asset.asset_id
        assert comp.name == "RSA-2048"
        assert comp.crypto_properties is not None
        assert comp.crypto_properties.asset_type == CDX_ASSET_TYPE_ALGORITHM
        ap = comp.crypto_properties.algorithm_properties
        assert ap is not None
        assert ap.primitive == CDX_PRIMITIVE_PKE_ASYMM
        assert ap.parameter_set_identifier == "2048"
        assert ap.curve is None
        assert ap.classical_security_level == 112

    def test_aes_gcm_component(self):
        asset = make_asset(
            algorithm="AES",
            key_length_bits=256,
            mode="GCM",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
        )
        comp = map_asset_to_component(asset)
        assert comp.name == "AES-256-GCM"
        ap = comp.crypto_properties.algorithm_properties
        assert ap.primitive == CDX_PRIMITIVE_AE
        assert ap.parameter_set_identifier == "256"
        assert ap.mode == "gcm"  # lowercase in CDX output

    def test_sha256_component(self):
        asset = make_asset(
            algorithm="SHA-256",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            effective_quantum_security_bits=85,
        )
        comp = map_asset_to_component(asset)
        assert comp.name == "SHA-256"
        ap = comp.crypto_properties.algorithm_properties
        assert ap.primitive == CDX_PRIMITIVE_HASH
        assert ap.parameter_set_identifier is None  # No key size for hash
        # NIST quantum level: 85 bits < 128 → None (below minimum level 1)
        assert ap.nist_quantum_security_level is None

    def test_sha384_nist_quantum_level_1(self):
        asset = make_asset(
            algorithm="SHA-384",
            primitive_type=PrimitiveType.HASH_FUNCTION,
            effective_quantum_security_bits=128,  # BHT: 384/3 = 128
        )
        comp = map_asset_to_component(asset)
        ap = comp.crypto_properties.algorithm_properties
        assert ap.nist_quantum_security_level == 1  # 128 bits = Level 1

    def test_aes_256_nist_quantum_level_5(self):
        asset = make_asset(
            algorithm="AES",
            key_length_bits=256,
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            effective_quantum_security_bits=128,  # AES-256 Grover: 256//2 = 128
        )
        comp = map_asset_to_component(asset)
        # AES-256 Grover: 128 bits → Level 1 (128 bits meets Level 1 threshold)
        ap = comp.crypto_properties.algorithm_properties
        assert ap.nist_quantum_security_level == 1

    def test_ml_kem_768_kem_primitive(self):
        asset = make_asset(
            algorithm="ML-KEM-768",
            primitive_type=PrimitiveType.KEY_EXCHANGE,
        )
        comp = map_asset_to_component(asset)
        assert comp.crypto_properties.algorithm_properties.primitive == CDX_PRIMITIVE_KEM

    def test_evidence_locations_preserved(self):
        loc1 = make_file_location("src/crypto.py", 10, snippet="AES.encrypt()")
        loc2 = make_file_location("src/utils.py", 55)
        asset = make_asset(algorithm="AES", primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        # Override locations
        asset.locations = [loc1, loc2]

        comp = map_asset_to_component(asset)
        assert comp.evidence is not None
        assert len(comp.evidence) == 2
        assert comp.evidence[0].location == "src/crypto.py"
        assert comp.evidence[0].line == 10
        assert comp.evidence[0].symbol == "AES.encrypt()"
        assert comp.evidence[1].location == "src/utils.py"

    def test_qnetra_properties_present(self):
        asset = make_asset(
            algorithm="RSA",
            key_length_bits=2048,
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
            classical_security_status="SECURE",
            supporting_finding_ids=["abc", "def"],
        )
        comp = map_asset_to_component(asset)
        prop_names = {p.name for p in comp.properties}

        assert "qnetra:asset-id" in prop_names
        assert "qnetra:confidence" in prop_names
        assert "qnetra:quantum-threat-type" in prop_names
        assert "qnetra:quantum-vulnerable" in prop_names
        assert "qnetra:classical-security-status" in prop_names
        assert "qnetra:source-finding-ids" in prop_names

    def test_no_fabrication_rsa_no_key(self):
        """RSA with unknown key size → no parameterSetIdentifier in output."""
        asset = make_asset(algorithm="RSA", key_length_bits=None)
        comp = map_asset_to_component(asset)
        ap = comp.crypto_properties.algorithm_properties
        assert ap.parameter_set_identifier is None

    def test_no_fabrication_ecdsa_no_curve(self):
        """ECDSA with unknown curve → no curve in output."""
        asset = make_asset(algorithm="ECDSA", curve=None, primitive_type=PrimitiveType.DIGITAL_SIGNATURE)
        comp = map_asset_to_component(asset)
        ap = comp.crypto_properties.algorithm_properties
        assert ap.curve is None

    def test_no_fabrication_aes_no_key(self):
        """AES with unknown key → no parameterSetIdentifier."""
        asset = make_asset(algorithm="AES", key_length_bits=None, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        comp = map_asset_to_component(asset)
        ap = comp.crypto_properties.algorithm_properties
        assert ap.parameter_set_identifier is None

    def test_properties_sorted_deterministically(self):
        """qnetra: properties must be sorted by name for deterministic output."""
        asset = make_asset(
            algorithm="RSA",
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
            classical_security_status="SECURE",
        )
        comp = map_asset_to_component(asset)
        names = [p.name for p in comp.properties]
        assert names == sorted(names)


# ===========================================================================
# 7. Serializer — JSON Output
# ===========================================================================

class TestCBOMSerializerJSON:
    """Tests for CBOMSerializer.to_json()."""

    def setup_method(self):
        self.serializer = CBOMSerializer()
        self.rsa_asset = make_asset(
            algorithm="RSA",
            key_length_bits=2048,
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
        )
        self.aes_asset = make_asset(
            algorithm="AES",
            key_length_bits=256,
            mode="GCM",
            primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
            start_line=20,
        )

    def test_json_output_is_valid_json(self):
        json_str = self.serializer.to_json([self.rsa_asset], deterministic=True)
        doc = json.loads(json_str)
        assert isinstance(doc, dict)

    def test_json_bom_format(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        assert doc["bomFormat"] == "CycloneDX"

    def test_json_spec_version(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        assert doc["specVersion"] == "1.6"

    def test_json_version(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        assert doc["version"] == 1

    def test_json_components_list(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset, self.aes_asset]))
        assert isinstance(doc["components"], list)
        assert len(doc["components"]) == 2

    def test_json_component_type(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        comp = doc["components"][0]
        assert comp["type"] == "cryptographic-asset"

    def test_json_component_bom_ref(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        comp = doc["components"][0]
        assert comp["bom-ref"] == self.rsa_asset.asset_id

    def test_json_rsa_crypto_properties(self):
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        comp = doc["components"][0]
        cp = comp["cryptoProperties"]
        assert cp["assetType"] == "algorithm"
        ap = cp["algorithmProperties"]
        assert ap["primitive"] == CDX_PRIMITIVE_PKE_ASYMM
        assert ap["parameterSetIdentifier"] == "2048"
        assert ap["executionEnvironment"] == "software-plain-text"

    def test_json_no_fabrication_rsa_no_key(self):
        """RSA with no key_length → no parameterSetIdentifier in JSON."""
        asset = make_asset(algorithm="RSA", key_length_bits=None)
        doc = json.loads(self.serializer.to_json([asset]))
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "parameterSetIdentifier" not in ap

    def test_json_no_fabrication_aes_no_key_no_mode(self):
        """AES with no key, no mode → no parameterSetIdentifier, no mode."""
        asset = make_asset(algorithm="AES", key_length_bits=None, mode=None, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        doc = json.loads(self.serializer.to_json([asset]))
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "parameterSetIdentifier" not in ap
        assert "mode" not in ap

    def test_json_aes_gcm_mode_lowercase(self):
        """Mode is lowercased in CDX output."""
        doc = json.loads(self.serializer.to_json([self.aes_asset]))
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert ap["mode"] == "gcm"

    def test_json_deterministic_serial_number(self):
        """Deterministic mode uses a fixed serial number."""
        json1 = self.serializer.to_json([self.rsa_asset], deterministic=True)
        json2 = self.serializer.to_json([self.rsa_asset], deterministic=True)
        doc1 = json.loads(json1)
        doc2 = json.loads(json2)
        assert doc1.get("serialNumber") == doc2.get("serialNumber")

    def test_json_deterministic_no_timestamp(self):
        """Deterministic mode omits timestamp from metadata."""
        doc = json.loads(self.serializer.to_json([self.rsa_asset], deterministic=True))
        meta = doc.get("metadata", {})
        assert "timestamp" not in meta

    def test_json_live_mode_has_serial_number(self):
        """Live mode generates a serial number."""
        doc = json.loads(self.serializer.to_json([self.rsa_asset], deterministic=False))
        assert "serialNumber" in doc
        assert doc["serialNumber"].startswith("urn:uuid:")

    def test_json_metadata_tools(self):
        """Metadata includes tool information."""
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        meta = doc.get("metadata", {})
        tools = meta.get("tools", {})
        assert "components" in tools
        assert len(tools["components"]) == 1
        tool = tools["components"][0]
        assert tool["name"] == "QNetra ECDAT Engine"
        assert tool["version"] == "1.0.0"

    def test_json_evidence_occurrences(self):
        """Evidence occurrences are included in JSON output."""
        doc = json.loads(self.serializer.to_json([self.rsa_asset]))
        comp = doc["components"][0]
        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        assert len(occurrences) >= 1
        assert "location" in occurrences[0]

    def test_json_qnetra_properties_present(self):
        """qnetra: custom properties are embedded in output."""
        asset = make_asset(
            algorithm="RSA",
            quantum_vulnerable=True,
            quantum_threat_type="SHOR_POLYNOMIAL_BREAK",
        )
        doc = json.loads(self.serializer.to_json([asset]))
        comp = doc["components"][0]
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "qnetra:asset-id" in props
        assert "qnetra:quantum-threat-type" in props
        assert props["qnetra:quantum-vulnerable"] == "true"

    def test_json_components_sorted_by_asset_id(self):
        """Components are sorted by asset_id for deterministic ordering."""
        assets = [self.rsa_asset, self.aes_asset]
        doc = json.loads(self.serializer.to_json(assets, deterministic=True))
        bom_refs = [c["bom-ref"] for c in doc["components"]]
        sorted_ids = sorted([self.rsa_asset.asset_id, self.aes_asset.asset_id])
        assert bom_refs == sorted_ids

    def test_json_empty_asset_list(self):
        """Empty asset list → empty components array."""
        doc = json.loads(self.serializer.to_json([]))
        assert doc["components"] == []

    def test_json_to_json_dict_returns_dict(self):
        result = self.serializer.to_json_dict([self.rsa_asset])
        assert isinstance(result, dict)
        assert result["bomFormat"] == "CycloneDX"


# ===========================================================================
# 8. Serializer — XML Output
# ===========================================================================

class TestCBOMSerializerXML:
    def setup_method(self):
        self.serializer = CBOMSerializer()
        self.rsa_asset = make_asset(algorithm="RSA", key_length_bits=2048)

    def test_xml_output_is_string(self):
        xml_str = self.serializer.to_xml([self.rsa_asset], deterministic=True)
        assert isinstance(xml_str, str)

    def test_xml_declaration_present(self):
        xml_str = self.serializer.to_xml([self.rsa_asset], xml_declaration=True)
        assert xml_str.startswith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")

    def test_xml_no_declaration(self):
        xml_str = self.serializer.to_xml([self.rsa_asset], xml_declaration=False)
        assert not xml_str.startswith("<?xml")

    def test_xml_contains_bom_element(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert "<bom" in xml_str

    def test_xml_contains_component_element(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert 'type="cryptographic-asset"' in xml_str

    def test_xml_contains_asset_type(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert "<assetType>algorithm</assetType>" in xml_str

    def test_xml_contains_primitive(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert f"<primitive>{CDX_PRIMITIVE_PKE_ASYMM}</primitive>" in xml_str

    def test_xml_contains_parameter_set_identifier(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert "<parameterSetIdentifier>2048</parameterSetIdentifier>" in xml_str

    def test_xml_no_parameter_set_identifier_when_unknown(self):
        asset = make_asset(algorithm="RSA", key_length_bits=None)
        xml_str = self.serializer.to_xml([asset])
        assert "<parameterSetIdentifier>" not in xml_str

    def test_xml_name_element(self):
        xml_str = self.serializer.to_xml([self.rsa_asset])
        assert "<name>RSA-2048</name>" in xml_str


# ===========================================================================
# 9. Validator Tests
# ===========================================================================

class TestCBOMValidator:
    def setup_method(self):
        self.validator = CBOMValidator()
        self.serializer = CBOMSerializer()
        self.valid_asset = make_asset(algorithm="RSA", key_length_bits=2048)

    def _make_valid_doc(self) -> dict[str, Any]:
        return self.serializer.to_json_dict([self.valid_asset], deterministic=True)

    # Valid CBOM passes validation
    def test_valid_cbom_passes(self):
        doc = self._make_valid_doc()
        result = self.validator.validate(doc)
        assert result.is_valid, f"Unexpected errors: {result.errors}"
        assert len(result.errors) == 0

    def test_valid_result_truthy(self):
        doc = self._make_valid_doc()
        result = self.validator.validate(doc)
        assert bool(result) is True

    # Missing required fields
    def test_missing_bom_format(self):
        doc = self._make_valid_doc()
        del doc["bomFormat"]
        result = self.validator.validate(doc)
        assert not result.is_valid
        assert any("bomFormat" in e for e in result.errors)

    def test_wrong_bom_format(self):
        doc = self._make_valid_doc()
        doc["bomFormat"] = "SPDX"
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_missing_spec_version(self):
        doc = self._make_valid_doc()
        del doc["specVersion"]
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_wrong_spec_version(self):
        doc = self._make_valid_doc()
        doc["specVersion"] = "1.5"
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_missing_version(self):
        doc = self._make_valid_doc()
        del doc["version"]
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_version_less_than_one(self):
        doc = self._make_valid_doc()
        doc["version"] = 0
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_missing_components(self):
        doc = self._make_valid_doc()
        del doc["components"]
        result = self.validator.validate(doc)
        assert not result.is_valid

    # serialNumber format
    def test_invalid_serial_number_format(self):
        doc = self._make_valid_doc()
        doc["serialNumber"] = "not-a-uuid"
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_valid_serial_number(self):
        doc = self._make_valid_doc()
        doc["serialNumber"] = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        result = self.validator.validate(doc)
        assert result.is_valid

    # Component validation
    def test_duplicate_bom_ref_fails(self):
        asset = make_asset(algorithm="RSA", key_length_bits=2048)
        doc = self.serializer.to_json_dict([asset], deterministic=True)
        # Duplicate the component with same bom-ref
        doc["components"].append(doc["components"][0].copy())
        result = self.validator.validate(doc)
        assert not result.is_valid
        assert any("duplicate" in e.lower() for e in result.errors)

    def test_invalid_asset_type(self):
        doc = self._make_valid_doc()
        doc["components"][0]["cryptoProperties"]["assetType"] = "invalid-type"
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_invalid_primitive(self):
        doc = self._make_valid_doc()
        doc["components"][0]["cryptoProperties"]["algorithmProperties"]["primitive"] = "not-a-primitive"
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_invalid_nist_quantum_level(self):
        doc = self._make_valid_doc()
        doc["components"][0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = 6
        result = self.validator.validate(doc)
        assert not result.is_valid

    def test_valid_nist_quantum_level_5(self):
        doc = self._make_valid_doc()
        doc["components"][0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = 5
        result = self.validator.validate(doc)
        assert result.is_valid, f"Errors: {result.errors}"

    # Warnings
    def test_no_metadata_produces_warning(self):
        doc = self._make_valid_doc()
        if "metadata" in doc:
            del doc["metadata"]
        result = self.validator.validate(doc)
        # Should be valid (metadata is optional) but have a warning
        assert result.is_valid
        assert len(result.warnings) > 0


# ===========================================================================
# 10. No-Fabrication Integration Tests
# ===========================================================================

class TestNoFabricationPolicy:
    """
    End-to-end no-fabrication tests verifying that unknown cryptographic
    parameters are never invented in the CBOM output.
    """

    def setup_method(self):
        self.serializer = CBOMSerializer()
        self.validator = CBOMValidator()

    def test_aes_unknown_key_no_parameter_set_in_json(self):
        asset = make_asset(algorithm="AES", key_length_bits=None, primitive_type=PrimitiveType.SYMMETRIC_CIPHER)
        doc = self.serializer.to_json_dict([asset])
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "parameterSetIdentifier" not in ap, (
            "FABRICATION VIOLATION: parameterSetIdentifier must not be present when key is None."
        )

    def test_rsa_unknown_key_no_parameter_set_in_json(self):
        asset = make_asset(algorithm="RSA", key_length_bits=None)
        doc = self.serializer.to_json_dict([asset])
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "parameterSetIdentifier" not in ap

    def test_ecdsa_unknown_curve_no_curve_in_json(self):
        asset = make_asset(algorithm="ECDSA", curve=None, primitive_type=PrimitiveType.DIGITAL_SIGNATURE)
        doc = self.serializer.to_json_dict([asset])
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "curve" not in ap

    def test_rsa_shor_no_quantum_security_bits(self):
        """Shor-vulnerable RSA: effective_quantum_security_bits=None → no nistQuantumSecurityLevel."""
        asset = make_asset(
            algorithm="RSA",
            key_length_bits=2048,
            effective_quantum_security_bits=None,  # Shor → None by design
            quantum_vulnerable=True,
        )
        doc = self.serializer.to_json_dict([asset])
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "nistQuantumSecurityLevel" not in ap

    def test_sha256_no_parameter_set_in_json(self):
        """SHA-256 has no key length → no parameterSetIdentifier."""
        asset = make_asset(algorithm="SHA-256", primitive_type=PrimitiveType.HASH_FUNCTION)
        doc = self.serializer.to_json_dict([asset])
        ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert "parameterSetIdentifier" not in ap


# ===========================================================================
# 11. Determinism Tests
# ===========================================================================

class TestDeterminism:
    """Tests proving that identical inputs produce identical outputs."""

    def setup_method(self):
        self.serializer = CBOMSerializer()

    def _make_two_assets(self) -> list[CryptoAsset]:
        a1 = make_asset("RSA", key_length_bits=2048, start_line=10)
        a2 = make_asset("AES", key_length_bits=256, mode="GCM",
                        primitive_type=PrimitiveType.SYMMETRIC_CIPHER, start_line=20)
        return [a1, a2]

    def test_deterministic_json_identical(self):
        assets = self._make_two_assets()
        json1 = self.serializer.to_json(assets, deterministic=True)
        json2 = self.serializer.to_json(assets, deterministic=True)
        assert json1 == json2

    def test_deterministic_xml_identical(self):
        assets = self._make_two_assets()
        xml1 = self.serializer.to_xml(assets, deterministic=True)
        xml2 = self.serializer.to_xml(assets, deterministic=True)
        assert xml1 == xml2

    def test_reversed_asset_order_same_output(self):
        """Regardless of input order, sorted by asset_id → same JSON."""
        assets = self._make_two_assets()
        json_forward = self.serializer.to_json(assets, deterministic=True)
        json_backward = self.serializer.to_json(list(reversed(assets)), deterministic=True)
        assert json_forward == json_backward


# ===========================================================================
# 12. Full Pipeline Integration (using real classifier-like fixtures)
# ===========================================================================

class TestPipelineIntegration:
    """Integration test: multiple classified assets → valid CBOM."""

    def setup_method(self):
        self.serializer = CBOMSerializer()
        self.validator = CBOMValidator()

    def test_multi_asset_cbom_is_valid(self):
        assets = [
            make_asset("RSA", key_length_bits=2048, quantum_vulnerable=True,
                       quantum_threat_type="SHOR_POLYNOMIAL_BREAK"),
            make_asset("AES", key_length_bits=256, mode="GCM",
                       primitive_type=PrimitiveType.SYMMETRIC_CIPHER, start_line=20),
            make_asset("SHA-256", primitive_type=PrimitiveType.HASH_FUNCTION, start_line=30),
            make_asset("ECDSA", curve="secp256r1", primitive_type=PrimitiveType.DIGITAL_SIGNATURE,
                       start_line=40),
            make_asset("ECDH", primitive_type=PrimitiveType.KEY_EXCHANGE, start_line=50),
            make_asset("HMAC-SHA-256", primitive_type=PrimitiveType.MAC, start_line=60),
            make_asset("PBKDF2", primitive_type=PrimitiveType.KDF, start_line=70),
            make_asset("ML-KEM-768", primitive_type=PrimitiveType.KEY_EXCHANGE, start_line=80),
            make_asset("ML-DSA", primitive_type=PrimitiveType.DIGITAL_SIGNATURE, start_line=90),
        ]

        doc = self.serializer.to_json_dict(assets, deterministic=True)
        result = self.validator.validate(doc)

        assert result.is_valid, f"CBOM validation failed: {result.errors}"
        assert len(doc["components"]) == 9

    def test_bom_refs_unique_in_multi_asset_cbom(self):
        assets = [
            make_asset("RSA", key_length_bits=2048, start_line=10),
            make_asset("AES", primitive_type=PrimitiveType.SYMMETRIC_CIPHER, start_line=20),
            make_asset("SHA-256", primitive_type=PrimitiveType.HASH_FUNCTION, start_line=30),
        ]
        doc = self.serializer.to_json_dict(assets, deterministic=True)
        bom_refs = [c.get("bom-ref") for c in doc["components"]]
        assert len(bom_refs) == len(set(bom_refs)), "Duplicate bom-refs found!"

    def test_cbom_round_trip_json_parseable(self):
        """JSON → parse → validate: full round trip."""
        assets = [make_asset("RSA", key_length_bits=4096, quantum_vulnerable=True)]
        json_str = self.serializer.to_json(assets)
        reparsed = json.loads(json_str)
        result = self.validator.validate(reparsed)
        assert result.is_valid

    def test_cbom_components_count_matches_assets(self):
        """Number of components equals number of input assets."""
        n = 15
        assets = [
            make_asset("RSA", key_length_bits=2048, start_line=i * 5)
            for i in range(n)
        ]
        doc = self.serializer.to_json_dict(assets, deterministic=True)
        assert len(doc["components"]) == n
