"""
QNetra CBOM Generator — CryptoAsset → CycloneDX 1.6 Component Mapper
======================================================================

Implements deterministic, no-fabrication mapping from canonical QNetra
CryptoAsset objects to CycloneDX 1.6 CDXComponent structures.

DESIGN PRINCIPLES:
  1. NO FABRICATION: If a parameter (key_length, curve, mode) is None on the
     CryptoAsset, it must remain absent in the CBOM output.
  2. CANONICAL NAMING: Reuse the algorithm name produced by normalization.
     Do not create a second normalization engine.
  3. EVIDENCE PRESERVATION: Map asset_id, locations, finding_ids to
     evidence and qnetra: namespaced properties.
  4. PRIMITIVE MAPPING: Map QNetra PrimitiveType → CycloneDX 1.6 primitive
     enum using the official CycloneDX 1.6 primitive taxonomy.
  5. ALGORITHM NAME → CDX NAME: Construct parameterized algorithm display
     names ONLY when the corresponding parameters are actually known.
  6. DETERMINISM: All outputs use sorted/ordered fields. No timestamps,
     no random state, no mutable global state.

PrimitiveType → CDX primitive mapping:
  ASYMMETRIC_ENCRYPTION → "public-key-encryption"
  DIGITAL_SIGNATURE     → "signature"
  KEY_EXCHANGE          → "key-agree"
  SYMMETRIC_CIPHER      → "ae" (if mode is GCM/CCM/EAX) or "block-cipher"
  HASH_FUNCTION         → "hash"
  MAC                   → "mac"
  KDF                   → "kdf"
  PROTOCOL              → "protocol" (use assetType="protocol")
  LIBRARY               → asset skipped or "related-crypto-material"
  CERTIFICATE           → "certificate" (use assetType="certificate")
  KEY_MATERIAL          → "related-crypto-material"
  RANDOM                → "drbg"
  UNKNOWN               → "unknown"

PQC Algorithms (ML-KEM, ML-DSA, SLH-DSA):
  → "post-quantum" primitive, "algorithm" assetType

References:
  - CycloneDX 1.6 JSON schema: https://cyclonedx.org/docs/1.6/json/
  - docs/06_API_AND_DATA_CONTRACTS.md Section 3
  - core/models.py (CryptoAsset canonical schema)
"""

from __future__ import annotations

from typing import Optional

from core.models import CryptoAsset, PrimitiveType
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
    CDXAlgorithmProperties,
    CDXComponent,
    CDXCryptoProperties,
    CDXEvidence,
    CDXProperty,
)


# ---------------------------------------------------------------------------
# Authenticated Encryption modes — when present, prefer "ae" primitive
# ---------------------------------------------------------------------------
_AUTHENTICATED_ENCRYPTION_MODES = frozenset({"GCM", "CCM", "EAX", "SIV", "OCB"})

# ---------------------------------------------------------------------------
# Stream cipher families
# ---------------------------------------------------------------------------
_STREAM_CIPHER_FAMILIES = frozenset({"CHACHA", "RC4", "CHACHA20", "SALSA20"})

# ---------------------------------------------------------------------------
# PQC algorithm prefixes recognized as post-quantum
# ---------------------------------------------------------------------------
_PQC_ALGORITHM_PREFIXES = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})

# ---------------------------------------------------------------------------
# Key Encapsulation Mechanism algorithms
# ---------------------------------------------------------------------------
_KEM_ALGORITHMS = frozenset({"ML-KEM"})


def _is_pqc(algorithm: str) -> bool:
    """Return True if algorithm is a recognized finalized NIST PQC standard."""
    upper = algorithm.upper()
    for prefix in _PQC_ALGORITHM_PREFIXES:
        if upper.startswith(prefix):
            return True
    return False


def _is_kem(algorithm: str) -> bool:
    """Return True if algorithm is a Key Encapsulation Mechanism."""
    upper = algorithm.upper()
    for alg in _KEM_ALGORITHMS:
        if upper.startswith(alg):
            return True
    return False


def _is_stream_cipher(algorithm: str, family: Optional[str]) -> bool:
    """Return True if algorithm is a stream cipher."""
    upper_alg = algorithm.upper()
    upper_fam = (family or "").upper()
    return upper_fam in _STREAM_CIPHER_FAMILIES or "CHACHA" in upper_alg or "RC4" in upper_alg


def _map_primitive(
    primitive_type: PrimitiveType,
    algorithm: str,
    family: Optional[str],
    mode: Optional[str],
) -> str:
    """
    Map QNetra PrimitiveType + algorithm details to CycloneDX 1.6 primitive string.

    Priority:
      1. PQC algorithms always → "post-quantum" (unless it's ML-KEM → "kem")
      2. PrimitiveType routing
      3. Sub-classification within symmetric (ae vs block-cipher vs stream-cipher)

    Returns one of the official CycloneDX 1.6 primitive enum values.
    """
    # PQC KEM: ML-KEM → "kem"
    if _is_kem(algorithm):
        return CDX_PRIMITIVE_KEM

    # PQC signatures/others: ML-DSA, SLH-DSA → "post-quantum"
    if _is_pqc(algorithm):
        return CDX_PRIMITIVE_POST_QUANTUM

    if primitive_type == PrimitiveType.ASYMMETRIC_ENCRYPTION:
        return CDX_PRIMITIVE_PKE_ASYMM

    if primitive_type == PrimitiveType.DIGITAL_SIGNATURE:
        return CDX_PRIMITIVE_SIGNATURE

    if primitive_type == PrimitiveType.KEY_EXCHANGE:
        return CDX_PRIMITIVE_KEY_AGREE

    if primitive_type == PrimitiveType.SYMMETRIC_CIPHER:
        if _is_stream_cipher(algorithm, family):
            return CDX_PRIMITIVE_STREAM_CIPHER
        # Only classify as ae when mode is known and authenticated
        if mode and mode.upper() in _AUTHENTICATED_ENCRYPTION_MODES:
            return CDX_PRIMITIVE_AE
        return CDX_PRIMITIVE_BLOCK_CIPHER

    if primitive_type == PrimitiveType.HASH_FUNCTION:
        return CDX_PRIMITIVE_HASH

    if primitive_type == PrimitiveType.MAC:
        return CDX_PRIMITIVE_MAC

    if primitive_type == PrimitiveType.KDF:
        return CDX_PRIMITIVE_KDF

    if primitive_type == PrimitiveType.RANDOM:
        return CDX_PRIMITIVE_DRBG

    return CDX_PRIMITIVE_UNKNOWN


def _map_asset_type(primitive_type: PrimitiveType) -> str:
    """
    Map QNetra PrimitiveType to CycloneDX 1.6 cryptoProperties.assetType.
    """
    if primitive_type == PrimitiveType.CERTIFICATE:
        return CDX_ASSET_TYPE_CERTIFICATE

    if primitive_type == PrimitiveType.PROTOCOL:
        return CDX_ASSET_TYPE_PROTOCOL

    if primitive_type in (PrimitiveType.KEY_MATERIAL, PrimitiveType.LIBRARY):
        return CDX_ASSET_TYPE_RELATED_MATERIAL

    return CDX_ASSET_TYPE_ALGORITHM


def _build_display_name(asset: CryptoAsset) -> str:
    """
    Build a human-readable component name from normalized CryptoAsset fields.

    NO FABRICATION RULE: Only include parameters that are actually known.
    - AES with key_length=256, mode=GCM → "AES-256-GCM"
    - AES with mode=GCM but no key_length → "AES-GCM"
    - AES with no key_length, no mode → "AES"
    - RSA with key_length=2048 → "RSA-2048"
    - RSA with no key_length → "RSA"
    - ECDSA with curve=secp256r1 → "ECDSA-secp256r1"
    - ECDSA with no curve → "ECDSA"
    """
    # Library assets: use algorithm directly (it's already "Library: xxx")
    if asset.primitive_type == PrimitiveType.LIBRARY:
        return asset.algorithm

    base = asset.algorithm
    parts = [base]

    # For symmetric ciphers: key_length_bits, then mode
    if asset.primitive_type == PrimitiveType.SYMMETRIC_CIPHER:
        if asset.key_length_bits is not None:
            parts.append(str(asset.key_length_bits))
        if asset.mode is not None:
            parts.append(asset.mode.upper())
        name = "-".join(parts) if len(parts) > 1 else parts[0]
        return name

    # For asymmetric / key-exchange with key_length (RSA, DH)
    if asset.primitive_type in (
        PrimitiveType.ASYMMETRIC_ENCRYPTION,
        PrimitiveType.KEY_EXCHANGE,
    ):
        if asset.key_length_bits is not None:
            parts.append(str(asset.key_length_bits))
        elif asset.curve is not None:
            parts.append(asset.curve)
        return "-".join(parts) if len(parts) > 1 else parts[0]

    # For digital signatures: curve takes priority over key_length for ECC
    if asset.primitive_type == PrimitiveType.DIGITAL_SIGNATURE:
        fam = (asset.algorithm_family or "").upper()
        if fam in ("ECC", "ECDSA", "ED25519") or "ECDSA" in base.upper() or "ED25519" in base.upper():
            if asset.curve is not None:
                parts.append(asset.curve)
        elif asset.key_length_bits is not None:
            parts.append(str(asset.key_length_bits))
        return "-".join(parts) if len(parts) > 1 else parts[0]

    # Default: return algorithm name as-is (already normalized)
    return asset.algorithm


def _build_parameter_set_identifier(asset: CryptoAsset) -> Optional[str]:
    """
    Determine the parameterSetIdentifier for algorithmProperties.

    This is a string representation of the primary parameter distinguishing
    algorithm variants. Only set when the parameter is actually known.

    Examples:
      RSA-2048 → "2048"
      AES-256-GCM → "256"
      ECDSA P-256 → "secp256r1"
      RSA (unknown key) → None  ← NO FABRICATION
      AES (unknown key) → None  ← NO FABRICATION
    """
    if asset.key_length_bits is not None:
        return str(asset.key_length_bits)

    if asset.curve is not None:
        return asset.curve

    return None


def _build_nist_quantum_security_level(asset: CryptoAsset) -> Optional[int]:
    """
    Map effective quantum security bits to a NIST PQC Security Level (1-5).

    NIST Security Level mapping:
      Level 1: ≥ AES-128 security (≥ 128 bit preimage for symmetric)
      Level 2: ≥ SHA-256 collision security
      Level 3: ≥ AES-192 security
      Level 4: ≥ SHA-384 collision security
      Level 5: ≥ AES-256 security

    Conservatively:
      >= 256 bits → Level 5
      >= 192 bits → Level 3
      >= 128 bits → Level 1
      < 128 bits  → None (does not meet NIST minimum)

    Note: Returns None if quantum bits are unknown or the algorithm
    is Shor-vulnerable (where effective_quantum_security_bits=None by design).
    """
    qbits = asset.effective_quantum_security_bits
    if qbits is None:
        return None
    if qbits >= 256:
        return 5
    if qbits >= 192:
        return 3
    if qbits >= 128:
        return 1
    return None  # Below minimum — not a valid NIST level


def _build_evidence(asset: CryptoAsset) -> Optional[list[CDXEvidence]]:
    """
    Build CDXEvidence list from the asset's locations.

    Only includes location data that is actually present — no fabrication.
    Multiple locations are all preserved.
    """
    if not asset.locations and not asset.location:
        return None

    evidence_locations = asset.locations if asset.locations else [asset.location]

    evidence_list = []
    for loc in evidence_locations:
        if loc is None:
            continue
        ev = CDXEvidence(
            location=loc.file_path if loc.file_path else None,
            line=loc.start_line,
            symbol=loc.snippet if loc.snippet else None,
        )
        evidence_list.append(ev)

    return evidence_list if evidence_list else None


def _build_properties(asset: CryptoAsset) -> list[CDXProperty]:
    """
    Build the list of custom qnetra: namespaced properties.

    Maps QNetra-specific metadata fields to CycloneDX custom properties.
    All properties are namespaced with 'qnetra:' prefix to clearly identify
    them as QNetra extensions vs. standard CycloneDX fields.

    Only adds properties when the value is not None.
    Properties are sorted by name for deterministic output.
    """
    props: list[CDXProperty] = []

    # Core identity & traceability
    props.append(CDXProperty("qnetra:asset-id", asset.asset_id))
    props.append(CDXProperty("qnetra:confidence", str(round(asset.confidence_score, 4))))
    props.append(CDXProperty("qnetra:confidence-level", asset.confidence_level.value))

    # Supporting findings (for full audit trail)
    if asset.supporting_finding_ids:
        # Join with pipe separator for readability; IDs are UUIDs so safe
        props.append(CDXProperty(
            "qnetra:source-finding-ids",
            "|".join(sorted(asset.supporting_finding_ids)),
        ))

    # Classification metadata (serialized from pre-computed values only)
    if asset.quantum_threat_type is not None:
        props.append(CDXProperty("qnetra:quantum-threat-type", asset.quantum_threat_type))

    if asset.quantum_vulnerable is not None:
        props.append(CDXProperty("qnetra:quantum-vulnerable", str(asset.quantum_vulnerable).lower()))

    if asset.classical_security_status is not None:
        props.append(CDXProperty("qnetra:classical-security-status", asset.classical_security_status))

    if asset.quantum_security_status is not None:
        props.append(CDXProperty("qnetra:quantum-security-status", asset.quantum_security_status))

    if asset.effective_classical_security_bits is not None:
        props.append(CDXProperty(
            "qnetra:effective-classical-security-bits",
            str(asset.effective_classical_security_bits),
        ))

    if asset.effective_quantum_security_bits is not None:
        props.append(CDXProperty(
            "qnetra:effective-quantum-security-bits",
            str(asset.effective_quantum_security_bits),
        ))

    if asset.classification_notes is not None:
        props.append(CDXProperty("qnetra:classification-notes", asset.classification_notes))

    # Sort for deterministic output
    props.sort(key=lambda p: p.name)
    return props


def _should_skip_as_library(asset: CryptoAsset) -> bool:
    """
    Determine if the asset should be represented as a related-crypto-material
    (library detection) rather than a proper algorithm component.

    Library-type assets can still be emitted as related-crypto-material
    components but are handled with a different display name and no
    algorithmProperties.
    """
    return asset.primitive_type == PrimitiveType.LIBRARY


def map_asset_to_component(asset: CryptoAsset) -> CDXComponent:
    """
    Map a single canonical CryptoAsset to a CycloneDX 1.6 CDXComponent.

    This is the core mapping function. All field decisions are made here
    based strictly on the provided CryptoAsset — no external lookups,
    no database calls, no re-scanning.

    NO FABRICATION: If asset.key_length_bits is None, the parameterSetIdentifier
    is omitted. If asset.curve is None, the curve field is omitted.

    Args:
        asset: Canonical CryptoAsset from normalization + classification pipeline.

    Returns:
        CDXComponent ready for inclusion in a CDXBom.components list.
    """
    asset_type = _map_asset_type(asset.primitive_type)
    display_name = _build_display_name(asset)

    # Build cryptoProperties
    if asset_type == CDX_ASSET_TYPE_ALGORITHM:
        primitive = _map_primitive(
            asset.primitive_type,
            asset.algorithm,
            asset.algorithm_family,
            asset.mode,
        )
        algo_props = CDXAlgorithmProperties(
            primitive=primitive,
            parameter_set_identifier=_build_parameter_set_identifier(asset),
            curve=asset.curve,  # None if unknown → not included in output
            execution_environment="software-plain-text",
            mode=asset.mode.lower() if asset.mode else None,
            padding=asset.padding,
            classical_security_level=asset.effective_classical_security_bits,
            nist_quantum_security_level=_build_nist_quantum_security_level(asset),
        )
        crypto_props = CDXCryptoProperties(
            asset_type=CDX_ASSET_TYPE_ALGORITHM,
            algorithm_properties=algo_props,
            implementation_library=asset.implementation_library,
        )
    elif asset_type == CDX_ASSET_TYPE_PROTOCOL:
        crypto_props = CDXCryptoProperties(
            asset_type=CDX_ASSET_TYPE_PROTOCOL,
            implementation_library=asset.implementation_library,
        )
    elif asset_type == CDX_ASSET_TYPE_CERTIFICATE:
        crypto_props = CDXCryptoProperties(
            asset_type=CDX_ASSET_TYPE_CERTIFICATE,
            implementation_library=asset.implementation_library,
        )
    else:
        # RELATED_CRYPTO_MATERIAL (library, key material, RANDOM, UNKNOWN)
        crypto_props = CDXCryptoProperties(
            asset_type=CDX_ASSET_TYPE_RELATED_MATERIAL,
            implementation_library=asset.implementation_library,
        )

    # Build evidence list from locations
    evidence = _build_evidence(asset)

    # Build qnetra: custom properties
    properties = _build_properties(asset)

    return CDXComponent(
        type="cryptographic-asset",
        bom_ref=asset.asset_id,  # Use deterministic asset_id as bom-ref
        name=display_name,
        crypto_properties=crypto_props,
        evidence=evidence,
        properties=properties,
    )
