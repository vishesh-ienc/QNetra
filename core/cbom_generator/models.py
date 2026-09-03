"""
QNetra CBOM Generator — Internal Domain Models for CycloneDX 1.6 CBOM Output
==============================================================================

Defines lightweight, CBOM-specific Python dataclasses representing the
CycloneDX 1.6 JSON document structure.

These models are the OUTPUT CONTRACT of the CBOM generation layer.
They represent the serialized form of cryptographic assets within a CycloneDX
document and are DISTINCT from the input CryptoAsset model.

DESIGN NOTE:
  - These models do NOT duplicate crypto intelligence from CryptoAsset.
  - They are thin serialization-oriented containers whose field names align
    with the official CycloneDX 1.6 JSON property names.
  - All Optional fields default to None and are omitted from output when None.

CycloneDX 1.6 Reference:
  https://cyclonedx.org/docs/1.6/json/
  ECMA-424 1st Edition, April 2024

Cryptographic asset types (component.type = "cryptographic-asset"):
  - assetType: "algorithm" | "certificate" | "protocol" | "related-crypto-material"

algorithmProperties.primitive values (official enum from CycloneDX 1.6):
  ae | block-cipher | drbg | ekep | hash | kdf | key-agree | kem |
  mac | pke | post-quantum | public-key-encryption | signature | stream-cipher | unknown

algorithmProperties.executionEnvironment values:
  hardware | software-plain-text | software-encrypted-ram | software-tee | ota | other | unknown

Contract Reference:
  docs/06_API_AND_DATA_CONTRACTS.md Section 3 (CycloneDX 1.6 CBOM Schema Alignment)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# CycloneDX 1.6 Primitive Enum Values (algorithmProperties.primitive)
# Defined from the official CycloneDX 1.6 specification.
# Only these values are permitted in the CBOM output.
# ---------------------------------------------------------------------------

CDX_PRIMITIVE_AE = "ae"                       # Authenticated Encryption (e.g. AES-GCM)
CDX_PRIMITIVE_BLOCK_CIPHER = "block-cipher"   # Block cipher (e.g. AES-CBC, DES)
CDX_PRIMITIVE_DRBG = "drbg"                   # Deterministic Random Bit Generator
CDX_PRIMITIVE_EKEP = "ekep"                   # Extended Key Encapsulation Protocol
CDX_PRIMITIVE_HASH = "hash"                   # Hash functions (SHA-256, MD5, etc.)
CDX_PRIMITIVE_KDF = "kdf"                     # Key Derivation Functions (HKDF, PBKDF2)
CDX_PRIMITIVE_KEY_AGREE = "key-agree"         # Key Agreement (ECDH, DH, X25519)
CDX_PRIMITIVE_KEM = "kem"                     # Key Encapsulation Mechanism (ML-KEM)
CDX_PRIMITIVE_MAC = "mac"                     # Message Authentication Code (HMAC)
CDX_PRIMITIVE_PKE = "pke"                     # Public Key Encryption / Generic PKC
CDX_PRIMITIVE_POST_QUANTUM = "post-quantum"   # Post-Quantum algorithms (ML-DSA, SLH-DSA)
CDX_PRIMITIVE_PKE_ASYMM = "public-key-encryption"  # Asymmetric encryption (RSA-OAEP)
CDX_PRIMITIVE_SIGNATURE = "signature"         # Digital signatures (RSA, ECDSA, Ed25519)
CDX_PRIMITIVE_STREAM_CIPHER = "stream-cipher" # Stream ciphers (ChaCha20, RC4)
CDX_PRIMITIVE_UNKNOWN = "unknown"             # Unknown / unclassifiable

# ---------------------------------------------------------------------------
# CycloneDX 1.6 Asset Type Enum Values (cryptoProperties.assetType)
# ---------------------------------------------------------------------------
CDX_ASSET_TYPE_ALGORITHM = "algorithm"
CDX_ASSET_TYPE_CERTIFICATE = "certificate"
CDX_ASSET_TYPE_PROTOCOL = "protocol"
CDX_ASSET_TYPE_RELATED_MATERIAL = "related-crypto-material"  # Keys, tokens, secrets


# ---------------------------------------------------------------------------
# Internal Dataclasses representing CycloneDX 1.6 CBOM structures
# ---------------------------------------------------------------------------

@dataclass
class CDXAlgorithmProperties:
    """
    CycloneDX 1.6 algorithmProperties structure.

    Represents the cryptographic parameters of an algorithm asset.
    Only non-None fields are included in serialized output to preserve
    the no-fabrication policy from CryptoAsset.
    """
    primitive: str                           # Required; must be a CDX_PRIMITIVE_* value
    parameter_set_identifier: Optional[str] = None  # e.g. "2048" for RSA, "256" for AES
    curve: Optional[str] = None             # EC curve name e.g. "secp256r1"
    execution_environment: str = "software-plain-text"  # Default to plaintext software
    implementation_platform: Optional[str] = None
    certified_level: Optional[str] = None
    mode: Optional[str] = None              # Cipher mode: "cbc", "gcm", etc. (lowercase for CDX)
    padding: Optional[str] = None           # Padding scheme
    crypto_functions: Optional[list[str]] = None  # e.g. ["encrypt", "decrypt"]
    classical_security_level: Optional[int] = None  # Effective classical security bits
    nist_quantum_security_level: Optional[int] = None  # NIST quantum security level (1-5)


@dataclass
class CDXEvidence:
    """
    CycloneDX 1.6 evidence structure for cryptographic asset occurrence.

    Preserves traceability from CBOM component back to scanner discovery.
    Represents an occurrence location within the codebase.
    """
    location: Optional[str] = None   # File path (e.g. "src/crypto.py")
    line: Optional[int] = None       # Source code line number
    symbol: Optional[str] = None     # Raw symbol / code snippet (if available)


@dataclass
class CDXCryptoProperties:
    """
    CycloneDX 1.6 cryptoProperties structure (the core crypto metadata block).

    This is the primary block within a cryptographic-asset component that
    describes the asset's cryptographic properties.
    """
    asset_type: str = CDX_ASSET_TYPE_ALGORITHM  # Default is algorithm
    algorithm_properties: Optional[CDXAlgorithmProperties] = None
    oid: Optional[str] = None               # ASN.1 OID where applicable
    related_crypto_material_type: Optional[str] = None   # For key material assets
    implementation_library: Optional[str] = None  # Underlying library


@dataclass
class CDXProperty:
    """
    CycloneDX 1.6 property (custom name-value metadata extension).

    Used for QNetra-specific metadata that does not have a canonical
    CycloneDX field. Namespaced under "qnetra:" prefix.
    """
    name: str    # e.g. "qnetra:asset-id", "qnetra:confidence"
    value: str   # String value


@dataclass
class CDXComponent:
    """
    CycloneDX 1.6 component with type="cryptographic-asset".

    Represents one cryptographic asset in the CBOM components list.
    """
    type: str = "cryptographic-asset"           # Always "cryptographic-asset" for CBOM
    bom_ref: str = ""                           # Unique reference within BOM (asset_id)
    name: str = ""                              # Human-readable asset name
    crypto_properties: Optional[CDXCryptoProperties] = None
    evidence: Optional[list[CDXEvidence]] = None  # Source locations / occurrences
    properties: Optional[list[CDXProperty]] = None  # Custom qnetra: metadata


@dataclass
class CDXToolComponent:
    """
    CycloneDX 1.6 tool component (used in metadata.tools).
    Identifies QNetra as the CBOM generating tool.
    """
    type: str = "application"
    name: str = "QNetra ECDAT Engine"
    version: str = "1.0.0"
    description: str = "Enterprise Cryptographic Discovery & Analysis Tool"


@dataclass
class CDXMetadataTools:
    """
    CycloneDX 1.6 metadata.tools structure.
    """
    components: list[CDXToolComponent] = field(default_factory=list)


@dataclass
class CDXMetadata:
    """
    CycloneDX 1.6 BOM metadata block.

    Note: timestamp is intentionally omitted from serialization when
    deterministic_mode=True to ensure identical output on repeated runs.
    """
    tools: Optional[CDXMetadataTools] = None
    timestamp: Optional[str] = None  # ISO 8601 datetime; omitted in deterministic mode


@dataclass
class CDXBom:
    """
    Top-level CycloneDX 1.6 Bill of Materials document.

    Structure:
      {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:<uuid>",
        "version": 1,
        "metadata": { ... },
        "components": [ ... ]
      }
    """
    bom_format: str = "CycloneDX"
    spec_version: str = "1.6"
    serial_number: Optional[str] = None    # urn:uuid:<uuid4> — may be None for deterministic mode
    version: int = 1
    metadata: Optional[CDXMetadata] = None
    components: list[CDXComponent] = field(default_factory=list)
