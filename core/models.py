"""
QNetra Core Domain Models — Canonical Cryptographic Asset Schema
================================================================

Defines the canonical data contracts for Phase 2 Normalization and downstream
intelligence engines (CBOM, Quantum Risk, Mosca, PQC Recommendations):
  - CryptoAsset: Canonical normalized cryptographic asset derived from RawFinding(s).
  - PrimitiveType: Functional cryptographic primitive categorization.
  - SupportingFindingEvidence: Evidence summary retained from supporting raw findings.

Contract Reference:
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.2)
  - docs/10_API_CONTRACT.md (Section 8)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from scanners.framework.models import ConfidenceLevel, FileLocation


class PrimitiveType(str, Enum):
    """
    Functional cryptographic primitive classification conforming to
    docs/06_API_AND_DATA_CONTRACTS.md Section 2.2.
    """
    ASYMMETRIC_ENCRYPTION = "ASYMMETRIC_ENCRYPTION"  # RSA, ElGamal
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"          # ECDSA, Ed25519, RSA-PSS, ML-DSA
    KEY_EXCHANGE = "KEY_EXCHANGE"                   # ECDH, X25519, DH, ML-KEM
    SYMMETRIC_CIPHER = "SYMMETRIC_CIPHER"           # AES, ChaCha20, 3DES, DES
    HASH_FUNCTION = "HASH_FUNCTION"                 # SHA-256, SHA-3, SHA-1, MD5
    MAC = "MAC"                                     # HMAC, Poly1305, CMAC
    KDF = "KDF"                                     # PBKDF2, HKDF, bcrypt, scrypt, Argon2
    PROTOCOL = "PROTOCOL"                           # TLS, SSH, SSL
    LIBRARY = "LIBRARY"                             # Cryptographic library / shared object
    CERTIFICATE = "CERTIFICATE"                     # X.509, PEM certificate
    KEY_MATERIAL = "KEY_MATERIAL"                   # Private/public keys, hardcoded keys
    RANDOM = "RANDOM"                               # PRNG, CSPRNG
    UNKNOWN = "UNKNOWN"                             # Unclassified primitive


class SupportingFindingEvidence(BaseModel):
    """
    Structured evidence from a RawFinding supporting a canonical CryptoAsset.
    Preserves audit traceability from high-level asset back to concrete scanner discoveries.
    """
    finding_id: str = Field(description="Unique ID of the raw scanner finding.")
    scanner_name: str = Field(description="Name of the scanner that discovered this evidence.")
    discovery_method: str = Field(description="Method used (AST, REGEX, API_CALL, etc.).")
    raw_symbol: str = Field(description="Raw symbol, API call, or string matched.")
    location: FileLocation = Field(description="Location where evidence was found.")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Finding confidence score.")
    confidence_rationale: str = Field(description="Finding-level confidence rationale.")


class CryptoAsset(BaseModel):
    """
    Canonical Normalized Cryptographic Asset.

    A CryptoAsset represents a distinct, verified cryptographic construction or
    usage discovered in target software. It is synthesized by `core.normalization`
    from one or more `RawFinding` evidence records.

    ARCHITECTURAL INVARIANT:
    RawFinding = individual piece of scanner evidence (unprocessed).
    CryptoAsset = canonical cryptographic asset derived from one or more RawFindings.

    Contract References:
      - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.2)
      - docs/10_API_CONTRACT.md (Section 8)
    """

    # --- Identity & Canonical Classification ---
    asset_id: str = Field(
        description="Deterministic canonical UUID for this cryptographic asset (UUIDv5)."
    )
    algorithm: str = Field(
        description="Standardized canonical algorithm name (e.g. 'RSA', 'AES-256-GCM', 'SHA-256', 'ECDSA')."
    )
    algorithm_family: Optional[str] = Field(
        default=None,
        description="High-level algorithm family (e.g. 'RSA', 'AES', 'SHA', 'ECC', 'CHACHA')."
    )
    primitive_type: PrimitiveType = Field(
        description="Standardized functional cryptographic primitive category."
    )

    # --- Technical Cryptographic Parameters ---
    key_length_bits: Optional[int] = Field(
        default=None,
        description="Key size or modulus length in bits (e.g. 2048, 256, 128)."
    )
    curve: Optional[str] = Field(
        default=None,
        description="Elliptic curve name (e.g. 'secp256r1', 'Ed25519', 'Curve25519')."
    )
    mode: Optional[str] = Field(
        default=None,
        description="Cipher mode of operation (e.g. 'GCM', 'CBC', 'CTR')."
    )
    padding: Optional[str] = Field(
        default=None,
        description="Padding scheme (e.g. 'PKCS1_OAEP', 'PKCS7', 'NoPadding')."
    )
    implementation_library: Optional[str] = Field(
        default=None,
        description="Underlying implementation library (e.g. 'pycryptodome', 'OpenSSL', 'BouncyCastle')."
    )

    # --- Source Location & Traceability ---
    location: FileLocation = Field(
        description="Primary location of the asset in scanned code or artifact."
    )
    locations: list[FileLocation] = Field(
        default_factory=list,
        description="All contributing source locations across supporting findings."
    )
    supporting_finding_ids: list[str] = Field(
        default_factory=list,
        description="List of RawFinding IDs that corroborate and support this asset."
    )
    supporting_findings: list[SupportingFindingEvidence] = Field(
        default_factory=list,
        description="Detailed evidence records preserved from each supporting RawFinding."
    )

    # --- Confidence ---
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Aggregated discovery confidence score [0.0, 1.0]."
    )
    confidence_level: ConfidenceLevel = Field(
        description="Descriptive confidence tier (VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW)."
    )
    confidence_rationale: str = Field(
        description="Explainable explanation of how confidence was derived and aggregated."
    )

    # --- Downstream Placeholders (Phase 2 Classification & Phase 3 Risk) ---
    quantum_vulnerable: Optional[bool] = Field(
        default=None,
        description="Phase 2 Classification: True if vulnerable to Shor or Grover (per documented rules)."
    )
    quantum_threat_type: Optional[str] = Field(
        default=None,
        description="Phase 2 Classification: QuantumThreat.value, 'NOT_APPLICABLE', or 'UNKNOWN'."
    )

    # --- Phase 2.2 Classification Fields (Populated by core.classification) ---
    classical_security_status: Optional[str] = Field(
        default=None,
        description="Classical cryptographic security status: SECURE, WEAK, BROKEN, UNKNOWN."
    )
    quantum_security_status: Optional[str] = Field(
        default=None,
        description="Post-quantum security level: SAFE, DEGRADED, CRITICAL, UNKNOWN."
    )
    effective_classical_security_bits: Optional[int] = Field(
        default=None,
        description=(
            "Estimated classical security bits (NIST SP 800-57): "
            "RSA-2048 ≈ 112, ECDSA P-256 ≈ 128, AES-256 = 256. "
            "None if parameters insufficient to estimate."
        )
    )
    effective_quantum_security_bits: Optional[int] = Field(
        default=None,
        description=(
            "Estimated effective quantum security bits. "
            "None for Shor-vulnerable algorithms (fundamentally broken, not merely reduced). "
            "Grover-impacted symmetric: key_bits // 2. "
            "Hash functions: BHT collision resistance estimate. "
            "None if key parameters unknown."
        )
    )
    classification_notes: Optional[str] = Field(
        default=None,
        description="Deterministic classification rationale combining classical and quantum notes."
    )

    # --- Phase 3 Risk Engine Placeholders ---
    risk_score: Optional[int] = Field(
        default=None,
        description="Phase 3 Risk Engine placeholder: deterministic risk score (0-100)."
    )
    risk_severity: Optional[str] = Field(
        default=None,
        description="Phase 3 Risk Engine placeholder: CRITICAL, HIGH, MEDIUM, LOW."
    )
    recommendation_id: Optional[str] = Field(
        default=None,
        description="Phase 3 Recommendation placeholder: link to PQC recommendation."
    )

    # --- Additional Metadata ---
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata (symbols, binary format, container context, extracted parameters)."
    )

    def to_api_dict(self) -> dict[str, Any]:
        """
        Export dictionary conforming strictly to docs/10_API_CONTRACT.md Section 8.
        Includes Phase 2.2 classification fields.
        """
        return {
            "asset_id": self.asset_id,
            "algorithm": self.algorithm,
            "algorithm_family": self.algorithm_family,
            "primitive_type": self.primitive_type.value,
            "key_length_bits": self.key_length_bits,
            "curve": self.curve,
            "mode": self.mode,
            "padding": self.padding,
            "implementation_library": self.implementation_library,
            "location": {
                "file_path": self.location.file_path,
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "byte_offset": self.location.byte_offset,
                "snippet": self.location.snippet,
            },
            # Phase 2.2 Classification fields
            "classical_security_status": self.classical_security_status,
            "quantum_vulnerable": self.quantum_vulnerable,
            "quantum_threat_type": self.quantum_threat_type,
            "quantum_security_status": self.quantum_security_status,
            "effective_classical_security_bits": self.effective_classical_security_bits,
            "effective_quantum_security_bits": self.effective_quantum_security_bits,
            "classification_notes": self.classification_notes,
            # Confidence
            "confidence_score": round(self.confidence_score, 4),
            "confidence_level": self.confidence_level.value,
            # Phase 3 Risk placeholders
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity,
            "supporting_finding_ids": self.supporting_finding_ids,
            "recommendation_id": self.recommendation_id,
        }
