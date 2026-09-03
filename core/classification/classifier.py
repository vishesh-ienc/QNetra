"""
QNetra Classification Engine — Phase 2 Milestone 2.2
======================================================

Enriches canonical CryptoAsset objects with deterministic cryptographic and
quantum threat classification across three orthogonal dimensions:

  1. Classical Security Status: SECURE, WEAK, BROKEN, UNKNOWN
  2. Quantum Threat Type:       from scanner registry (QuantumThreat enum values)
  3. Quantum Security Status:   SAFE, DEGRADED, CRITICAL, UNKNOWN

Design Invariants:
  - Deterministic: same input always produces same output
  - No fabrication: unknown parameters remain unknown (None is never replaced with a guess)
  - Orthogonal dimensions: classical and quantum are classified independently
  - Shor-vulnerable quantum_bits: always None (Shor breaks the problem, not merely reduces bits)
  - Grover quantum_bits: key_bits // 2 (only when key_bits is known)
  - Hash quantum_bits: BHT-based collision resistance (explicitly noted)
  - Side-effect scoped: classify() mutates CryptoAsset fields; classify_one() is pure

Scope Boundary:
  - Risk scoring (risk_score, risk_severity): Phase 3 only — NOT implemented here
  - Mosca timeline: Phase 3 only — NOT implemented here
  - PQC recommendations: Phase 3 only — NOT implemented here
  - Migration priorities: Phase 3 only — NOT implemented here

References:
  - docs/05_ALGORITHMS.md Alg-05 (Primitive & Quantum Threat Categorization)
  - docs/06_API_AND_DATA_CONTRACTS.md Section 2.2 (CryptoAsset schema)
  - docs/08_DECISIONS_AND_LOG.md DEC-011 (schema change)
  - docs/09_KNOWLEDGE_BASE.md (quantum attack models)
  - core/classification/knowledge.py (all numeric estimates and thresholds)
"""

from __future__ import annotations

import logging
from typing import Optional

from core.classification.knowledge import (
    FINALIZED_NIST_PQC,
    NOT_QUANTUM_APPLICABLE_PRIMITIVE_TYPES,
    UNCONDITIONALLY_BROKEN,
    UNCONDITIONALLY_WEAK,
    get_ecc_classical_security_bits,
    get_ecc_classical_status,
    get_hash_quantum_profile,
    get_rsa_classical_status,
    get_rsa_dh_classical_security_bits,
    get_symmetric_grover_quantum_bits,
    is_symmetric_quantum_vulnerable,
    QUANTUM_SECURITY_THRESHOLD_BITS,
)
from core.classification.models import (
    ClassicalSecurityStatus,
    ClassificationResult,
    QuantumSecurityStatus,
)
from core.models import CryptoAsset, PrimitiveType

logger = logging.getLogger(__name__)

# Canonical QuantumThreat string values from scanners.registry.crypto_algorithms.
# We use string constants to avoid circular imports with the scanner registry.
_QT_SHOR = "SHOR_POLYNOMIAL_BREAK"
_QT_GROVER = "GROVER_BIT_HALVING"
_QT_BROKEN = "CLASSICALLY_BROKEN"
_QT_RESISTANT = "QUANTUM_RESISTANT"
_QT_NOT_APPLICABLE = "NOT_APPLICABLE"
_QT_UNKNOWN = "UNKNOWN"


def _build_unknown_result() -> ClassificationResult:
    """Return classification result for an unknown or unrecognizable algorithm."""
    return ClassificationResult(
        classical_security_status=ClassicalSecurityStatus.UNKNOWN,
        effective_classical_security_bits=None,
        classical_notes="Algorithm cannot be identified from available evidence.",
        quantum_threat_str=_QT_UNKNOWN,
        quantum_security_status=QuantumSecurityStatus.UNKNOWN,
        quantum_vulnerable=None,
        effective_quantum_security_bits=None,
        quantum_notes="Quantum classification requires algorithm identification.",
        classification_confidence="UNKNOWN",
    )


def _build_not_applicable_result(prim_type_value: str) -> ClassificationResult:
    """Return result for primitive types that don't have direct quantum classification."""
    return ClassificationResult(
        classical_security_status=ClassicalSecurityStatus.UNKNOWN,
        effective_classical_security_bits=None,
        classical_notes=(
            f"Primitive type '{prim_type_value}' is not a directly classifiable cryptographic primitive. "
            "Security depends on contained components."
        ),
        quantum_threat_str=_QT_NOT_APPLICABLE,
        quantum_security_status=QuantumSecurityStatus.UNKNOWN,
        quantum_vulnerable=False,  # Not a threat surface in itself
        effective_quantum_security_bits=None,
        quantum_notes=(
            f"Primitive type '{prim_type_value}' does not have a direct quantum threat classification. "
            "Inspect contained primitives for quantum vulnerability."
        ),
        classification_confidence="HIGH",  # HIGH because the rule is clear, not because we have details
    )


class ClassificationEngine:
    """
    Deterministic cryptographic and quantum threat classifier for CryptoAsset objects.

    Public API:
      classify(assets)  → List[CryptoAsset]  (enriches in-place, returns same list)
      classify_one(asset) → ClassificationResult  (pure function, no mutation)

    Usage:
      engine = ClassificationEngine()
      classified_assets = engine.classify(normalized_assets)

    Alternatively, to inspect without mutating:
      result = engine.classify_one(asset)
    """

    def classify(self, assets: list[CryptoAsset]) -> list[CryptoAsset]:
        """
        Enrich each CryptoAsset in-place with classification fields.

        Mutates the following CryptoAsset fields:
          - quantum_vulnerable
          - quantum_threat_type
          - classical_security_status
          - quantum_security_status
          - effective_classical_security_bits
          - effective_quantum_security_bits
          - classification_notes

        Does NOT mutate: risk_score, risk_severity, recommendation_id (Phase 3 scope).

        Args:
            assets: List of normalized CryptoAsset objects.

        Returns:
            The same list with all assets enriched.
        """
        classified_count = 0
        for asset in assets:
            try:
                result = self.classify_one(asset)
                self._enrich_asset(asset, result)
                classified_count += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Classification failed for asset %s (%s): %s",
                    asset.asset_id, asset.algorithm, exc,
                )
        logger.debug("ClassificationEngine: classified %d/%d assets", classified_count, len(assets))
        return assets

    def classify_one(self, asset: CryptoAsset) -> ClassificationResult:
        """
        Classify a single CryptoAsset deterministically.

        Pure function: does not mutate asset.

        Routing order:
          1. Not-applicable primitive types (LIBRARY, CERTIFICATE, etc.)
          2. Unknown algorithm
          3. Finalized NIST PQC algorithms
          4. Protocol (TLS, SSL, SSH)
          5. Hash functions
          6. Symmetric ciphers (AES, ChaCha20, 3DES, DES, RC4)
          7. MACs (HMAC, CMAC, Poly1305)
          8. KDFs (PBKDF2, bcrypt, Argon2, HKDF, scrypt)
          9. Public-key cryptography (RSA, DSA, DH, ECDSA, ECDH, Ed25519)
          10. Fallback: unknown

        Args:
            asset: Normalized CryptoAsset object.

        Returns:
            ClassificationResult with all classification dimensions populated.
        """
        prim = asset.primitive_type.value
        algorithm = asset.algorithm or ""
        family = (asset.algorithm_family or "").upper()

        # 1. Not-applicable primitive types
        if prim in NOT_QUANTUM_APPLICABLE_PRIMITIVE_TYPES:
            return _build_not_applicable_result(prim)

        # 2. Unknown algorithm
        if algorithm in ("", "Unknown Algorithm", "UNKNOWN"):
            return _build_unknown_result()

        # 3. Finalized NIST PQC — highest priority for the listed families
        if family in FINALIZED_NIST_PQC or algorithm.upper().split("-")[0] in FINALIZED_NIST_PQC:
            return self._classify_pqc(asset)

        # 4. Protocol
        if prim == "PROTOCOL":
            return self._classify_protocol(asset)

        # 5. Hash functions
        if prim == "HASH_FUNCTION":
            return self._classify_hash(asset)

        # 6. Symmetric ciphers
        if prim == "SYMMETRIC_CIPHER":
            return self._classify_symmetric(asset)

        # 7. MACs
        if prim == "MAC":
            return self._classify_mac(asset)

        # 8. KDFs
        if prim == "KDF":
            return self._classify_kdf(asset)

        # 9. Public-key (ASYMMETRIC_ENCRYPTION, DIGITAL_SIGNATURE, KEY_EXCHANGE)
        if prim in ("ASYMMETRIC_ENCRYPTION", "DIGITAL_SIGNATURE", "KEY_EXCHANGE"):
            # Check for PQC algorithms classified under these primitive types
            if family in FINALIZED_NIST_PQC:
                return self._classify_pqc(asset)
            return self._classify_public_key(asset)

        # 10. Fallback
        logger.debug("ClassificationEngine: no route for prim=%s alg=%s — returning UNKNOWN", prim, algorithm)
        return _build_unknown_result()

    # ------------------------------------------------------------------
    # Private classification methods — one per cryptographic family
    # ------------------------------------------------------------------

    def _classify_pqc(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify NIST finalized PQC algorithms: ML-KEM, ML-DSA, SLH-DSA."""
        alg = asset.algorithm
        family = asset.algorithm_family or alg.split("-")[0]
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.SECURE,
            effective_classical_security_bits=None,  # PQC security levels differ from classical bit counts
            classical_notes=(
                f"{alg} is a finalized NIST Post-Quantum Cryptography standard. "
                f"Classical security analysis is not applicable in the same way as classical algorithms."
            ),
            quantum_threat_str=_QT_RESISTANT,
            quantum_security_status=QuantumSecurityStatus.SAFE,
            quantum_vulnerable=False,
            effective_quantum_security_bits=None,
            quantum_notes=(
                f"{alg} ({family}) is a NIST finalized PQC standard (FIPS 203/204/205). "
                "Designed to resist both classical and quantum attacks. "
                "Effective quantum security level is defined by the NIST parameter set, "
                "not reducible to a single bit count comparable to symmetric key sizes."
            ),
            classification_confidence="HIGH",
        )

    def _classify_protocol(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify protocol assets (TLS, SSH). Security depends on negotiated cipher suite."""
        alg = asset.algorithm
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            effective_classical_security_bits=None,
            classical_notes=(
                f"Protocol '{alg}' security depends on the negotiated cipher suite and key exchange. "
                "Cannot classify without knowing the configured cryptographic primitives."
            ),
            quantum_threat_str=_QT_NOT_APPLICABLE,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
            effective_quantum_security_bits=None,
            quantum_notes=(
                f"Protocol '{alg}' quantum security depends on the negotiated cipher suite. "
                "Inspect the specific key exchange and symmetric cipher for quantum classification."
            ),
            classification_confidence="LOW",
        )

    def _classify_hash(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify hash function using BHT-based quantum collision resistance profiles."""
        alg = asset.algorithm
        profile = get_hash_quantum_profile(alg)

        if profile is None:
            # Hash not in profile database — unknown
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.UNKNOWN,
                effective_classical_security_bits=None,
                classical_notes=f"Hash function '{alg}' is not in the classification knowledge base.",
                quantum_threat_str=_QT_UNKNOWN,
                quantum_security_status=QuantumSecurityStatus.UNKNOWN,
                quantum_vulnerable=None,
                effective_quantum_security_bits=None,
                quantum_notes=f"Hash function '{alg}' quantum profile unavailable.",
                classification_confidence="UNKNOWN",
            )

        # Determine quantum_threat_str from classical status and quantum vulnerability
        if profile.classical_status == "BROKEN":
            qt_str = _QT_BROKEN
        elif profile.quantum_vulnerable is False:
            qt_str = _QT_RESISTANT
        else:
            qt_str = _QT_GROVER

        # Determine quantum_security_status
        if profile.classical_status == "BROKEN" or profile.quantum_vulnerable is True:
            if profile.quantum_collision_bits is None or profile.quantum_collision_bits < QUANTUM_SECURITY_THRESHOLD_BITS:
                qss = QuantumSecurityStatus.CRITICAL if profile.classical_status == "BROKEN" else QuantumSecurityStatus.DEGRADED
            else:
                qss = QuantumSecurityStatus.SAFE
        elif profile.quantum_vulnerable is False:
            qss = QuantumSecurityStatus.SAFE
        else:
            qss = QuantumSecurityStatus.UNKNOWN

        # More precisely: CRITICAL for classically broken, DEGRADED for grover-below-threshold
        if profile.classical_status == "BROKEN":
            qss = QuantumSecurityStatus.CRITICAL

        classical_bits = profile.classical_collision_bits if profile.classical_status != "BROKEN" else None

        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus(profile.classical_status),
            effective_classical_security_bits=classical_bits,
            classical_notes=(
                f"{alg} classical security: {profile.classical_status}. "
                + (f"Collision resistance: {profile.classical_collision_bits} bits." if classical_bits else "")
            ),
            quantum_threat_str=qt_str,
            quantum_security_status=qss,
            quantum_vulnerable=profile.quantum_vulnerable,
            effective_quantum_security_bits=profile.quantum_collision_bits,
            quantum_notes=profile.quantum_note,
            classification_confidence="HIGH",
        )

    def _classify_symmetric(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify symmetric ciphers: AES, ChaCha20, 3DES, DES, RC4."""
        alg = asset.algorithm
        family = (asset.algorithm_family or "").upper()
        alg_upper = alg.upper()
        key_bits = asset.key_length_bits

        # Unconditionally broken ciphers (DES, RC4)
        broken_families = {"DES", "RC4"}
        if family in broken_families or any(b in alg_upper for b in broken_families):
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.BROKEN,
                effective_classical_security_bits=None,
                classical_notes=f"{alg} is unconditionally broken classically.",
                quantum_threat_str=_QT_BROKEN,
                quantum_security_status=QuantumSecurityStatus.CRITICAL,
                quantum_vulnerable=True,
                effective_quantum_security_bits=None,
                quantum_notes=f"{alg} is classically broken — quantum threat is secondary.",
                classification_confidence="HIGH",
            )

        # 3DES — WEAK (effective 112-bit, deprecated NIST SP 800-131A Rev 2)
        if family in UNCONDITIONALLY_WEAK or "3DES" in alg_upper or "TRIPLE" in alg_upper:
            # 3DES effective key = 112 bits (2-key) → Grover: 56 bits effective
            effective_classical = 112
            effective_quantum = 56  # 112 // 2
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.WEAK,
                effective_classical_security_bits=effective_classical,
                classical_notes=(
                    "3DES has an effective key strength of 112 bits (two-key) or 168 bits (three-key). "
                    "Deprecated by NIST SP 800-131A Rev 2 — disallowed for new applications."
                ),
                quantum_threat_str=_QT_GROVER,
                quantum_security_status=QuantumSecurityStatus.DEGRADED,
                quantum_vulnerable=True,
                effective_quantum_security_bits=effective_quantum,
                quantum_notes=(
                    "3DES Grover quantum analysis: effective key ~112 bits → "
                    "~56 bits effective quantum security (key_bits // 2). "
                    "Below 128-bit NIST quantum threshold."
                ),
                classification_confidence="HIGH",
            )

        # ChaCha20 — always 256-bit key
        if "CHACHA" in alg_upper:
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.SECURE,
                effective_classical_security_bits=256,
                classical_notes="ChaCha20 uses a fixed 256-bit key — classically secure.",
                quantum_threat_str=_QT_GROVER,
                quantum_security_status=QuantumSecurityStatus.SAFE,
                quantum_vulnerable=False,
                effective_quantum_security_bits=128,  # 256 // 2
                quantum_notes=(
                    "ChaCha20 Grover analysis: 256-bit key → 128-bit effective quantum security. "
                    "Meets NIST 128-bit post-quantum threshold."
                ),
                classification_confidence="HIGH",
            )

        # AES — parameter-dependent
        if "AES" in alg_upper or family == "AES":
            return self._classify_aes(asset)

        # Unknown symmetric — cannot classify without more info
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            effective_classical_security_bits=None,
            classical_notes=f"Symmetric cipher '{alg}' not in classification knowledge base.",
            quantum_threat_str=_QT_UNKNOWN,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
            effective_quantum_security_bits=None,
            quantum_notes=f"Symmetric cipher '{alg}' quantum profile unavailable.",
            classification_confidence="UNKNOWN",
        )

    def _classify_aes(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify AES ciphers — parameter-dependent on key size."""
        alg = asset.algorithm
        key_bits = asset.key_length_bits

        # Classical status: all AES key sizes are SECURE classically (NIST-approved)
        # AES-128 and AES-192 are classically secure, just not recommended for long-term
        classical_status = ClassicalSecurityStatus.SECURE
        classical_bits = key_bits  # AES classical security = key length
        classical_notes = (
            f"AES classical security: SECURE. "
            + (f"Key length: {key_bits} bits — NIST-approved AES variant." if key_bits
               else "Key length unknown — cannot assess specific variant.")
        )

        # Quantum: Grover — effective quantum = key_bits // 2
        effective_quantum = get_symmetric_grover_quantum_bits(key_bits)
        vulnerable = is_symmetric_quantum_vulnerable(key_bits)

        if key_bits is None:
            qss = QuantumSecurityStatus.UNKNOWN
            quantum_vulnerable = None
            qnote = (
                f"AES quantum analysis: Grover's algorithm halves effective key security. "
                "Key size unknown — cannot estimate effective quantum security bits. "
                "Provide key_length_bits to classify. "
                "Do not assume a default key size."
            )
            confidence = "LOW"
        elif effective_quantum is not None and effective_quantum >= QUANTUM_SECURITY_THRESHOLD_BITS:
            qss = QuantumSecurityStatus.SAFE
            quantum_vulnerable = False
            qnote = (
                f"AES-{key_bits} Grover analysis: {key_bits}-bit key → "
                f"~{effective_quantum}-bit effective quantum security (key_bits // 2). "
                f"Meets NIST {QUANTUM_SECURITY_THRESHOLD_BITS}-bit post-quantum threshold."
            )
            confidence = "HIGH"
        else:
            qss = QuantumSecurityStatus.DEGRADED
            quantum_vulnerable = True
            qnote = (
                f"AES-{key_bits} Grover analysis: {key_bits}-bit key → "
                f"~{effective_quantum}-bit effective quantum security (key_bits // 2). "
                f"Below NIST {QUANTUM_SECURITY_THRESHOLD_BITS}-bit post-quantum threshold."
            )
            confidence = "HIGH"

        return ClassificationResult(
            classical_security_status=classical_status,
            effective_classical_security_bits=classical_bits,
            classical_notes=classical_notes,
            quantum_threat_str=_QT_GROVER,
            quantum_security_status=qss,
            quantum_vulnerable=quantum_vulnerable,
            effective_quantum_security_bits=effective_quantum,
            quantum_notes=qnote,
            classification_confidence=confidence,
        )

    def _classify_mac(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify MAC algorithms: HMAC, CMAC, Poly1305."""
        alg = asset.algorithm
        alg_upper = alg.upper()

        # Poly1305 (always 256-bit key, paired with ChaCha20)
        if "POLY1305" in alg_upper:
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.SECURE,
                effective_classical_security_bits=None,
                classical_notes="Poly1305 is a one-time MAC — secure when used with unique keys.",
                quantum_threat_str=_QT_GROVER,
                quantum_security_status=QuantumSecurityStatus.SAFE,
                quantum_vulnerable=False,
                effective_quantum_security_bits=None,
                quantum_notes=(
                    "Poly1305 paired with ChaCha20 provides quantum security comparable to "
                    "ChaCha20-Poly1305 (128-bit effective quantum security)."
                ),
                classification_confidence="HIGH",
            )

        # HMAC — check for underlying hash in algorithm name
        if "HMAC" in alg_upper:
            return self._classify_hmac(asset)

        # CMAC (AES-based)
        if "CMAC" in alg_upper or "OMAC" in alg_upper:
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.SECURE,
                effective_classical_security_bits=None,
                classical_notes="CMAC/OMAC is AES-based — classically secure.",
                quantum_threat_str=_QT_GROVER,
                quantum_security_status=QuantumSecurityStatus.UNKNOWN,
                quantum_vulnerable=None,
                effective_quantum_security_bits=None,
                quantum_notes=(
                    "CMAC quantum security depends on the AES key length used. "
                    "Key length not directly available from the MAC identifier."
                ),
                classification_confidence="LOW",
            )

        # Generic unknown MAC
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            effective_classical_security_bits=None,
            classical_notes=f"MAC '{alg}' not in classification knowledge base.",
            quantum_threat_str=_QT_UNKNOWN,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
            effective_quantum_security_bits=None,
            quantum_notes=f"MAC '{alg}' quantum profile unavailable.",
            classification_confidence="UNKNOWN",
        )

    def _classify_hmac(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify HMAC — determine security from underlying hash if identifiable."""
        alg = asset.algorithm
        alg_upper = alg.upper()

        # Try to identify underlying hash from the algorithm name
        underlying_hash: Optional[str] = None
        for candidate in ("SHA-512", "SHA-384", "SHA-256", "SHA-1", "MD5", "SHA-3"):
            if candidate.replace("-", "") in alg_upper.replace("-", "").replace("_", ""):
                underlying_hash = candidate
                break

        if underlying_hash:
            hash_profile = get_hash_quantum_profile(underlying_hash)
            if hash_profile:
                # Quantum security follows the underlying hash
                qt_str = _QT_GROVER if hash_profile.classical_status != "BROKEN" else _QT_BROKEN
                if hash_profile.quantum_vulnerable is False:
                    qt_str = _QT_RESISTANT
                return ClassificationResult(
                    classical_security_status=ClassicalSecurityStatus(hash_profile.classical_status),
                    effective_classical_security_bits=hash_profile.classical_collision_bits,
                    classical_notes=(
                        f"{alg} uses {underlying_hash} as underlying hash. "
                        f"Classical security follows {underlying_hash}: {hash_profile.classical_status}."
                    ),
                    quantum_threat_str=qt_str,
                    quantum_security_status=(
                        QuantumSecurityStatus.SAFE if hash_profile.quantum_vulnerable is False
                        else (QuantumSecurityStatus.CRITICAL if hash_profile.classical_status == "BROKEN"
                              else QuantumSecurityStatus.DEGRADED)
                    ),
                    quantum_vulnerable=hash_profile.quantum_vulnerable,
                    effective_quantum_security_bits=hash_profile.quantum_collision_bits,
                    quantum_notes=(
                        f"{alg} quantum security follows {underlying_hash}: {hash_profile.quantum_note}"
                    ),
                    classification_confidence="HIGH",
                )

        # Underlying hash unknown
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            effective_classical_security_bits=None,
            classical_notes=(
                f"{alg}: underlying hash algorithm not identifiable from algorithm name. "
                "Classical security depends on the hash function used."
            ),
            quantum_threat_str=_QT_GROVER,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
            effective_quantum_security_bits=None,
            quantum_notes=(
                f"{alg}: underlying hash algorithm unknown. "
                "Quantum security cannot be estimated without knowing the hash function. "
                "Grover/BHT impact applies to the underlying hash — specify HMAC-SHA256 etc."
            ),
            classification_confidence="LOW",
        )

    def _classify_kdf(self, asset: CryptoAsset) -> ClassificationResult:
        """Classify key derivation functions: PBKDF2, bcrypt, scrypt, Argon2, HKDF."""
        alg = asset.algorithm
        alg_upper = alg.upper()

        # Argon2 — memory-hard, quantum-resistant
        if "ARGON2" in alg_upper:
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.SECURE,
                effective_classical_security_bits=None,
                classical_notes="Argon2 is a memory-hard KDF — winner of the Password Hashing Competition.",
                quantum_threat_str=_QT_RESISTANT,
                quantum_security_status=QuantumSecurityStatus.SAFE,
                quantum_vulnerable=False,
                effective_quantum_security_bits=None,
                quantum_notes=(
                    "Argon2 is classified as quantum-resistant per the scanner registry. "
                    "Memory-hardness limits quantum speedup. "
                    "Effective quantum security level depends on configured parameters."
                ),
                classification_confidence="HIGH",
            )

        # HKDF — security depends on underlying HMAC/hash
        if "HKDF" in alg_upper:
            return ClassificationResult(
                classical_security_status=ClassicalSecurityStatus.SECURE,
                effective_classical_security_bits=None,
                classical_notes="HKDF security depends on the underlying hash function.",
                quantum_threat_str=_QT_GROVER,
                quantum_security_status=QuantumSecurityStatus.UNKNOWN,
                quantum_vulnerable=None,
                effective_quantum_security_bits=None,
                quantum_notes=(
                    "HKDF quantum security depends on the underlying hash function. "
                    "Grover's algorithm applies to the hash. Specify hash variant for classification."
                ),
                classification_confidence="LOW",
            )

        # bcrypt, scrypt, PBKDF2 — Grover-impacted, key-stretch KDFs
        for kdf_name in ("BCRYPT", "SCRYPT", "PBKDF2"):
            if kdf_name in alg_upper:
                return ClassificationResult(
                    classical_security_status=ClassicalSecurityStatus.SECURE,
                    effective_classical_security_bits=None,
                    classical_notes=f"{alg} is a secure password-hashing/key-derivation function.",
                    quantum_threat_str=_QT_GROVER,
                    quantum_security_status=QuantumSecurityStatus.UNKNOWN,
                    quantum_vulnerable=None,
                    effective_quantum_security_bits=None,
                    quantum_notes=(
                        f"{alg} quantum security depends on cost parameters and output length. "
                        "Grover's algorithm applies to brute-force key search. "
                        "Cannot estimate quantum bits without specific output length."
                    ),
                    classification_confidence="LOW",
                )

        # Generic KDF
        return ClassificationResult(
            classical_security_status=ClassicalSecurityStatus.UNKNOWN,
            effective_classical_security_bits=None,
            classical_notes=f"KDF '{alg}' not in classification knowledge base.",
            quantum_threat_str=_QT_UNKNOWN,
            quantum_security_status=QuantumSecurityStatus.UNKNOWN,
            quantum_vulnerable=None,
            effective_quantum_security_bits=None,
            quantum_notes=f"KDF '{alg}' quantum profile unavailable.",
            classification_confidence="UNKNOWN",
        )

    def _classify_public_key(self, asset: CryptoAsset) -> ClassificationResult:
        """
        Classify all Shor-vulnerable public-key cryptography: RSA, DSA, DH, ECDSA, ECDH, Ed25519.

        All public-key systems based on integer factorization or discrete logarithm
        (including elliptic curve discrete log) are broken by Shor's polynomial-time algorithm.

        CRITICAL INVARIANT: effective_quantum_security_bits = None for ALL Shor-vulnerable assets.
        Shor's algorithm completely solves the underlying mathematical problem — it is not a
        mere quadratic speedup that reduces key bits. There is no meaningful "N bits of residual
        quantum security" for Shor-vulnerable algorithms.
        """
        alg = asset.algorithm
        family = (asset.algorithm_family or "").upper()
        key_bits = asset.key_length_bits
        curve = asset.curve

        # Classical security depends on the algorithm family and parameters
        classical_status, classical_bits, classical_notes, confidence = self._assess_public_key_classical(
            alg, family, key_bits, curve
        )

        return ClassificationResult(
            classical_security_status=classical_status,
            effective_classical_security_bits=classical_bits,
            classical_notes=classical_notes,
            quantum_threat_str=_QT_SHOR,
            quantum_security_status=QuantumSecurityStatus.CRITICAL,
            quantum_vulnerable=True,
            # Never fabricate quantum bits for Shor-vulnerable assets
            effective_quantum_security_bits=None,
            quantum_notes=(
                f"{alg} is vulnerable to Shor's algorithm (polynomial-time quantum attack). "
                "Shor's algorithm completely solves the underlying mathematical hardness assumption "
                "(integer factorization / elliptic curve discrete logarithm). "
                "Effective quantum security bits are not applicable — the problem is fundamentally broken. "
                "Reference: docs/09_KNOWLEDGE_BASE.md §1.1."
            ),
            classification_confidence=confidence,
        )

    def _assess_public_key_classical(
        self,
        alg: str,
        family: str,
        key_bits: Optional[int],
        curve: Optional[str],
    ) -> tuple[ClassicalSecurityStatus, Optional[int], str, str]:
        """Return (classical_status, classical_bits, classical_notes, confidence) for public-key algorithms."""
        alg_upper = alg.upper()

        # RSA
        if family == "RSA" or "RSA" in alg_upper:
            classical_status_str = get_rsa_classical_status(key_bits)
            classical_bits = get_rsa_dh_classical_security_bits(key_bits)
            if key_bits:
                notes = (
                    f"RSA-{key_bits} classical security: {classical_status_str} "
                    f"(~{classical_bits} bits equivalent, NIST SP 800-57 Table 2)."
                )
                confidence = "HIGH"
            else:
                notes = "RSA key size unknown — classical security cannot be estimated."
                confidence = "LOW"
            return ClassicalSecurityStatus(classical_status_str), classical_bits, notes, confidence

        # DSA
        if family == "DSA" or "DSA" in alg_upper and "ECDSA" not in alg_upper:
            classical_status_str = get_rsa_classical_status(key_bits)
            classical_bits = get_rsa_dh_classical_security_bits(key_bits)
            if key_bits:
                notes = (
                    f"DSA-{key_bits} classical security: {classical_status_str} "
                    f"(~{classical_bits} bits equivalent per NIST SP 800-57)."
                )
                confidence = "HIGH"
            else:
                notes = "DSA key size unknown — classical security cannot be estimated."
                confidence = "LOW"
            return ClassicalSecurityStatus(classical_status_str), classical_bits, notes, confidence

        # DH / Diffie-Hellman
        if family == "DH" or "DH" in alg_upper and "ECDH" not in alg_upper:
            classical_status_str = get_rsa_classical_status(key_bits)
            classical_bits = get_rsa_dh_classical_security_bits(key_bits)
            if key_bits:
                notes = (
                    f"DH-{key_bits} classical security: {classical_status_str} "
                    f"(~{classical_bits} bits equivalent per NIST SP 800-57)."
                )
                confidence = "HIGH"
            else:
                notes = "DH key size unknown — classical security cannot be estimated."
                confidence = "LOW"
            return ClassicalSecurityStatus(classical_status_str), classical_bits, notes, confidence

        # ECC (ECDSA, ECDH, Ed25519)
        if family in ("ECC", "ECDSA", "ECDH", "ED25519") or any(
            x in alg_upper for x in ("ECDSA", "ECDH", "ED25519", "EC ")
        ):
            classical_status_str = get_ecc_classical_status(curve)
            classical_bits = get_ecc_classical_security_bits(curve)
            if curve:
                notes = (
                    f"{alg} classical security: SECURE "
                    f"(curve {curve} ≈ {classical_bits}-bit equivalent per NIST SP 800-57)."
                )
                confidence = "HIGH"
            else:
                notes = f"{alg}: curve unknown — classical security cannot be estimated precisely."
                confidence = "LOW"
            return ClassicalSecurityStatus(classical_status_str), classical_bits, notes, confidence

        # Generic public key — fallback
        return ClassicalSecurityStatus.UNKNOWN, None, f"{alg}: public key algorithm type not fully resolved.", "LOW"

    # ------------------------------------------------------------------
    # Asset enrichment
    # ------------------------------------------------------------------

    @staticmethod
    def _enrich_asset(asset: CryptoAsset, result: ClassificationResult) -> None:
        """Enrich CryptoAsset in-place with classification result. Does not touch Phase 3 fields."""
        asset.quantum_vulnerable = result.quantum_vulnerable
        asset.quantum_threat_type = result.quantum_threat_str
        asset.classical_security_status = result.classical_security_status.value
        asset.quantum_security_status = result.quantum_security_status.value
        asset.effective_classical_security_bits = result.effective_classical_security_bits
        asset.effective_quantum_security_bits = result.effective_quantum_security_bits
        asset.classification_notes = (
            f"[{result.classification_confidence}] "
            f"Classical [{result.classical_security_status.value}]: {result.classical_notes} | "
            f"Quantum [{result.quantum_security_status.value}]: {result.quantum_notes}"
        )
