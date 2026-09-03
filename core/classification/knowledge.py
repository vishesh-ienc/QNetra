"""
QNetra Classification Knowledge Base
======================================

Extends scanner registry knowledge with classification-specific security assessments.
Answers the question: "What are the security properties of this cryptographic asset?"
(distinct from scanner registry question: "Is this a cryptographic algorithm?")

IMPORTANT SEPARATION:
  - scanners/registry/crypto_algorithms.py → detection + QuantumThreat enum
  - core/classification/knowledge.py        → security bit estimates, thresholds, profiles

All knowledge here must cite an authoritative source.
No values may be invented or assumed without documentation.

References:
  - NIST SP 800-57 Part 1 Rev 5 (2020): Key management recommendations
  - NIST SP 800-131A Rev 2 (2019): Transitioning algorithms and key lengths
  - Brassard, Høyer, Tapp (BHT, 1997): Quantum collision finding algorithm
  - docs/09_KNOWLEDGE_BASE.md (Shor, Grover, HNDL, PQC standards)
  - docs/05_ALGORITHMS.md (Alg-05: classification algorithm specification)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# RSA / DH Classical Security Bit Estimates (NIST SP 800-57 Part 1 Rev 5, Table 2)
# Maps modulus bit size → approximate classical security bits
# ---------------------------------------------------------------------------
_RSA_DH_SECURITY_TABLE: list[tuple[int, int]] = [
    (15360, 256),
    (7680, 192),
    (4096, 140),
    (3072, 128),
    (2048, 112),
    (1024, 80),
    (512, 56),   # approximate — 512-bit RSA is considered broken
]


def get_rsa_dh_classical_security_bits(key_bits: Optional[int]) -> Optional[int]:
    """
    Return NIST SP 800-57 Table 2 equivalent classical security bits for RSA/DH key size.
    Returns None if key_bits is None (unknown — must not fabricate).

    Reference: NIST SP 800-57 Part 1 Rev 5, Table 2.
    """
    if key_bits is None:
        return None
    for threshold, sec_bits in _RSA_DH_SECURITY_TABLE:
        if key_bits >= threshold:
            return sec_bits
    # Below 512-bit: treat as 56 bits (weak/broken territory)
    return 56


def get_rsa_classical_status(key_bits: Optional[int]) -> str:
    """
    Return ClassicalSecurityStatus value for RSA based on key size.
    Reference: NIST SP 800-131A Rev 2.

    Rules:
      >= 2048 bits → SECURE (NIST-acceptable minimum)
      1024 bits    → WEAK   (deprecated; NIST disallowed post-2015)
      < 1024 bits  → BROKEN (factored on commodity hardware)
      None         → UNKNOWN
    """
    if key_bits is None:
        return "UNKNOWN"
    if key_bits >= 2048:
        return "SECURE"
    if key_bits >= 1024:
        return "WEAK"
    return "BROKEN"


# ---------------------------------------------------------------------------
# ECC Curve Classical Security Bit Estimates
# Based on the elliptic curve discrete logarithm problem complexity.
# Reference: NIST SP 800-57 Table 2; BSI TR-02102-1.
# ---------------------------------------------------------------------------
_ECC_CURVE_CLASSICAL_BITS: dict[str, int] = {
    "secp256r1": 128,       # P-256, 256-bit → 128-bit classical security
    "secp384r1": 192,       # P-384, 384-bit → 192-bit classical security
    "secp521r1": 260,       # P-521, 521-bit → ~260-bit classical security
    "secp256k1": 128,       # Bitcoin curve, 256-bit → 128-bit classical security
    "Curve25519": 128,      # X25519/ECDH, 255-bit → ~128-bit classical security
    "Ed25519": 128,         # EdDSA, 255-bit → ~128-bit classical security
    "brainpoolP256r1": 128,
    "brainpoolP384r1": 192,
    "brainpoolP512r1": 256,
}


def get_ecc_classical_security_bits(curve: Optional[str]) -> Optional[int]:
    """Return classical security bits for an ECC curve. None if curve is unknown."""
    if curve is None:
        return None
    return _ECC_CURVE_CLASSICAL_BITS.get(curve)


def get_ecc_classical_status(curve: Optional[str]) -> str:
    """
    Return ClassicalSecurityStatus for ECC based on curve.
    All NIST-standard curves at 256+ bits provide ≥ 128-bit classical security (SECURE).
    Unknown curve → UNKNOWN.
    """
    if curve is None:
        return "UNKNOWN"
    bits = get_ecc_classical_security_bits(curve)
    if bits is None:
        return "UNKNOWN"
    # All curves in our registry have ≥ 128-bit security — SECURE classically
    return "SECURE"


# ---------------------------------------------------------------------------
# Symmetric Cipher Quantum Security (Grover's Algorithm)
# Reference: docs/09_KNOWLEDGE_BASE.md Section 1.2
#
# Grover's algorithm provides quadratic speedup: effective quantum security = key_bits / 2.
# This model applies to symmetric encryption where brute-force key search is the
# primary attack vector. The formula is key_bits // 2 (integer division).
#
# NIST post-quantum security threshold: 128-bit effective quantum security.
# AES-128 → 64-bit effective quantum → BELOW threshold (quantum_vulnerable = True)
# AES-192 → 96-bit effective quantum → BELOW threshold (quantum_vulnerable = True)
# AES-256 → 128-bit effective quantum → AT threshold (quantum_vulnerable = False)
# ---------------------------------------------------------------------------
QUANTUM_SECURITY_THRESHOLD_BITS: int = 128
"""NIST-recommended minimum effective quantum security (equivalent to AES-128 classical)."""


def get_symmetric_grover_quantum_bits(key_bits: Optional[int]) -> Optional[int]:
    """
    Effective quantum security bits for symmetric cipher under Grover's algorithm.
    Formula: effective_quantum_bits = key_bits // 2
    Returns None if key_bits is None (must not fabricate).
    """
    if key_bits is None:
        return None
    return key_bits // 2


def is_symmetric_quantum_vulnerable(key_bits: Optional[int]) -> Optional[bool]:
    """
    Determine quantum_vulnerable for a Grover-impacted symmetric cipher.
    True  → effective quantum bits < 128 (below NIST threshold)
    False → effective quantum bits >= 128
    None  → key_bits is None (cannot determine — do not fabricate)
    """
    if key_bits is None:
        return None
    effective = get_symmetric_grover_quantum_bits(key_bits)
    assert effective is not None  # key_bits was not None
    return effective < QUANTUM_SECURITY_THRESHOLD_BITS


# ---------------------------------------------------------------------------
# Hash Function Quantum Security Profiles
# Reference: BHT (Brassard-Høyer-Tapp, 1997) quantum collision algorithm.
#
# BHT reduces quantum collision finding to O(2^(n/3)) for n-bit hash output.
# This gives quantum collision resistance ≈ output_bits / 3 bits.
# This is the most conservative (smallest) quantum security bound for hash functions.
#
# Note: Grover preimage resistance is output_bits / 2 (better than BHT collision).
# We report BHT collision resistance as it is the more stringent and relevant bound
# for most cryptographic use cases (digital signatures, commitment schemes).
#
# Reference: NIST SP 800-107 Rev 1 (hash function security), docs/09_KNOWLEDGE_BASE.md.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HashQuantumProfile:
    """Security profile for hash function quantum classification."""
    canonical_name: str
    classical_status: str          # ClassicalSecurityStatus value
    classical_collision_bits: Optional[int]  # Collision resistance (birthday): output_bits / 2
    quantum_collision_bits: Optional[int]    # BHT quantum collision: output_bits / 3
    quantum_note: str
    quantum_vulnerable: Optional[bool]


HASH_QUANTUM_PROFILES: dict[str, HashQuantumProfile] = {
    "MD5": HashQuantumProfile(
        canonical_name="MD5",
        classical_status="BROKEN",
        classical_collision_bits=0,    # Collision attacks feasible (Wang et al. 2004)
        quantum_collision_bits=None,   # Moot — already classically broken
        quantum_note=(
            "MD5 is classically broken — practical collision attacks exist on commodity hardware "
            "(Wang et al., 2004; MD5CRK project). "
            "Quantum computing amplifies this vulnerability but classical cryptanalysis is the primary threat. "
            "Quantum threat type: CLASSICALLY_BROKEN."
        ),
        quantum_vulnerable=True,       # Classically broken → unconditionally vulnerable
    ),
    "SHA-1": HashQuantumProfile(
        canonical_name="SHA-1",
        classical_status="BROKEN",
        classical_collision_bits=0,    # SHAttered attack (Stevens et al., 2017)
        quantum_collision_bits=None,   # Moot — classically broken
        quantum_note=(
            "SHA-1 is classically broken — full collision demonstrated by SHAttered attack (2017). "
            "NIST deprecated SHA-1 for digital signatures; prohibited after 2030. "
            "Quantum threat type: CLASSICALLY_BROKEN. Quantum analysis is secondary."
        ),
        quantum_vulnerable=True,
    ),
    "SHA-256": HashQuantumProfile(
        canonical_name="SHA-256",
        classical_status="SECURE",
        classical_collision_bits=128,  # 256-bit output → 128-bit classical collision resistance
        quantum_collision_bits=85,     # BHT: 256/3 ≈ 85 bits quantum collision resistance
        quantum_note=(
            "SHA-256 quantum security analysis: "
            "Collision resistance via BHT algorithm: ~85 bits (2^(256/3) ≈ 2^85). "
            "Preimage resistance via Grover: ~128 bits (2^(256/2) = 2^128). "
            "The BHT-based collision resistance bound (85 bits) is below the NIST 128-bit "
            "post-quantum threshold, making SHA-256 quantum-vulnerable in collision-resistance contexts. "
            "Threat type: GROVER_BIT_HALVING. "
            "Reference: BHT (1997), docs/09_KNOWLEDGE_BASE.md §1.2."
        ),
        quantum_vulnerable=True,   # 85-bit BHT < 128-bit NIST threshold
    ),
    "SHA-384": HashQuantumProfile(
        canonical_name="SHA-384",
        classical_status="SECURE",
        classical_collision_bits=192,  # 384-bit output → 192-bit classical collision resistance
        quantum_collision_bits=128,    # BHT: 384/3 = 128 bits quantum collision resistance
        quantum_note=(
            "SHA-384 quantum security analysis: "
            "Collision resistance via BHT algorithm: ~128 bits (2^(384/3) = 2^128). "
            "Exactly meets NIST 128-bit post-quantum threshold. "
            "Classified as QUANTUM_RESISTANT per registry and NIST guidance. "
            "Threat type: QUANTUM_RESISTANT. "
            "Reference: BHT (1997), docs/09_KNOWLEDGE_BASE.md §1.2."
        ),
        quantum_vulnerable=False,   # 128-bit BHT = NIST threshold → SAFE
    ),
    "SHA-512": HashQuantumProfile(
        canonical_name="SHA-512",
        classical_status="SECURE",
        classical_collision_bits=256,  # 512-bit output → 256-bit classical collision resistance
        quantum_collision_bits=171,    # BHT: 512/3 ≈ 171 bits quantum collision resistance
        quantum_note=(
            "SHA-512 quantum security analysis: "
            "Collision resistance via BHT algorithm: ~171 bits (2^(512/3) ≈ 2^171). "
            "Well above NIST 128-bit post-quantum threshold. "
            "Classified as QUANTUM_RESISTANT per registry and NIST guidance. "
            "Threat type: QUANTUM_RESISTANT. "
            "Reference: BHT (1997), docs/09_KNOWLEDGE_BASE.md §1.2."
        ),
        quantum_vulnerable=False,
    ),
    "SHA-3": HashQuantumProfile(
        canonical_name="SHA-3",
        classical_status="SECURE",
        classical_collision_bits=None,  # Variant-dependent (SHA3-256 → 128, SHA3-512 → 256)
        quantum_collision_bits=None,    # Variant-dependent; estimated via BHT per output length
        quantum_note=(
            "SHA-3 / Keccak family — variant-dependent quantum security. "
            "SHA3-256: BHT quantum collision resistance ~85 bits. "
            "SHA3-384: BHT quantum collision resistance ~128 bits (SAFE). "
            "SHA3-512: BHT quantum collision resistance ~171 bits (SAFE). "
            "Classified as QUANTUM_RESISTANT per NIST guidelines for the SHA-3 family. "
            "Threat type: QUANTUM_RESISTANT (family-level classification)."
        ),
        quantum_vulnerable=False,   # Family-level: NIST classifies SHA-3 as quantum-resistant
    ),
}


def get_hash_quantum_profile(algorithm: str) -> Optional[HashQuantumProfile]:
    """
    Lookup hash quantum profile by canonical algorithm name.
    Returns None if algorithm is not in the hash profile database.
    """
    return HASH_QUANTUM_PROFILES.get(algorithm)


# ---------------------------------------------------------------------------
# Algorithms unconditionally broken classically (key-size independent)
# Reference: NIST, IETF, CryptoSuites registry
# ---------------------------------------------------------------------------
UNCONDITIONALLY_BROKEN: frozenset[str] = frozenset({
    "MD5",    # Collision attacks feasible
    "SHA-1",  # SHAttered collision (2017)
    "DES",    # 56-bit key, trivially brute-forced
    "RC4",    # Prohibited by RFC 7465 (2015)
    "SSL",    # All SSL versions formally prohibited (RFC 7568)
})

# Algorithms deprecated but not fully broken (effective security below recommended threshold)
UNCONDITIONALLY_WEAK: frozenset[str] = frozenset({
    "3DES",  # Effective 112-bit (triple-DES), deprecated by NIST SP 800-131A Rev 2
})

# NIST finalized PQC — always SECURE classically and QUANTUM_RESISTANT
FINALIZED_NIST_PQC: frozenset[str] = frozenset({
    "ML-KEM",   # NIST FIPS 203
    "ML-DSA",   # NIST FIPS 204
    "SLH-DSA",  # NIST FIPS 205
})

# Primitive types where quantum classification does not apply
NOT_QUANTUM_APPLICABLE_PRIMITIVE_TYPES: frozenset[str] = frozenset({
    "LIBRARY", "CERTIFICATE", "KEY_MATERIAL", "RANDOM",
})
