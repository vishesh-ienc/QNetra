"""
QNetra Recommendation Engine — Centralized PQC Knowledge Base
==============================================================

Authoritative single source of truth for all PQC algorithm definitions,
mapping tables, parameter selection policies, hybrid construction definitions,
and rationale string templates used by the Recommendation Engine.

Design Principles (PROJECT_RULES.md RULE-002, RULE-003):
  - No magic strings scattered in mapping functions.
  - Zero stochastic or ML-based decisions — purely deterministic table lookups.
  - Only finalized NIST PQC standards:
      * ML-KEM — FIPS 203 (Key Encapsulation Mechanism)
      * ML-DSA — FIPS 204 (Digital Signature Algorithm)
      * SLH-DSA — FIPS 205 (Stateless Hash-Based Digital Signature)
  - No draft or candidate algorithms as primary recommendations.
  - Parameter selection policy is explicit and documented as assumptions.
  - Unknown/unrecognized algorithms NEVER receive fabricated recommendations.

Contract References:
  - docs/05_ALGORITHMS.md (Alg-08: PQC Recommendation Engine)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.5)
  - docs/09_KNOWLEDGE_BASE.md (Section 3: PQC Standards)

Sources:
  - NIST FIPS 203 (2024). Module-Lattice-Based Key-Encapsulation Mechanism Standard.
  - NIST FIPS 204 (2024). Module-Lattice-Based Digital Signature Standard.
  - NIST FIPS 205 (2024). Stateless Hash-Based Digital Signature Standard.
  - NIST SP 800-131A Rev 2 (2019). Transitioning the Use of Cryptographic Algorithms.
  - NIST SP 800-57 Part 1 Rev 5 (2020). Key Management Recommendations.
"""

from __future__ import annotations

from core.models import PrimitiveType

# ===========================================================================
# 1. NIST-Approved PQC Algorithm Definitions
#    Only standardized (not draft) algorithms. Finalized FIPS 2024.
# ===========================================================================

# ML-KEM Parameter Sets (NIST FIPS 203)
# Security categories per NIST: Category 1 (128-bit), Category 3 (192-bit), Category 5 (256-bit)
ML_KEM_512 = "ML-KEM-512"    # NIST Category 1 — 128-bit classical security equivalent
ML_KEM_768 = "ML-KEM-768"    # NIST Category 3 — 192-bit classical security equivalent (DEFAULT)
ML_KEM_1024 = "ML-KEM-1024"  # NIST Category 5 — 256-bit classical security equivalent

# ML-DSA Parameter Sets (NIST FIPS 204)
ML_DSA_44 = "ML-DSA-44"      # NIST Category 2 — ~128-bit security
ML_DSA_65 = "ML-DSA-65"      # NIST Category 3 — ~192-bit security (DEFAULT)
ML_DSA_87 = "ML-DSA-87"      # NIST Category 5 — ~256-bit security

# SLH-DSA Parameter Sets (NIST FIPS 205 — stateless hash-based)
# Signature-focused fallback; larger signatures but no security-assumption conflicts
SLH_DSA_SHA2_128S = "SLH-DSA-SHA2-128s"   # Compact-sized; ~128-bit security
SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"   # Fast-signing variant; ~128-bit security
SLH_DSA_SHA2_192S = "SLH-DSA-SHA2-192s"   # Compact-sized; ~192-bit security
SLH_DSA_SHAKE_128S = "SLH-DSA-SHAKE-128s" # SHAKE-based; ~128-bit security

# NIST FIPS Standard Labels
FIPS_203 = "NIST FIPS 203"
FIPS_204 = "NIST FIPS 204"
FIPS_205 = "NIST FIPS 205"

# PQC Algorithm Prefixes (used for ALREADY_PQC detection)
# Must remain consistent with core/mosca_engine/knowledge.py PQC_ALGORITHM_PREFIXES
PQC_ALGORITHM_PREFIXES: frozenset[str] = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})


# ===========================================================================
# 2. Parameter Selection Policy
#    DEFAULT: ML-KEM-768 (Category 3, equivalent to AES-192)
#    HIGH-SECURITY: ML-KEM-1024 (Category 5) when key >= 3072 RSA or ECC >= 384 bits
#    Embedded/constrained: ML-KEM-512 (Category 1) - NEVER selected automatically;
#    caller must explicitly indicate constrained context.
#    All selections are documented as EXPLICIT ASSUMPTIONS in rationale.
# ===========================================================================

# RSA key size threshold for high-security ML-KEM-1024 selection
RSA_HIGH_SECURITY_KEY_THRESHOLD: int = 3072  # RSA >= 3072 bits -> consider ML-KEM-1024

# ECC key size (in bits, from curve bit length) for high-security selection
ECC_HIGH_SECURITY_BITS_THRESHOLD: int = 384  # P-384/brainpoolP384 -> consider ML-KEM-1024

# ML-DSA fallback: for high-security RSA/ECDSA, escalate to ML-DSA-87
DSA_HIGH_SECURITY_KEY_THRESHOLD: int = 3072

# ===========================================================================
# 3. Hybrid Construction Definitions
#    Only explicitly supported hybrid constructions per project contracts.
#    Do NOT invent hybrid constructions not listed here.
# ===========================================================================

# Key Exchange / KEM hybrid construction
HYBRID_X25519_ML_KEM_768 = "X25519 + ML-KEM-768"

# Digital Signature hybrid construction
HYBRID_ED25519_ML_DSA_65 = "Ed25519 + ML-DSA-65"

# Asymmetric encryption (RSA for key transport) hybrid
HYBRID_RSA_ML_KEM_768 = "RSA-OAEP + ML-KEM-768"


# ===========================================================================
# 4. Algorithm Family Normalization Map
#    Maps normalized algorithm names (upper-cased) to a canonical family key.
#    Used for routing recommendation mapping by algorithm family.
# ===========================================================================

# Algorithms that are Shor-vulnerable (public-key: RSA, ECC, DH families)
SHOR_VULNERABLE_KEY_EXCHANGE_FAMILIES: frozenset[str] = frozenset({
    "DH",
    "ECDH",
    "X25519",
    "X448",
    "CURVE25519",
})

SHOR_VULNERABLE_SIGNATURE_FAMILIES: frozenset[str] = frozenset({
    "ECDSA",
    "DSA",
    "ED25519",
    "ED448",
    "RSASSA",
    "RSA-PSS",
    "RSAPSS",
})

SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES: frozenset[str] = frozenset({
    "RSA",
    "ELGAMAL",
})

# Algorithms known to be classically broken (immediate action required)
CLASSICALLY_BROKEN_ALGORITHMS: frozenset[str] = frozenset({
    "MD5",
    "SHA-1",
    "SHA1",
    "DES",
    "3DES",
    "TRIPLEDES",
    "RC4",
    "RC2",
    "MD4",
    "MD2",
    "RIPEMD-128",
})

# Hash algorithms that need quantum-driven upgrades (not algorithmic replacement)
HASH_UPGRADE_MAP: dict[str, str] = {
    # SHA-256 is Grover-impacted (128-bit pre-image, ~85-bit collision resistance BHT)
    # -> upgrade to SHA-384 or SHA-512
    "SHA-256": "SHA-384",
    "SHA-224": "SHA-256",
    "SHA-1": "SHA-256",
    "SHA1": "SHA-256",
    "MD5": "SHA-256",
    "MD4": "SHA-256",
    "RIPEMD-160": "SHA-256",
}

# Symmetric cipher upgrade map (key-length upgrades only; not algorithm replacement)
SYMMETRIC_UPGRADE_MAP: dict[str, str] = {
    # AES-128 halves to 64-bit security under Grover -> upgrade to AES-256
    "AES-128": "AES-256",
    "AES-128-ECB": "AES-256-GCM",
    "AES-128-CBC": "AES-256-GCM",
    "AES-128-CTR": "AES-256-GCM",
    "AES-128-GCM": "AES-256-GCM",
    "AES-128-CCM": "AES-256-GCM",
}

# NOT_APPLICABLE primitive types — no PQC migration required
NOT_APPLICABLE_PRIMITIVE_TYPES: frozenset[PrimitiveType] = frozenset({
    PrimitiveType.LIBRARY,
    PrimitiveType.RANDOM,
})


# ===========================================================================
# 5. Guidance Step Templates
#    Reusable actionable guidance steps for each recommendation category.
# ===========================================================================

GUIDANCE_ML_KEM_DIRECT: list[str] = [
    "Identify all code paths where the current key exchange or encryption algorithm is invoked.",
    "Replace the classical key exchange mechanism with ML-KEM using a FIPS 203-compliant library.",
    "Update key and ciphertext buffer sizes to accommodate ML-KEM's larger public keys and ciphertexts.",
    "Run test suite and integration tests to verify functionality after replacement.",
    "Update certificate or key distribution infrastructure if applicable.",
]

GUIDANCE_ML_KEM_HYBRID: list[str] = [
    "Identify all code paths using the current key exchange or encryption mechanism.",
    "Implement a hybrid KEM that combines X25519 (classical) and ML-KEM-768 (post-quantum).",
    "Use the hybrid shared secret as the KDF input to derive final symmetric keys.",
    "Update protocol negotiation to advertise hybrid KEM capability to endpoints.",
    "Plan full deprecation of the classical-only path once PQC-capable endpoints reach majority.",
    "Update key and ciphertext buffer sizes to accommodate ML-KEM's larger payloads.",
]

GUIDANCE_ML_DSA_DIRECT: list[str] = [
    "Identify all signing and verification code paths using the current signature algorithm.",
    "Replace the signature algorithm with ML-DSA using a FIPS 204-compliant library.",
    "Update signature buffer and storage to accommodate ML-DSA's larger signature sizes.",
    "Re-sign any stored artifacts, certificates, or persistent objects using the new algorithm.",
    "Run test suite and integration tests to verify signing and verification after replacement.",
]

GUIDANCE_ML_DSA_HYBRID: list[str] = [
    "Identify all signing and verification paths using the current signature algorithm.",
    "Implement dual-signature (classical + ML-DSA) during the hybrid transition period.",
    "Update verification logic to accept either legacy or hybrid signatures during transition.",
    "Plan full migration to ML-DSA-only once hybrid capability is validated across all verifiers.",
]

GUIDANCE_SLH_DSA_FALLBACK: list[str] = [
    "Use SLH-DSA as a stateless hash-based signature if ML-DSA is not suitable for this deployment.",
    "Note: SLH-DSA produces significantly larger signatures than ML-DSA; validate storage/bandwidth constraints.",
    "Replace signing path with SLH-DSA using a FIPS 205-compliant library.",
    "Run regression tests after replacement.",
]

GUIDANCE_HASH_UPGRADE: list[str] = [
    "Identify all usage of the current hash function in code and storage.",
    "Replace or upgrade to a stronger hash function from the SHA-2 or SHA-3 family.",
    "Verify that dependent MACs, KDFs, and signature schemes are compatible with the upgraded hash.",
    "Re-hash any stored digests or checksums that must remain valid.",
]

GUIDANCE_SYMMETRIC_UPGRADE: list[str] = [
    "Upgrade the symmetric cipher key length to 256 bits to retain adequate post-Grover security.",
    "If using AES-128, re-key all sessions and storage with AES-256.",
    "Ensure the cipher mode is authenticated encryption (AES-256-GCM preferred).",
    "Update key derivation functions to produce 256-bit outputs.",
]

GUIDANCE_ALREADY_PQC: list[str] = [
    "No immediate migration action required — this asset already uses a NIST-approved PQC algorithm.",
    "Monitor NIST for updated parameter set recommendations or deprecations.",
]

GUIDANCE_NO_MIGRATION: list[str] = [
    "No PQC algorithm migration is required for this asset type.",
    "Continue monitoring for changes in cryptographic guidance applicable to this component.",
]

GUIDANCE_CERTIFICATE_PQC: list[str] = [
    "Identify all certificate issuance and validation chains using RSA or ECDSA.",
    "Plan certificate lifecycle transition to ML-DSA-based certificate authorities.",
    "Deploy hybrid certificates (dual classical + PQC signatures) during the transition period.",
    "Update TLS and PKI configuration to accept PQC certificates once CA support is available.",
    "Coordinate certificate rotation schedule with organizational migration timeline.",
]


# ===========================================================================
# 6. Rationale String Templates
# ===========================================================================

RATIONALE_SHOR_VULNERABLE_KEM = (
    "{algorithm} is a public-key key establishment mechanism vulnerable to Shor's algorithm "
    "(polynomial-time quantum key recovery). Once a Cryptographically Relevant Quantum Computer "
    "(CRQC) is operational, all historic session keys negotiated with {algorithm} can be recovered."
)

RATIONALE_ML_KEM_SELECTED = (
    "ML-KEM ({param_set}) is selected as the primary PQC replacement. ML-KEM (NIST FIPS 203) "
    "is a Module-Lattice-Based Key Encapsulation Mechanism standardized by NIST in 2024. "
    "It provides equivalent security category {category} with classical-safe and post-quantum "
    "security based on the hardness of the Module Learning With Errors (MLWE) problem."
)

RATIONALE_HYBRID_KEM = (
    "A hybrid {hybrid} construction is recommended for migration. "
    "The hybrid combines a classical key exchange (for backward compatibility with non-PQC endpoints) "
    "with ML-KEM (for post-quantum security). This ensures that the final shared secret is secure "
    "as long as at least one of the two components remains unbroken — providing defense-in-depth "
    "during the migration period."
)

RATIONALE_SHOR_VULNERABLE_SIG = (
    "{algorithm} is a digital signature algorithm vulnerable to Shor's algorithm "
    "(polynomial-time quantum forgery of signatures). A CRQC can forge arbitrary signatures "
    "or recover private signing keys."
)

RATIONALE_ML_DSA_SELECTED = (
    "ML-DSA ({param_set}) is selected as the primary PQC replacement. ML-DSA (NIST FIPS 204) "
    "is a Module-Lattice-Based Digital Signature Algorithm standardized by NIST in 2024. "
    "It provides security category {category} based on the hardness of MLWE."
)

RATIONALE_HASH_GROVER = (
    "{algorithm} is a hash function affected by Grover's quantum search algorithm. "
    "For {algorithm}, the effective pre-image resistance is halved under quantum attack. "
    "The collision resistance is further reduced under BHT quantum collision search. "
    "Upgrading to a stronger hash function in the same family increases the security margin."
)

RATIONALE_SYMMETRIC_GROVER = (
    "{algorithm} uses a key length that is effectively halved by Grover's quantum search "
    "algorithm. A 128-bit key provides only ~64 bits of post-quantum security, falling below "
    "the NIST 128-bit post-quantum security baseline. Upgrading to 256-bit provides adequate "
    "post-Grover security (~128 bits)."
)

RATIONALE_ALREADY_PQC = (
    "{algorithm} is already a NIST-standardized Post-Quantum Cryptography algorithm. "
    "No migration is required at this time. The algorithm meets NIST FIPS PQC requirements "
    "and is quantum-resistant under current cryptographic assumptions."
)

RATIONALE_NOT_APPLICABLE = (
    "{algorithm} ({primitive}) is classified as not requiring PQC algorithm migration. "
    "Library components, PRNG/DRBG instances, and non-cryptographic primitives are not "
    "subject to direct algorithm replacement by the PQC recommendation engine."
)

RATIONALE_UNKNOWN_ALGORITHM = (
    "Algorithm '{algorithm}' could not be reliably mapped to a known cryptographic family. "
    "A PQC recommendation cannot be produced without a verified algorithm classification. "
    "Manual cryptographic audit is required to determine the appropriate migration path."
)

RATIONALE_CLASSICALLY_BROKEN = (
    "{algorithm} is classically broken and requires immediate replacement regardless of "
    "quantum threat timelines. A classical cryptanalytic attack can break this algorithm "
    "today. Migration to a secure modern algorithm is the first priority; PQC migration "
    "can be planned as a subsequent step once the classically-secure replacement is deployed."
)

RATIONALE_CERTIFICATE_PQC = (
    "{algorithm} is used in a certificate context. Certificate migration to PQC requires "
    "coordinated CA infrastructure changes, certificate lifecycle management, and hybrid "
    "certificate deployment to ensure backward compatibility during the transition period."
)

# Parameter selection assumption templates
ASSUMPTION_ML_KEM_768_DEFAULT = (
    "ML-KEM-768 (NIST Category 3, ~192-bit classical security equivalent) is selected as the "
    "default parameter set per QNetra PQC baseline policy. This is a conservative, well-supported "
    "choice that balances security margin and performance. Override if the deployment context "
    "requires Category 1 (ML-KEM-512) for constrained environments or Category 5 (ML-KEM-1024) "
    "for highest-security scenarios."
)

ASSUMPTION_ML_KEM_1024_HIGH_SECURITY = (
    "ML-KEM-1024 (NIST Category 5, ~256-bit classical security equivalent) is selected because "
    "the source asset uses a key size or curve indicating a high-security requirement "
    "(RSA >= 3072 bits or ECC >= 384 bits)."
)

ASSUMPTION_ML_DSA_65_DEFAULT = (
    "ML-DSA-65 (NIST Category 3, ~192-bit classical security equivalent) is selected as the "
    "default parameter set per QNetra PQC baseline policy."
)

ASSUMPTION_ML_DSA_87_HIGH_SECURITY = (
    "ML-DSA-87 (NIST Category 5, ~256-bit classical security equivalent) is selected because "
    "the source asset uses a high-security key size (RSA >= 3072 bits or ECDSA >= 384 bits)."
)

ASSUMPTION_NO_KEY_SIZE = (
    "The source asset does not specify a key size. The default PQC parameter set is applied "
    "per QNetra baseline policy. If a higher or lower security level is required, override "
    "the parameter selection manually."
)

ASSUMPTION_HYBRID_TRANSITION = (
    "A hybrid transition is recommended for public-key cryptography replacements to ensure "
    "backward compatibility with non-PQC endpoints during the migration period."
)

LIMITATION_KEY_SIZE_UNKNOWN = (
    "Source asset key size is not available. Parameter set selection is based on the default "
    "QNetra policy. Verify this is appropriate for the security requirements of the deployment."
)

LIMITATION_CURVE_UNKNOWN = (
    "Elliptic curve specification is not available. Parameter set selection is based on the "
    "default QNetra policy."
)

LIMITATION_PQC_LIBRARY_AVAILABILITY = (
    "PQC library availability may vary by platform and language ecosystem. Verify that a "
    "FIPS 203/204/205-compliant implementation is available for the target platform before "
    "initiating migration."
)

LIMITATION_HYBRID_NOT_STANDARDIZED = (
    "Hybrid constructions are not yet universally standardized in all protocols. Check "
    "protocol-specific PQC guidance (e.g. IETF drafts for TLS/SSH hybrid KEMs) before "
    "deployment."
)

LIMITATION_CLASSICALLY_BROKEN_PRIORITY = (
    "This algorithm is classically broken. Migration to any PQC algorithm should be preceded "
    "by immediate migration to a classically-secure algorithm as the first priority."
)
