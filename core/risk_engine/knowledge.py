"""
QNetra Risk Engine — Centralized Knowledge & Scoring Constants
===============================================================

Authoritative single source of truth for all numerical constants, baseline scores,
parameter modifiers, and explainability templates used by the Risk Engine.

Design Principles (PROJECT_RULES.md RULE-002, RULE-003):
  - No magic numbers scattered in functions.
  - Zero machine learning or stochastic models — purely deterministic arithmetic.
  - Aligns exactly with:
      * docs/05_ALGORITHMS.md Alg-06 (Deterministic Quantum Risk Scoring)
      * docs/06_API_AND_DATA_CONTRACTS.md Section 2.3 (RiskAssessmentReport)
      * docs/10_API_CONTRACT.md Section 9 (Risk API)
"""

from __future__ import annotations

# ===========================================================================
# 1. Base Risk Scores (Algorithmic Class Baselines)
# Reference: docs/05_ALGORITHMS.md Alg-06
# ===========================================================================

# Broken Classical Primitives (MD5, SHA-1, DES, RC4) — immediate classical collapse
BASE_CLASSICALLY_BROKEN: float = 100.0

# Shor-Vulnerable Asymmetric Cryptography (RSA, ECC, DH, ECDSA, Ed25519)
BASE_SHOR_VULNERABLE: float = 90.0

# Grover-Impacted Symmetric Ciphers with < 256-bit keys (AES-128, 3DES)
BASE_GROVER_DEGRADED_SYMMETRIC: float = 60.0

# Grover/BHT-Impacted Hash Functions with < 128-bit quantum collision resistance (SHA-256)
BASE_GROVER_DEGRADED_HASH: float = 40.0

# Quantum-Resistant Classical Cryptography (AES-256, SHA-384, SHA-512)
BASE_QUANTUM_RESISTANT_CLASSICAL: float = 20.0

# NIST-Approved Standardized Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)
BASE_NIST_APPROVED_PQC: float = 0.0

# Unrecognized / Obscure / Proprietary Cryptographic Primitive (Unverified baseline)
BASE_UNKNOWN_ALGORITHM: float = 50.0

# Non-Cryptographic or Non-Vulnerable Component (Library detection, DRBG)
BASE_NOT_APPLICABLE: float = 0.0


# ===========================================================================
# 2. Parameter Modifiers (M_key, M_mode, M_padding)
# Reference: docs/05_ALGORITHMS.md Alg-06
# ===========================================================================

# RSA Key Length Modifiers
MOD_RSA_BELOW_2048: float = 10.0      # RSA-1024 or smaller: below NIST minimum -> +10
MOD_RSA_GE_4096: float = -5.0         # RSA-4096 or larger: maximum classical security margin -> -5

# Symmetric Key Length Modifiers
MOD_AES_128: float = 10.0             # AES-128: halves to 64-bit post-Grover -> +10
MOD_AES_256: float = -10.0            # AES-256: retains 128-bit post-Grover security -> -10
MOD_AES_192: float = -5.0             # AES-192: retains 96-bit post-Grover security -> -5

# Cipher Mode Modifiers
MOD_ECB_MODE: float = 15.0            # Electronic Codebook mode: leaks plaintext structure -> +15

# Padding Modifiers
MOD_WEAK_PADDING: float = 5.0         # PKCS#1 v1.5 encryption: vulnerable to Bleichenbacher -> +5

# Classical Weakness Modifiers
MOD_CLASSICAL_WEAK: float = 10.0      # Classical WEAK status (e.g. 3DES, deprecated keys) -> +10
MOD_PARAM_UNKNOWN: float = 0.0        # Missing parameter: NO FABRICATION policy -> 0.0 (no guess)


# ===========================================================================
# 3. Severity Thresholds
# Reference: docs/05_ALGORITHMS.md Alg-06 & docs/10_API_CONTRACT.md Section 9
# ===========================================================================

SEVERITY_CRITICAL_MIN: float = 80.0   # 80–100: CRITICAL (Immediate migration required)
SEVERITY_HIGH_MIN: float = 60.0       # 60–79:  HIGH     (Symmetric < 256 bits, SHA-224)
SEVERITY_MEDIUM_MIN: float = 30.0     # 30–59:  MEDIUM   (SHA-256, unverified parameters)
SEVERITY_LOW_MAX: float = 29.0        # 0–29:   LOW      (AES-256, SHA-384/512, PQC)


# ===========================================================================
# 4. Repository Aggregation Weights
# Reference: docs/06_API_AND_DATA_CONTRACTS.md Section 2.3
# Overall Risk = 0.7 * Max(Score) + 0.3 * Mean(Score)
# ===========================================================================

REPO_MAX_WEIGHT: float = 0.7
REPO_MEAN_WEIGHT: float = 0.3


# ===========================================================================
# 5. Explainability Rationale Templates
# ===========================================================================

RATIONALE_CLASSICALLY_BROKEN = (
    "{algorithm} is classically broken ({notes}). "
    "Immediate cryptanalytic break feasible without quantum computing."
)

RATIONALE_SHOR_VULNERABLE = (
    "{algorithm}{param_str} is fundamentally vulnerable to Shor's algorithm polynomial-time "
    "key recovery (order-finding in O((log N)^3)). Post-quantum security collapses to 0 bits."
)

RATIONALE_GROVER_DEGRADED = (
    "{algorithm}{param_str} effective security is halved by Grover's quantum search to ~{qbits} bits, "
    "falling below the NIST 128-bit post-quantum security threshold."
)

RATIONALE_QUANTUM_RESISTANT_SYMMETRIC = (
    "{algorithm}{param_str} retains ~{qbits} bits of effective post-quantum security under Grover's search, "
    "meeting the NIST 128-bit quantum security baseline."
)

RATIONALE_QUANTUM_RESISTANT_HASH = (
    "{algorithm} provides >= 128-bit post-quantum collision resistance under BHT quantum collision bounds."
)

RATIONALE_NIST_PQC = (
    "{algorithm} is a standardized Post-Quantum Cryptography algorithm approved under "
    "NIST FIPS standards. Quantum resistance verified."
)

RATIONALE_NOT_APPLICABLE = (
    "{algorithm} ({primitive_type}) is not directly vulnerable to quantum algorithmic attacks "
    "in this operational context."
)

RATIONALE_UNKNOWN_ALGORITHM = (
    "Algorithm '{algorithm}' could not be matched against verified cryptographic registries. "
    "Assigned moderate baseline risk pending manual audit."
)
