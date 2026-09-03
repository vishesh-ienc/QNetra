"""
QNetra Classification Layer — Domain Models
============================================

Defines classification-specific enums and result models for Phase 2 Milestone 2.2.
These models represent the output of the ClassificationEngine and are distinct from
scanner registry models (scanners.registry.crypto_algorithms).

Design Notes:
  - QuantumThreat from scanners.registry.crypto_algorithms is intentionally NOT redefined here.
    The existing registry enum is the canonical quantum threat categorization source.
    This module adds:
      * ClassicalSecurityStatus: independently classifies classical security (orthogonal to quantum)
      * QuantumSecurityStatus: quantifies effective quantum security level
      * ClassificationResult: structured result from ClassificationEngine.classify_one()
    These are genuinely distinct domain concepts, not duplicates of QuantumThreat.

Contract Reference:
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.2 — CryptoAsset classification fields)
  - docs/05_ALGORITHMS.md (Alg-05)
  - docs/08_DECISIONS_AND_LOG.md (DEC-011)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ClassicalSecurityStatus(str, Enum):
    """
    Classical cryptographic security status, evaluated independently of quantum threats.

    Assessed against classical cryptanalytic standards:
    - NIST SP 800-131A Rev 2 (key length transitions)
    - NIST SP 800-57 Part 1 (security bit equivalences)
    - IETF and industry deprecation status

    NOTE: Classical SECURE does not imply quantum resistance.
    RSA-2048 is SECURE classically but SHOR_VULNERABLE quantum-wise.
    These dimensions are strictly orthogonal.
    """
    SECURE = "SECURE"    # Meets current classical security requirements
    WEAK = "WEAK"        # Below recommended classical thresholds; deprecated but not fully broken
    BROKEN = "BROKEN"    # Classically broken — collision/factoring attacks feasible
    UNKNOWN = "UNKNOWN"  # Insufficient evidence to determine classical security status


class QuantumSecurityStatus(str, Enum):
    """
    Post-quantum security level after applying the relevant quantum attack model.

    Threshold: 128-bit effective quantum security is the NIST-recommended minimum
    (equivalent to AES-128 in classical security terms).
    Reference: NIST SP 800-57, docs/09_KNOWLEDGE_BASE.md Section 1.2.

    SAFE     → Effective quantum security ≥ 128-bit threshold
    DEGRADED → Effective quantum security > 0 but < 128-bit threshold
    CRITICAL → Zero or negligible effective quantum security (Shor-completely broken)
    UNKNOWN  → Insufficient evidence or primitive type is not quantumly assessable
    """
    SAFE = "SAFE"           # Effective quantum security ≥ 128-bit NIST threshold
    DEGRADED = "DEGRADED"   # Effective quantum security > 0 but < 128-bit threshold
    CRITICAL = "CRITICAL"   # Completely broken by quantum computing (Shor-vulnerable)
    UNKNOWN = "UNKNOWN"     # Insufficient evidence or not applicable


@dataclass
class ClassificationResult:
    """
    Structured output from ClassificationEngine.classify_one().

    Contains all classification dimensions for a single CryptoAsset.
    This is an internal result object — the ClassificationEngine uses it
    to enrich CryptoAsset fields.

    Invariants:
    - classical_security_status and quantum_threat_str are always set (never None)
    - quantum_vulnerable is None only when classification evidence is UNKNOWN
    - effective_quantum_security_bits is None for Shor-vulnerable algorithms
      (Shor fundamentally breaks the public-key problem — not a reducible bit count)
    - effective_quantum_security_bits is None when key parameters are unknown
    """

    # --- Classical Security ---
    classical_security_status: ClassicalSecurityStatus
    """Classical security assessment, independent of quantum threats."""

    effective_classical_security_bits: Optional[int]
    """NIST SP 800-57 equivalent classical security bits.
    Examples: RSA-2048 ≈ 112, ECDSA P-256 ≈ 128, AES-256 = 256, SHA-256 collision = 128.
    None if algorithm or key parameters are insufficient to estimate."""

    classical_notes: str
    """Deterministic, human-readable rationale for the classical classification.
    Must cite the specific rule or standard applied."""

    # --- Quantum Security ---
    quantum_threat_str: str
    """QuantumThreat.value from scanner registry, or 'NOT_APPLICABLE' / 'UNKNOWN'.
    Stored directly in CryptoAsset.quantum_threat_type (string field)."""

    quantum_security_status: QuantumSecurityStatus
    """Post-quantum security level after applying Shor/Grover/BHT attack models."""

    quantum_vulnerable: Optional[bool]
    """True  → quantumly vulnerable per documented classification rules.
    False → adequate quantum security per documented thresholds.
    None  → insufficient evidence (UNKNOWN cases only)."""

    effective_quantum_security_bits: Optional[int]
    """Effective quantum security bits:
    - Shor-vulnerable assets: None (algorithm is fundamentally broken; no meaningful bit count)
    - Grover-impacted symmetric ciphers: key_bits // 2
    - Hash functions: BHT-based quantum collision resistance estimate
    - Classically broken: None (security is moot)
    - None when key parameters are unknown (never fabricated)"""

    quantum_notes: str
    """Deterministic, human-readable rationale for the quantum classification.
    Must explicitly state which security property and attack model the estimate represents."""

    # --- Classification Quality ---
    classification_confidence: str
    """Classification confidence level:
    HIGH    — canonical algorithm identified in registry AND all relevant parameters present
    LOW     — algorithm identified but key parameters missing (key size, curve, etc.)
    UNKNOWN — algorithm cannot be confidently classified (not in registry)"""
