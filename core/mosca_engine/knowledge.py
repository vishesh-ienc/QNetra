"""
QNetra Mosca Engine — Centralized Knowledge, Constants & Configuration
=======================================================================

Authoritative single source of truth for:
  - MoscaConfig: Overridable scenario configuration (migration time Y, quantum arrival Z defaults).
  - Quantum-arrival scenario presets (OPTIMISTIC, BASELINE, CONSERVATIVE).
  - Migration time baselines by primitive class (documented assumptions, not fabrication).
  - HNDL sensitivity thresholds.
  - Urgency classification logic constants.

Design Principles (PROJECT_RULES.md RULE-002, RULE-003):
  - No magic numbers scattered inside calculation functions.
  - Zero machine learning or stochastic models — deterministic arithmetic only.
  - Every default is documented with its source and marked explicitly as an assumption.
  - Protected data lifetime (X) has NO default — the engine never fabricates it.
    If X is missing, the assessment returns UNKNOWN state. This is intentional.

Naming Convention (docs/09_KNOWLEDGE_BASE.md §2.1, docs/06_API_AND_DATA_CONTRACTS.md §2.4):
  X = Data Shelf Life   (years data must remain confidential)
  Y = Migration Time    (years to re-architect and deploy PQC)
  Z = Quantum Horizon   (years until CRQC — Cryptographically Relevant Quantum Computer)

Sources:
  - Mosca (2015). "Setting the Scene for the PQC Transition."
  - NIST IR 8240 (2019). "Status Report on the First Round of the NIST PQC Standardization Process."
  - NIST SP 800-131A Rev 2 (2019). Transitioning the Use of Cryptographic Algorithms.
  - ENISA (2021). "Post-Quantum Cryptography: Current state and quantum mitigation."
  - BSI (2021). "Quantum-Safe Cryptography — fundamentals, current developments and recommendations."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.mosca_engine.models import HNDLExposure, MoscaUrgency


# ===========================================================================
# 1. Quantum Arrival Scenarios (Z baseline — years until CRQC)
#    Source: Industry consensus range from NIST, ENISA, BSI (2021–2024).
#    These are documented assumptions/scenarios — NOT guaranteed predictions.
# ===========================================================================

#: Optimistic scenario: quantum computing progresses quickly. Assumes CRQC ~7 years.
QUANTUM_ARRIVAL_OPTIMISTIC: float = 7.0

#: Baseline scenario: mainstream consensus from NIST, ENISA, BSI. CRQC ~10 years.
QUANTUM_ARRIVAL_BASELINE: float = 10.0

#: Conservative scenario: quantum computing faces significant obstacles. CRQC ~15 years.
QUANTUM_ARRIVAL_CONSERVATIVE: float = 15.0


# ===========================================================================
# 2. Migration Time Baselines (Y — years to complete migration by primitive class)
#    Source: NIST guidance, ENISA PQC Roadmap, and enterprise migration studies.
#    These are documented defaults used ONLY when no explicit Y is supplied.
#    All usages are logged in MoscaAssessment.assumptions.
# ===========================================================================

#: Asymmetric (RSA, ECC, DH, ECDH, ECDSA) — protocol/library refactoring + cert renewal
MIGRATION_TIME_ASYMMETRIC: float = 4.0

#: Symmetric cipher key length upgrade (AES-128 → AES-256) — typically config/library change
MIGRATION_TIME_SYMMETRIC: float = 1.5

#: Hash function migration (SHA-1/SHA-256 → SHA-384/SHA-512/SHA3)
MIGRATION_TIME_HASH: float = 1.0

#: Protocol-level (TLS/SSH suite negotiation changes)
MIGRATION_TIME_PROTOCOL: float = 3.0

#: Library/component — depends on transitive dependency chain
MIGRATION_TIME_LIBRARY: float = 2.0

#: Fallback for UNKNOWN primitive type — conservative estimate
MIGRATION_TIME_UNKNOWN: float = 3.0


# ===========================================================================
# 3. HNDL Classification Thresholds
#    These govern when a Shor-vulnerable asset's protected lifetime
#    triggers an HNDL exposure tier.
# ===========================================================================

#: If protected lifetime > quantum horizon + this buffer → CRITICAL HNDL
HNDL_CRITICAL_BUFFER_YEARS: float = 5.0

#: If protected lifetime is within this margin of the quantum horizon → HIGH HNDL
HNDL_HIGH_MARGIN_YEARS: float = 0.0

#: If protected lifetime is at least this many years below quantum horizon → MEDIUM HNDL
HNDL_MEDIUM_THRESHOLD_YEARS: float = -3.0  # i.e. (lifetime - horizon) >= -3.0 → MEDIUM

#: Minimum protected lifetime (years) to imply non-trivial HNDL exposure for any asset
HNDL_MINIMUM_MEANINGFUL_LIFETIME: float = 1.0


# ===========================================================================
# 4. Urgency Classification Policy Constants
#    Determine which combinations of Mosca state + HNDL produce each urgency tier.
# ===========================================================================

#: Exposure gap (years) below which urgency becomes IMMEDIATE even if X+Y > Z
URGENCY_IMMEDIATE_GAP_THRESHOLD: float = 0.0  # Any triggered inequality → IMMEDIATE candidate

#: If exposure gap > this value → URGENT (rather than IMMEDIATE)
URGENCY_URGENT_GAP_THRESHOLD: float = 2.0

#: Safe buffer (years) below which PLANNED urgency is triggered even without inequality
URGENCY_PLANNED_BUFFER_THRESHOLD: float = 3.0


# ===========================================================================
# 5. NOT_APPLICABLE Primitive Types
#    These primitives are not subject to Mosca analysis.
# ===========================================================================

from core.models import PrimitiveType  # noqa: E402

NOT_APPLICABLE_PRIMITIVE_TYPES: frozenset[PrimitiveType] = frozenset({
    PrimitiveType.LIBRARY,
    PrimitiveType.RANDOM,
})

#: PQC algorithm prefixes — these are already quantum-safe; urgency = NOT_REQUIRED
PQC_ALGORITHM_PREFIXES: frozenset[str] = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})

#: Quantum threat types that indicate Shor-vulnerability (Mosca fully applicable)
SHOR_QUANTUM_THREAT_VALUES: frozenset[str] = frozenset({
    "SHOR_POLYNOMIAL_BREAK",
})

#: Quantum threat types that indicate Grover/BHT impact (Mosca partially applicable)
GROVER_QUANTUM_THREAT_VALUES: frozenset[str] = frozenset({
    "GROVER_BIT_HALVING",
})


# ===========================================================================
# 6. MoscaConfig — Central Configurable Scenario Parameters
# ===========================================================================

@dataclass
class MoscaConfig:
    """
    Configuration object for the MoscaEngine.

    Holds the default Y (migration time) and Z (quantum horizon) assumptions.
    Protected lifetime (X) deliberately has no default — it must be supplied
    by the caller. Never fabricating X is a core no-fabrication policy requirement.

    All defaults in this config are considered 'BASELINE' scenario assumptions.
    Override with OPTIMISTIC or CONSERVATIVE constants from this module for scenario analysis.

    Attributes:
      default_quantum_arrival_years:
          Z — assumed years until CRQC. Defaults to QUANTUM_ARRIVAL_BASELINE (10 years).
          Source: NIST, ENISA, BSI industry consensus estimate (2021–2024).
      default_protected_lifetime_years:
          X — if None (default), no protected lifetime is assumed. The engine will
          return UNKNOWN urgency when X is missing.
          Set to a numeric value only if you want a global project-wide default for
          all assets without explicit context.
      use_primitive_migration_defaults:
          If True, the engine derives Y from the primitive type when not explicitly provided.
          If False, migration time without explicit context returns UNKNOWN.
    """

    default_quantum_arrival_years: float = QUANTUM_ARRIVAL_BASELINE
    """Default quantum threat horizon (Z). Baseline assumption: 10 years."""

    default_protected_lifetime_years: Optional[float] = None
    """Default data shelf life (X). None = no-fabrication (returns UNKNOWN if not supplied)."""

    use_primitive_migration_defaults: bool = True
    """Use primitive-class migration time baselines when Y not explicitly supplied."""


# ===========================================================================
# 7. Assumption String Templates
#    Used to populate MoscaAssessment.assumptions[] for explainability.
# ===========================================================================

ASSUMPTION_QUANTUM_ARRIVAL = (
    "Quantum threat horizon (Z) set to {z:.1f} years — based on NIST/ENISA/BSI baseline "
    "consensus estimate (2021–2024). This is an assumption, not a guaranteed date."
)

ASSUMPTION_MIGRATION_TIME_DERIVED = (
    "Migration time (Y) set to {y:.1f} years — derived from the primitive type "
    "'{primitive}' using QNetra documented baseline. This is an estimated assumption; "
    "actual migration effort depends on organizational scale, system complexity, and "
    "dependency chains."
)

ASSUMPTION_PROTECTED_LIFETIME_MISSING = (
    "Protected data lifetime (X) was not supplied for this asset. "
    "Mosca inequality (X + Y > Z) cannot be evaluated without X. "
    "Urgency is returned as UNKNOWN. Provide 'protected_lifetime_years' "
    "in MoscaInput for a definitive assessment."
)

ASSUMPTION_MIGRATION_TIME_MISSING = (
    "Migration time (Y) could not be derived (primitive_type unknown and no explicit "
    "MoscaInput.migration_time_years supplied). Mosca inequality cannot be fully evaluated."
)

ASSUMPTION_HNDL_NOT_SENSITIVE = (
    "Asset was not flagged as HNDL-sensitive (hndl_sensitive=False or not specified). "
    "HNDL exposure is assessed from structural analysis of protected lifetime vs quantum horizon."
)

ASSUMPTION_NOT_APPLICABLE = (
    "This asset ({primitive}) is classified as NOT_APPLICABLE for Mosca analysis. "
    "Library components and random number generators are not directly subject to "
    "Harvest Now, Decrypt Later threat modeling."
)

ASSUMPTION_QUANTUM_RESISTANT = (
    "Algorithm '{algorithm}' is a NIST-approved Post-Quantum Cryptographic standard. "
    "Conventional Shor-based quantum attack urgency does not apply. "
    "Migration is NOT_REQUIRED unless transitioning from a hybrid or legacy system."
)

ASSUMPTION_GROVER_MOSCA_LIMITED = (
    "For Grover-impacted symmetric/hash algorithms, Mosca urgency reflects the risk of "
    "quantum-weakened (but not broken) security. Unlike Shor-vulnerable algorithms, "
    "HNDL exposure is structurally lower because the attack degrades — not eliminates — "
    "security. The primary recommendation is a key-length upgrade, not algorithm replacement."
)
