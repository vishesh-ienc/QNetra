"""
QNetra Mosca Engine — Orchestrator
====================================

The primary entry point for Milestone 3.2 Mosca Migration Assessment.

Orchestrates single-asset assessments, batch evaluations, and aggregate
repository-level Mosca/HNDL reporting.

Design Principles:
  - Deterministic: Output order and values are strictly reproducible.
  - Side-effect Isolation: `assess()` and `assess_all()` are PURELY FUNCTIONAL.
    They NEVER mutate the input CryptoAsset.
  - Assessment Date: Never calls datetime.now() internally. Explicit assessment_date
    must be provided in MoscaInput for deadline calculations.
  - Strict Boundary Separation: Does NOT invoke scanners, normalization, CBOM
    serialization, Risk Engine scoring, PQC recommendations, or FastAPI logic.
  - No PQC decisions: The Mosca Engine identifies urgency only.
    Milestone 3.3 owns PQC replacement recommendations.

Usage:
    from core.mosca_engine import MoscaEngine, MoscaInput, MoscaConfig

    config = MoscaConfig(
        default_quantum_arrival_years=10.0,
        use_primitive_migration_defaults=True,
    )
    engine = MoscaEngine(config=config)

    # Pure single-asset assessment (no asset mutation)
    context = MoscaInput(
        asset_id=asset.asset_id,
        protected_lifetime_years=15.0,
        assessment_date=date(2026, 9, 4),
    )
    assessment = engine.assess(asset, context)

    # Batch assessment (deterministic sort by asset_id)
    contexts = {a.asset_id: MoscaInput(asset_id=a.asset_id, ...) for a in assets}
    assessments = engine.assess_all(assets, contexts=contexts)

    # Repository-level report
    report = engine.generate_report(assets, contexts=contexts)
"""

from __future__ import annotations

import logging
from typing import Optional

from core.models import CryptoAsset, PrimitiveType
from core.mosca_engine.calculator import (
    calculate_deadline_years_from_now,
    calculate_exposure_gap,
    calculate_x_plus_y,
    classify_hndl_exposure,
    classify_urgency,
    evaluate_inequality,
    validate_duration,
)
from core.mosca_engine.knowledge import (
    ASSUMPTION_GROVER_MOSCA_LIMITED,
    ASSUMPTION_MIGRATION_TIME_DERIVED,
    ASSUMPTION_MIGRATION_TIME_MISSING,
    ASSUMPTION_NOT_APPLICABLE,
    ASSUMPTION_PROTECTED_LIFETIME_MISSING,
    ASSUMPTION_QUANTUM_ARRIVAL,
    ASSUMPTION_QUANTUM_RESISTANT,
    MIGRATION_TIME_ASYMMETRIC,
    MIGRATION_TIME_HASH,
    MIGRATION_TIME_LIBRARY,
    MIGRATION_TIME_PROTOCOL,
    MIGRATION_TIME_SYMMETRIC,
    MIGRATION_TIME_UNKNOWN,
    NOT_APPLICABLE_PRIMITIVE_TYPES,
    PQC_ALGORITHM_PREFIXES,
    MoscaConfig,
)
from core.mosca_engine.models import (
    AssetMoscaDetail,
    HNDLExposure,
    MoscaAssessment,
    MoscaAssessmentReport,
    MoscaInput,
    MoscaUrgency,
)

logger = logging.getLogger(__name__)


def _is_pqc_algorithm(algorithm: str) -> bool:
    """Return True if algorithm is a standardized NIST PQC algorithm."""
    upper = algorithm.upper()
    return any(upper.startswith(prefix) for prefix in PQC_ALGORITHM_PREFIXES)


def _is_not_applicable(asset: CryptoAsset) -> bool:
    """Return True if the asset's primitive type is not subject to Mosca analysis."""
    return asset.primitive_type in NOT_APPLICABLE_PRIMITIVE_TYPES


def _derive_migration_time_years(asset: CryptoAsset, config: MoscaConfig) -> Optional[float]:
    """
    Derive the default migration time (Y) based on primitive type.

    Called ONLY when no explicit Y is provided in MoscaInput.
    If use_primitive_migration_defaults is False, returns None.
    All derivations are logged as assumptions in MoscaAssessment.assumptions.

    Args:
        asset: Classified CryptoAsset.
        config: MoscaConfig with defaults policy.

    Returns:
        Float migration time in years, or None if primitives policy is off.
    """
    if not config.use_primitive_migration_defaults:
        return None

    primitive_migration_map: dict[PrimitiveType, float] = {
        PrimitiveType.ASYMMETRIC_ENCRYPTION: MIGRATION_TIME_ASYMMETRIC,
        PrimitiveType.DIGITAL_SIGNATURE: MIGRATION_TIME_ASYMMETRIC,
        PrimitiveType.KEY_EXCHANGE: MIGRATION_TIME_ASYMMETRIC,
        PrimitiveType.SYMMETRIC_CIPHER: MIGRATION_TIME_SYMMETRIC,
        PrimitiveType.HASH_FUNCTION: MIGRATION_TIME_HASH,
        PrimitiveType.MAC: MIGRATION_TIME_HASH,
        PrimitiveType.KDF: MIGRATION_TIME_HASH,
        PrimitiveType.PROTOCOL: MIGRATION_TIME_PROTOCOL,
        PrimitiveType.LIBRARY: MIGRATION_TIME_LIBRARY,
        PrimitiveType.CERTIFICATE: MIGRATION_TIME_ASYMMETRIC,
        PrimitiveType.KEY_MATERIAL: MIGRATION_TIME_ASYMMETRIC,
        PrimitiveType.RANDOM: MIGRATION_TIME_UNKNOWN,
        PrimitiveType.UNKNOWN: MIGRATION_TIME_UNKNOWN,
    }

    return primitive_migration_map.get(asset.primitive_type, MIGRATION_TIME_UNKNOWN)


class MoscaEngine:
    """
    Deterministic Mosca migration urgency and HNDL assessment engine.

    Consumes classified CryptoAsset instances plus optional per-asset MoscaInput context.
    Produces MoscaAssessment per asset and MoscaAssessmentReport for the repository.

    Strict Boundaries:
      ✓ Evaluates Mosca inequality (X + Y > Z)
      ✓ Models HNDL exposure
      ✓ Classifies migration urgency
      ✓ Calculates migration deadline (years from assessment_date)
      ✗ Does NOT perform risk scoring (core.risk_engine owns that)
      ✗ Does NOT recommend PQC replacements (core.recommendation_engine owns that)
      ✗ Does NOT run scanners or normalization
      ✗ Does NOT modify CryptoAsset objects (assess() is pure)
    """

    def __init__(self, config: Optional[MoscaConfig] = None) -> None:
        """
        Initialize MoscaEngine with optional configuration.

        Args:
            config: MoscaConfig with default quantum arrival and migration time policy.
                    If None, uses MoscaConfig defaults (BASELINE scenario, 10-year horizon).
        """
        self.config = config if config is not None else MoscaConfig()

    def assess(
        self,
        asset: CryptoAsset,
        context: Optional[MoscaInput] = None,
    ) -> MoscaAssessment:
        """
        Pure functional single-asset Mosca assessment.

        This method NEVER mutates the input CryptoAsset.

        Args:
            asset: Classified CryptoAsset (with classification fields populated).
            context: Optional per-asset inputs (X, Y, Z overrides, HNDL flag, date).

        Returns:
            MoscaAssessment with full explainability output.
        """
        assumptions: list[str] = []
        rationale: list[str] = []

        # --- Step 1: Check applicability ---
        mosca_applicable = True

        # NOT_APPLICABLE primitive types (Library, Random)
        if _is_not_applicable(asset):
            mosca_applicable = False
            assumptions.append(
                ASSUMPTION_NOT_APPLICABLE.format(primitive=asset.primitive_type.value)
            )
            rationale.append(
                f"Asset '{asset.algorithm}' ({asset.primitive_type.value}) is classified "
                f"as NOT_APPLICABLE for Mosca analysis. Library components and random "
                f"generators are not subject to Harvest Now, Decrypt Later threat modeling."
            )
            return MoscaAssessment(
                asset_id=asset.asset_id,
                x_data_lifetime_years=None,
                y_migration_time_years=None,
                z_quantum_arrival_years=None,
                x_plus_y=None,
                inequality_triggered=None,
                exposure_gap_years=None,
                urgency=MoscaUrgency.NOT_REQUIRED,
                hndl_exposure=HNDLExposure.NONE,
                migration_deadline_years_from_now=None,
                assessment_date=context.assessment_date if context else None,
                mosca_applicable=False,
                assumptions=assumptions,
                rationale=rationale,
            )

        # NIST-approved PQC algorithms → quantum-resistant, NOT_REQUIRED
        if _is_pqc_algorithm(asset.algorithm):
            mosca_applicable = False
            assumptions.append(
                ASSUMPTION_QUANTUM_RESISTANT.format(algorithm=asset.algorithm)
            )
            rationale.append(
                f"Algorithm '{asset.algorithm}' is a NIST-approved Post-Quantum Cryptographic "
                f"standard (FIPS 203/204/205). Conventional Shor-based quantum attack urgency "
                f"does not apply. Migration urgency is NOT_REQUIRED."
            )
            return MoscaAssessment(
                asset_id=asset.asset_id,
                x_data_lifetime_years=None,
                y_migration_time_years=None,
                z_quantum_arrival_years=None,
                x_plus_y=None,
                inequality_triggered=None,
                exposure_gap_years=None,
                urgency=MoscaUrgency.NOT_REQUIRED,
                hndl_exposure=HNDLExposure.NONE,
                migration_deadline_years_from_now=None,
                assessment_date=context.assessment_date if context else None,
                mosca_applicable=False,
                assumptions=assumptions,
                rationale=rationale,
            )

        # --- Step 2: Resolve Z (Quantum Arrival / Quantum Horizon) ---
        z_quantum_arrival_years: Optional[float] = None
        if context is not None and context.quantum_arrival_years is not None:
            validate_duration("quantum_arrival_years (Z)", context.quantum_arrival_years)
            z_quantum_arrival_years = context.quantum_arrival_years
        else:
            z_quantum_arrival_years = self.config.default_quantum_arrival_years
            assumptions.append(
                ASSUMPTION_QUANTUM_ARRIVAL.format(z=z_quantum_arrival_years)
            )

        # --- Step 3: Resolve Y (Migration Time) ---
        y_migration_time_years: Optional[float] = None
        if context is not None and context.migration_time_years is not None:
            validate_duration("migration_time_years (Y)", context.migration_time_years)
            y_migration_time_years = context.migration_time_years
        else:
            derived_y = _derive_migration_time_years(asset, self.config)
            if derived_y is not None:
                y_migration_time_years = derived_y
                assumptions.append(
                    ASSUMPTION_MIGRATION_TIME_DERIVED.format(
                        y=derived_y,
                        primitive=asset.primitive_type.value,
                    )
                )
            else:
                assumptions.append(ASSUMPTION_MIGRATION_TIME_MISSING)

        # --- Step 4: Resolve X (Protected Data Lifetime / Data Shelf Life) ---
        x_data_lifetime_years: Optional[float] = None
        if context is not None and context.protected_lifetime_years is not None:
            validate_duration("protected_lifetime_years (X)", context.protected_lifetime_years)
            x_data_lifetime_years = context.protected_lifetime_years
        elif self.config.default_protected_lifetime_years is not None:
            x_data_lifetime_years = self.config.default_protected_lifetime_years
            assumptions.append(
                "Protected data lifetime (X) set to {:.1f} years from engine global default "
                "(MoscaConfig.default_protected_lifetime_years). This is a project-level "
                "assumption; override with MoscaInput.protected_lifetime_years per asset.".format(
                    x_data_lifetime_years
                )
            )
        else:
            assumptions.append(ASSUMPTION_PROTECTED_LIFETIME_MISSING)

        # --- Step 5: Resolve HNDL sensitivity ---
        hndl_sensitive: Optional[bool] = None
        if context is not None:
            hndl_sensitive = context.hndl_sensitive
        if hndl_sensitive is None:
            assumptions.append(ASSUMPTION_HNDL_NOT_SENSITIVE := (
                "HNDL sensitivity not explicitly specified. "
                "HNDL exposure assessed from structural analysis "
                "(protected lifetime vs quantum horizon)."
            ))

        # --- Step 6: Calculate HNDL exposure ---
        hndl_exposure = classify_hndl_exposure(
            quantum_vulnerable=asset.quantum_vulnerable,
            quantum_threat_type=asset.quantum_threat_type,
            hndl_sensitive=hndl_sensitive,
            protected_lifetime_years=x_data_lifetime_years,
            quantum_arrival_years=z_quantum_arrival_years,
        )

        # Add Grover-specific note if applicable
        if asset.quantum_threat_type == "GROVER_BIT_HALVING":
            assumptions.append(ASSUMPTION_GROVER_MOSCA_LIMITED)

        # --- Step 7: Evaluate Mosca Inequality ---
        x_plus_y: Optional[float] = None
        inequality_triggered: Optional[bool] = None
        exposure_gap_years: Optional[float] = None
        migration_deadline_years_from_now: Optional[float] = None

        if x_data_lifetime_years is not None and y_migration_time_years is not None:
            x_plus_y = calculate_x_plus_y(x_data_lifetime_years, y_migration_time_years)
            inequality_triggered = evaluate_inequality(
                x_data_lifetime_years, y_migration_time_years, z_quantum_arrival_years
            )
            exposure_gap_years = calculate_exposure_gap(
                x_data_lifetime_years, y_migration_time_years, z_quantum_arrival_years
            )
            migration_deadline_years_from_now = calculate_deadline_years_from_now(
                z_quantum_arrival_years, y_migration_time_years
            )

            # Build inequality rationale
            rationale.append(
                f"Mosca Inequality: X + Y = {x_data_lifetime_years:.1f} + "
                f"{y_migration_time_years:.1f} = {x_plus_y:.1f} years vs "
                f"Z = {z_quantum_arrival_years:.1f} years. "
                f"X + Y > Z: {inequality_triggered}."
            )
            if inequality_triggered:
                rationale.append(
                    f"HNDL EXPOSURE ACTIVE: The data must remain confidential for "
                    f"{x_data_lifetime_years:.1f} years, but the migration requires "
                    f"{y_migration_time_years:.1f} years, together exceeding the "
                    f"{z_quantum_arrival_years:.1f}-year quantum horizon by "
                    f"{exposure_gap_years:.1f} years. Adversaries may be harvesting "
                    f"today's ciphertext for future decryption."
                )
            else:
                buffer = z_quantum_arrival_years - x_plus_y
                rationale.append(
                    f"Safe migration buffer: {buffer:.1f} years remain before the "
                    f"quantum horizon closes. Migration should be planned proactively."
                )
        elif y_migration_time_years is not None:
            # X missing — partial analysis
            rationale.append(
                f"Mosca inequality cannot be fully evaluated: protected data lifetime (X) "
                f"is unknown. Y = {y_migration_time_years:.1f} years, "
                f"Z = {z_quantum_arrival_years:.1f} years."
            )
        else:
            rationale.append(
                "Mosca inequality cannot be evaluated: both X (protected lifetime) "
                "and Y (migration time) are unavailable."
            )

        # HNDL rationale
        rationale.append(
            f"HNDL Exposure: {hndl_exposure.value}. "
            + _hndl_rationale(
                hndl_exposure,
                asset.quantum_threat_type,
                x_data_lifetime_years,
                z_quantum_arrival_years,
                hndl_sensitive,
            )
        )

        # --- Step 8: Classify urgency ---
        urgency = classify_urgency(
            mosca_applicable=mosca_applicable,
            quantum_vulnerable=asset.quantum_vulnerable,
            quantum_threat_type=asset.quantum_threat_type,
            inequality_triggered=inequality_triggered,
            hndl_exposure=hndl_exposure,
            exposure_gap_years=exposure_gap_years,
            z_quantum_arrival_years=z_quantum_arrival_years,
            y_migration_time_years=y_migration_time_years,
        )

        rationale.append(f"Migration urgency: {urgency.value}.")

        # Assessment date from context
        assessment_date = context.assessment_date if context is not None else None

        return MoscaAssessment(
            asset_id=asset.asset_id,
            x_data_lifetime_years=x_data_lifetime_years,
            y_migration_time_years=y_migration_time_years,
            z_quantum_arrival_years=z_quantum_arrival_years,
            x_plus_y=x_plus_y,
            inequality_triggered=inequality_triggered,
            exposure_gap_years=exposure_gap_years,
            urgency=urgency,
            hndl_exposure=hndl_exposure,
            migration_deadline_years_from_now=migration_deadline_years_from_now,
            assessment_date=assessment_date,
            mosca_applicable=mosca_applicable,
            assumptions=assumptions,
            rationale=rationale,
        )

    def assess_all(
        self,
        assets: list[CryptoAsset],
        contexts: Optional[dict[str, MoscaInput]] = None,
    ) -> list[MoscaAssessment]:
        """
        Pure functional batch Mosca assessment.

        This method NEVER mutates any input CryptoAsset.
        Results are sorted deterministically by asset_id.

        Args:
            assets: List of classified CryptoAssets.
            contexts: Optional dict mapping asset_id → MoscaInput context.
                      Assets without a context entry are assessed with None context.

        Returns:
            Deterministic list of MoscaAssessment objects sorted by asset_id.
        """
        assessments = []
        for asset in assets:
            context = contexts.get(asset.asset_id) if contexts else None
            assessment = self.assess(asset, context)
            assessments.append(assessment)

        # Deterministic sort by asset_id
        assessments.sort(key=lambda a: a.asset_id)
        return assessments

    def generate_report(
        self,
        assets: list[CryptoAsset],
        assessments: Optional[list[MoscaAssessment]] = None,
        contexts: Optional[dict[str, MoscaInput]] = None,
    ) -> MoscaAssessmentReport:
        """
        Generate aggregate repository-level MoscaAssessmentReport.

        Conforms to:
          - docs/06_API_AND_DATA_CONTRACTS.md Section 2.4
          - docs/10_API_CONTRACT.md Section 12

        Args:
            assets: List of classified CryptoAssets.
            assessments: Optional pre-computed assessments. If None, computed internally.
            contexts: Optional context dict (used if assessments is None).

        Returns:
            Populated MoscaAssessmentReport.
        """
        if assessments is None:
            assessments = self.assess_all(assets, contexts=contexts)

        total_assets = len(assets)

        # Initialize distribution counters
        urgency_distribution: dict[str, int] = {u.value: 0 for u in MoscaUrgency}
        hndl_distribution: dict[str, int] = {h.value: 0 for h in HNDLExposure}

        mosca_applicable_count = 0
        mosca_triggered_count = 0
        hndl_exposed_count = 0

        for a in assessments:
            urgency_distribution[a.urgency.value] += 1
            hndl_distribution[a.hndl_exposure.value] += 1

            if a.mosca_applicable:
                mosca_applicable_count += 1

            if a.inequality_triggered is True:
                mosca_triggered_count += 1

            if a.hndl_exposure not in (HNDLExposure.NONE, HNDLExposure.UNKNOWN):
                hndl_exposed_count += 1

        # Build highest-urgency asset details
        # Priority order: IMMEDIATE > URGENT > PLANNED > MONITOR > UNKNOWN > NOT_REQUIRED
        urgency_order = [
            MoscaUrgency.IMMEDIATE,
            MoscaUrgency.URGENT,
            MoscaUrgency.PLANNED,
            MoscaUrgency.MONITOR,
            MoscaUrgency.UNKNOWN,
            MoscaUrgency.NOT_REQUIRED,
        ]
        urgency_rank = {u: i for i, u in enumerate(urgency_order)}

        sorted_by_urgency = sorted(
            assessments,
            key=lambda a: (urgency_rank.get(a.urgency, 99), a.asset_id),
        )

        # Top 10 highest urgency assets
        highest_urgency_assets = [
            AssetMoscaDetail(
                asset_id=a.asset_id,
                urgency=a.urgency.value,
                hndl_exposure=a.hndl_exposure.value,
                inequality_triggered=a.inequality_triggered,
                mosca_applicable=a.mosca_applicable,
            )
            for a in sorted_by_urgency[:10]
            if a.urgency not in (MoscaUrgency.NOT_REQUIRED,)
        ]

        return MoscaAssessmentReport(
            total_assets=total_assets,
            mosca_applicable_assets=mosca_applicable_count,
            mosca_triggered_assets=mosca_triggered_count,
            hndl_exposed_assets=hndl_exposed_count,
            urgency_distribution=urgency_distribution,
            hndl_distribution=hndl_distribution,
            highest_urgency_assets=highest_urgency_assets,
            assessments=assessments,
        )


def _hndl_rationale(
    hndl_exposure: HNDLExposure,
    quantum_threat_type: Optional[str],
    protected_lifetime_years: Optional[float],
    quantum_arrival_years: float,
    hndl_sensitive: Optional[bool],
) -> str:
    """Build a human-readable HNDL rationale string."""
    if hndl_exposure == HNDLExposure.NONE:
        return (
            "Asset is quantum-resistant. No HNDL exposure applies."
        )
    if hndl_exposure == HNDLExposure.UNKNOWN:
        return (
            "HNDL exposure cannot be assessed due to missing classification "
            "or protected lifetime information."
        )

    threat_desc = {
        "SHOR_POLYNOMIAL_BREAK": "Shor-vulnerable public-key algorithm",
        "GROVER_BIT_HALVING": "Grover-impacted symmetric/hash algorithm",
    }.get(quantum_threat_type or "", "quantum-vulnerable algorithm")

    lifetime_desc = (
        f"{protected_lifetime_years:.1f}-year data confidentiality requirement"
        if protected_lifetime_years is not None
        else "unspecified data lifetime"
    )

    if hndl_exposure == HNDLExposure.CRITICAL:
        return (
            f"This asset uses a {threat_desc} and protects data with a "
            f"{lifetime_desc} that far exceeds the {quantum_arrival_years:.1f}-year "
            f"quantum threat horizon. Adversaries harvesting ciphertext today will "
            f"likely decrypt it before its confidentiality period expires."
        )
    if hndl_exposure == HNDLExposure.HIGH:
        return (
            f"This asset uses a {threat_desc} and protects data with a "
            f"{lifetime_desc} extending at or beyond the {quantum_arrival_years:.1f}-year "
            f"quantum threat horizon. Harvest-now-decrypt-later exposure is likely."
        )
    if hndl_exposure == HNDLExposure.MEDIUM:
        return (
            f"This asset uses a {threat_desc} and protects data with a "
            f"{lifetime_desc}. Data may be at risk if CRQC arrives sooner than "
            f"the {quantum_arrival_years:.1f}-year baseline assumption."
        )
    # LOW
    return (
        f"This asset uses a {threat_desc}, but the protected data lifetime "
        f"({lifetime_desc}) falls well within the {quantum_arrival_years:.1f}-year "
        f"quantum horizon. HNDL exposure is low under the baseline scenario."
    )
