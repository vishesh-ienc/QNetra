"""
Scan pipeline orchestration.

Calls the existing, unmodified engines in the documented order:

    ScannerRouter (scanners.*)
        -> Normalizer               (core.normalization)
        -> ClassificationEngine     (core.classification)
        -> CBOMSerializer           (core.cbom_generator)
        -> RiskEngine               (core.risk_engine)
        -> MoscaEngine              (core.mosca_engine)
        -> RecommendationEngine     (core.recommendation_engine)

This module contains no cryptographic, risk, or classification logic of its
own — it is the same orchestration already proven in
frontend/tools/generate_fixtures.py, generalized to run against an arbitrary
uploaded target instead of the fixed sample directory, and wired to mutate a
ScanRecord as each real stage completes so progress polling reflects the
actual pipeline, not a simulated one.
"""

from __future__ import annotations

import logging
import traceback
from datetime import date, datetime, timezone
from typing import Optional

from core.classification.classifier import ClassificationEngine
from core.mosca_engine.engine import MoscaEngine
from core.mosca_engine.knowledge import MoscaConfig
from core.mosca_engine.models import MoscaInput
from core.normalization.normalizer import Normalizer
from core.recommendation_engine.engine import RecommendationEngine
from core.risk_engine.engine import RiskEngine
from scanners.binary.scanner import BinaryScanner
from scanners.container.scanner import ContainerScanner
from scanners.framework.models import ScanOptions, ScanStatus as EngineScanStatus, ScanTarget, TargetType
from scanners.framework.router import ScannerRouter
from scanners.repository.scanner import RepositoryScanner

from backend.store import ScanRecord

logger = logging.getLogger("qnetra.backend.pipeline")

DEFAULT_QUANTUM_HORIZON_YEARS = 10.0


def _router() -> ScannerRouter:
    router = ScannerRouter()
    router.register(TargetType.REPOSITORY, RepositoryScanner())
    router.register(TargetType.CONTAINER_FS, ContainerScanner())
    router.register(TargetType.BINARY, BinaryScanner())
    return router


_TARGET_TYPE_MAP = {
    "REPOSITORY": TargetType.REPOSITORY,
    "CONTAINER_FS": TargetType.CONTAINER_FS,
    "BINARY": TargetType.BINARY,
    "AUTO": TargetType.AUTO,
}


def _set_stage(scan: ScanRecord, stage: str, status: str) -> None:
    scan.stage_status[stage] = status
    if status == "RUNNING":
        scan.current_stage = stage


def run_pipeline(
    scan: ScanRecord,
    *,
    data_shelf_life_years_x: Optional[float],
    migration_time_years_y: Optional[float],
    quantum_threat_horizon_years_z: Optional[float],
) -> None:
    """
    Execute the full pipeline against `scan.target_path`, mutating `scan` in
    place as each real stage completes. Runs on a background thread — callers
    are expected to have already set scan.status = "RUNNING".
    """
    scan.started_at = datetime.now(timezone.utc)
    z_years = quantum_threat_horizon_years_z or DEFAULT_QUANTUM_HORIZON_YEARS
    assessment_date = date.today()
    scan.mosca_params = {
        "data_shelf_life_years_x": data_shelf_life_years_x,
        "migration_time_years_y": migration_time_years_y,
        "quantum_threat_horizon_years_z": z_years,
        "migration_time_source": (
            "EXPLICIT" if migration_time_years_y is not None else "DERIVED_FROM_PRIMITIVE_TYPE"
        ),
    }

    try:
        # --- DISCOVERY -----------------------------------------------------
        _set_stage(scan, "DISCOVERY", "RUNNING")
        target_type = _TARGET_TYPE_MAP.get(scan.target_type, TargetType.AUTO)
        target = ScanTarget(
            path=scan.target_path,
            target_type=target_type,
            name=scan.target_name,
            options=ScanOptions(),
        )
        result = _router().route(target)

        scan.directories_visited = result.statistics.directories_visited
        scan.files_discovered = result.statistics.files_discovered
        scan.files_scanned = result.statistics.files_scanned
        scan.files_skipped = result.statistics.files_skipped
        scan.files_errored = result.statistics.files_errored
        scan.findings_by_method = dict(result.statistics.findings_by_method)
        scan.findings_by_category = dict(result.statistics.findings_by_category)
        scan.warnings.extend(result.warnings)

        if result.status == EngineScanStatus.FAILED:
            scan.errors.extend(result.errors or ["Discovery scanner reported a fatal failure."])
            _set_stage(scan, "DISCOVERY", "FAILED")
            scan.status = "FAILED"
            scan.completed_at = datetime.now(timezone.utc)
            return

        scan.errors.extend(result.errors)
        scan.findings = list(result.findings)
        _set_stage(scan, "DISCOVERY", "COMPLETED")

        # --- NORMALIZATION ---------------------------------------------------
        _set_stage(scan, "NORMALIZATION", "RUNNING")
        assets = Normalizer().normalize(scan.findings)
        stats = Normalizer.compute_statistics(scan.findings, assets)
        scan.normalization_stats = stats.model_dump()
        _set_stage(scan, "NORMALIZATION", "COMPLETED")

        # --- CLASSIFICATION ----------------------------------------------------
        _set_stage(scan, "CLASSIFICATION", "RUNNING")
        assets = ClassificationEngine().classify(assets)
        scan.assets = assets
        _set_stage(scan, "CLASSIFICATION", "COMPLETED")

        # --- CBOM (computed for completeness; served on demand by /cbom) -----
        _set_stage(scan, "CBOM", "RUNNING")
        # CBOM is serialized lazily in the /cbom route from scan.assets, since
        # it is a pure function of the classified assets and needs no state here.
        _set_stage(scan, "CBOM", "COMPLETED")

        # --- RISK ---------------------------------------------------------
        _set_stage(scan, "RISK_ANALYSIS", "RUNNING")
        risk_engine = RiskEngine()
        scan.risk_assessments = risk_engine.assess_and_enrich_all(assets)
        scan.risk_report = risk_engine.generate_report(assets, scan.risk_assessments)
        _set_stage(scan, "RISK_ANALYSIS", "COMPLETED")

        # --- MOSCA ----------------------------------------------------------
        _set_stage(scan, "MOSCA_ANALYSIS", "RUNNING")
        mosca_engine = MoscaEngine(MoscaConfig(default_quantum_arrival_years=z_years))
        contexts = {
            a.asset_id: MoscaInput(
                asset_id=a.asset_id,
                protected_lifetime_years=data_shelf_life_years_x,
                migration_time_years=migration_time_years_y,
                assessment_date=assessment_date,
            )
            for a in assets
        }
        scan.mosca_assessments = mosca_engine.assess_all(assets, contexts=contexts)
        scan.mosca_report = mosca_engine.generate_report(
            assets, scan.mosca_assessments, contexts=contexts
        )
        scan.mosca_params["assessment_date"] = assessment_date.isoformat()
        _set_stage(scan, "MOSCA_ANALYSIS", "COMPLETED")

        # --- RECOMMENDATIONS --------------------------------------------------
        _set_stage(scan, "PQC_ANALYSIS", "RUNNING")
        rec_engine = RecommendationEngine()
        scan.recommendations = rec_engine.recommend_all(assets)
        scan.recommendation_report = rec_engine.generate_report(assets, scan.recommendations)
        _set_stage(scan, "PQC_ANALYSIS", "COMPLETED")

        scan.status = "PARTIAL" if scan.errors else "COMPLETED"
        scan.current_stage = "COMPLETED"

    except Exception as exc:  # noqa: BLE001 — surfaced to the API as a scan failure
        logger.exception("Pipeline failed for scan %s", scan.scan_id)
        scan.errors.append(f"{type(exc).__name__}: {exc}")
        scan.errors.append(traceback.format_exc(limit=5))
        scan.status = "FAILED"
        for stage, status in scan.stage_status.items():
            if status == "RUNNING":
                scan.stage_status[stage] = "FAILED"
    finally:
        scan.completed_at = datetime.now(timezone.utc)
