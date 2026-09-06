from __future__ import annotations

from datetime import date
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from core.mosca_engine.engine import MoscaEngine
from core.mosca_engine.knowledge import MoscaConfig
from core.mosca_engine.models import MoscaInput

from backend.errors import scan_not_found, validation_error
from backend.pipeline import DEFAULT_QUANTUM_HORIZON_YEARS
from backend.serializers import mosca_report_dict
from backend.store import ScanRecord, store

router = APIRouter(prefix="/scans/{scan_id}/mosca", tags=["mosca"])


class MoscaRequest(BaseModel):
    data_shelf_life_years_x: float
    migration_time_years_y: Optional[float] = None
    quantum_threat_horizon_years_z: Optional[float] = None


def _recompute(
    scan: ScanRecord,
    x: Optional[float],
    y: Optional[float],
    z: Optional[float],
    *,
    persist: bool,
) -> dict:
    """
    Re-evaluates the already-classified assets through core.mosca_engine with
    different X/Y/Z. This calls the same unmodified engine the initial scan
    used — it does not reimplement the inequality.
    """
    z_years = z if z is not None else scan.mosca_params.get("quantum_threat_horizon_years_z", DEFAULT_QUANTUM_HORIZON_YEARS)
    assessment_date = date.today()
    engine = MoscaEngine(MoscaConfig(default_quantum_arrival_years=z_years))
    contexts = {
        a.asset_id: MoscaInput(
            asset_id=a.asset_id,
            protected_lifetime_years=x,
            migration_time_years=y,
            assessment_date=assessment_date,
        )
        for a in scan.assets
    }
    assessments = engine.assess_all(scan.assets, contexts=contexts)
    report = engine.generate_report(scan.assets, assessments, contexts=contexts)
    params = {
        "data_shelf_life_years_x": x,
        "migration_time_years_y": y,
        "quantum_threat_horizon_years_z": z_years,
        "migration_time_source": "EXPLICIT" if y is not None else "DERIVED_FROM_PRIMITIVE_TYPE",
        "assessment_date": assessment_date.isoformat(),
    }

    if persist:
        scan.mosca_assessments = assessments
        scan.mosca_report = report
        scan.mosca_params = params
        return mosca_report_dict(scan)

    payload = report.to_dict()
    payload["scan_id"] = scan.scan_id
    payload["parameters"] = params
    payload["assessments"] = [a.to_dict() for a in assessments]
    payload["assessment_date"] = params["assessment_date"]
    payload["assessed_at"] = None
    return payload


@router.get("")
def get_mosca(
    scan_id: str,
    data_shelf_life_years_x: Optional[float] = Query(None),
    migration_time_years_y: Optional[float] = Query(None),
    quantum_threat_horizon_years_z: Optional[float] = Query(None),
):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)

    no_override = (
        data_shelf_life_years_x is None
        and migration_time_years_y is None
        and quantum_threat_horizon_years_z is None
    )
    if no_override:
        return mosca_report_dict(scan)

    return _recompute(
        scan,
        data_shelf_life_years_x,
        migration_time_years_y,
        quantum_threat_horizon_years_z,
        persist=False,
    )


@router.post("")
def post_mosca(scan_id: str, body: MoscaRequest):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    if body.data_shelf_life_years_x <= 0:
        raise validation_error(
            "data_shelf_life_years_x must be > 0",
            [{"field": "data_shelf_life_years_x", "error": "must be > 0"}],
        )
    return _recompute(
        scan,
        body.data_shelf_life_years_x,
        body.migration_time_years_y,
        body.quantum_threat_horizon_years_z,
        persist=True,
    )
