from __future__ import annotations

import threading
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.errors import artifact_not_found, scan_not_found, validation_error
from backend.pipeline import run_pipeline
from backend.serializers import progress_dict, scan_dict
from backend.store import ScanRecord, new_id, store

router = APIRouter(prefix="/scans", tags=["scans"])


class MoscaParams(BaseModel):
    data_shelf_life_years_x: Optional[float] = None
    migration_time_years_y: Optional[float] = None
    quantum_threat_horizon_years_z: Optional[float] = None


class CreateScanRequest(BaseModel):
    name: Optional[str] = None
    artifact_id: str
    target_type: str = Field(default="AUTO")
    mosca_params: Optional[MoscaParams] = None


@router.post("", status_code=202)
def create_scan(body: CreateScanRequest):
    artifact = store.get_artifact(body.artifact_id)
    if artifact is None:
        raise artifact_not_found(body.artifact_id)

    valid_types = {"REPOSITORY", "CONTAINER_FS", "BINARY", "AUTO"}
    if body.target_type not in valid_types:
        raise validation_error(
            f"target_type must be one of {sorted(valid_types)}.",
            [{"field": "target_type", "error": "invalid enum value"}],
        )

    scan = ScanRecord(
        scan_id=new_id(),
        name=body.name or artifact.name,
        artifact_id=artifact.artifact_id,
        target_path=str(artifact.path),
        target_type=body.target_type,
        target_name=artifact.name,
    )
    scan.status = "QUEUED"
    store.put_scan(scan)

    mosca = body.mosca_params or MoscaParams()

    def _worker() -> None:
        scan.status = "RUNNING"
        run_pipeline(
            scan,
            data_shelf_life_years_x=mosca.data_shelf_life_years_x,
            migration_time_years_y=mosca.migration_time_years_y,
            quantum_threat_horizon_years_z=mosca.quantum_threat_horizon_years_z,
        )

    threading.Thread(target=_worker, daemon=True).start()
    return scan_dict(scan)


@router.get("")
def list_scans():
    scans = store.list_scans()
    return {
        "data": [scan_dict(s) for s in scans],
        "pagination": {
            "page": 1,
            "page_size": max(len(scans), 1),
            "total_items": len(scans),
            "total_pages": 1,
        },
    }


@router.get("/{scan_id}")
def get_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    return scan_dict(scan)


@router.get("/{scan_id}/progress")
def get_progress(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    return progress_dict(scan)
