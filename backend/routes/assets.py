from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from backend.errors import asset_not_found, scan_not_found
from backend.filtering import ListParams, apply_sort, paginate
from backend.serializers import asset_dict
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/assets", tags=["assets"])

SEARCH_FIELDS = ["algorithm", "implementation_library", "primitive_type"]


@router.get("")
def list_assets(
    scan_id: str,
    params: ListParams = Depends(),
    algorithm: Optional[str] = Query(None),
    primitive_type: Optional[str] = Query(None),
    quantum_vulnerable: Optional[bool] = Query(None),
    quantum_threat_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    library: Optional[str] = Query(None),
):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)

    rows = [asset_dict(a) for a in scan.assets]

    if algorithm:
        rows = [r for r in rows if r["algorithm"] == algorithm]
    if primitive_type:
        rows = [r for r in rows if r["primitive_type"] == primitive_type]
    if quantum_vulnerable is not None:
        rows = [r for r in rows if r["quantum_vulnerable"] == quantum_vulnerable]
    if quantum_threat_type:
        rows = [r for r in rows if r["quantum_threat_type"] == quantum_threat_type]
    if severity:
        rows = [r for r in rows if r["risk_severity"] == severity]
    if library:
        rows = [r for r in rows if r["implementation_library"] == library]
    if params.q:
        rows = [
            r
            for r in rows
            if params.q in " ".join(str(r.get(f) or "") for f in SEARCH_FIELDS).lower()
            or params.q in r["location"]["file_path"].lower()
        ]

    rows = apply_sort(rows, params.sort or "risk_score", params.order)
    return paginate(rows, params.page, params.page_size)


@router.get("/{asset_id}")
def get_asset(scan_id: str, asset_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    for a in scan.assets:
        if a.asset_id == asset_id:
            return asset_dict(a)
    raise asset_not_found(asset_id)
