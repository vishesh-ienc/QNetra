from __future__ import annotations

from fastapi import APIRouter

from backend.errors import scan_not_found
from backend.serializers import risk_report_dict
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/risk", tags=["risk"])


@router.get("")
def get_risk(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    return risk_report_dict(scan)
