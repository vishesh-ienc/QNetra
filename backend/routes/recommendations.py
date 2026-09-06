from __future__ import annotations

from fastapi import APIRouter

from backend.errors import scan_not_found
from backend.serializers import recommendation_report_dict
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/recommendations", tags=["recommendations"])


@router.get("")
def get_recommendations(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    return recommendation_report_dict(scan)
