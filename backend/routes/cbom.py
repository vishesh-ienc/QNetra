from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Query, Response

from core.cbom_generator.serializer import CBOMSerializer

from backend.errors import scan_not_found, validation_error
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/cbom", tags=["cbom"])


def _serializer() -> CBOMSerializer:
    return CBOMSerializer(tool_version="1.0.0")


@router.get("")
def get_cbom(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    # Deterministic=False + the scan's own completion time: a live timestamp on
    # a document produced from a specific, identifiable scan run.
    ts = scan.completed_at or datetime.now(timezone.utc)
    return _serializer().to_json_dict(scan.assets, deterministic=False, scan_timestamp=ts)


@router.get("/export")
def export_cbom(scan_id: str, format: str = Query("json", pattern="^(json|xml)$")):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    ts = scan.completed_at or datetime.now(timezone.utc)
    serializer = _serializer()

    if format == "json":
        body = serializer.to_json(scan.assets, deterministic=False, scan_timestamp=ts)
        media_type = "application/json"
        ext = "json"
    else:
        body = serializer.to_xml(scan.assets, deterministic=False, scan_timestamp=ts)
        media_type = "application/xml"
        ext = "xml"

    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="qnetra-cbom-{scan_id}.{ext}"'
        },
    )
