from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from backend.errors import finding_not_found, scan_not_found
from backend.filtering import ListParams, apply_search, apply_sort, paginate
from backend.serializers import finding_dict
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/findings", tags=["findings"])

SEARCH_FIELDS = ["raw_symbol", "suspected_algorithm", "library_hint"]


@router.get("")
def list_findings(
    scan_id: str,
    params: ListParams = Depends(),
    algorithm: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    method: Optional[str] = Query(None),
    min_confidence: Optional[float] = Query(None),
):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)

    rows = [finding_dict(f) for f in scan.findings]

    if algorithm:
        rows = [r for r in rows if r["suspected_algorithm"] == algorithm]
    if category:
        rows = [r for r in rows if r["artifact_category"] == category]
    if scanner:
        rows = [r for r in rows if scanner.lower() in r["scanner_name"].lower()]
    if method:
        rows = [r for r in rows if r["discovery_method"] == method]
    if min_confidence is not None:
        rows = [r for r in rows if r["confidence_score"] >= min_confidence]
    # location.file_path is searched alongside the top-level text fields.
    if params.q:
        rows = [
            r
            for r in rows
            if params.q in " ".join(str(r.get(f) or "") for f in SEARCH_FIELDS).lower()
            or params.q in r["location"]["file_path"].lower()
        ]

    rows = apply_sort(rows, params.sort or "confidence_score", params.order)
    return paginate(rows, params.page, params.page_size)


@router.get("/{finding_id}")
def get_finding(scan_id: str, finding_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    for f in scan.findings:
        if f.finding_id == finding_id:
            return finding_dict(f)
    raise finding_not_found(finding_id)
