"""
Combined export endpoints (docs/10_API_CONTRACT.md §15).

Every field here is read from data the pipeline already computed for this
scan — this route composes and formats, it does not analyse. PDF is not
implemented: no engine in core/ produces report prose or page layout, and
inventing one would be new work, not exposure of existing output, so it is
declined honestly rather than faked.
"""

from __future__ import annotations

import csv
import io
import json as jsonlib
from datetime import datetime, timezone

from fastapi import APIRouter, Query, Response

from backend.errors import ApiError, scan_not_found
from backend.serializers import (
    asset_dict,
    finding_dict,
    mosca_report_dict,
    recommendation_report_dict,
    risk_report_dict,
    scan_dict,
)
from backend.store import store
from core.cbom_generator.serializer import CBOMSerializer

router = APIRouter(prefix="/scans/{scan_id}/export", tags=["export"])

CSV_COLUMNS = [
    "asset_id",
    "algorithm",
    "primitive_type",
    "risk_score",
    "risk_severity",
    "risk_rationale",
    "mosca_urgency",
    "hndl_exposure",
    "x_plus_y_years",
    "z_years",
    "exposure_gap_years",
    "recommendation_type",
    "recommended_algorithm",
    "pqc_standard",
    "hybrid_scheme",
    "migration_complexity",
]


@router.get("")
def export_scan(scan_id: str, format: str = Query("json", pattern="^(json|csv|pdf)$")):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)

    if format == "pdf":
        raise ApiError(
            501,
            "NOT_IMPLEMENTED",
            "No engine in core/ generates report prose or page layout. Producing a PDF here "
            "would author a document the pipeline never produced, so it is not implemented.",
        )

    if format == "json":
        ts = scan.completed_at or datetime.now(timezone.utc)
        envelope = {
            "scan": scan_dict(scan),
            "findings": [finding_dict(f) for f in scan.findings],
            "assets": [asset_dict(a) for a in scan.assets],
            "risk": risk_report_dict(scan),
            "mosca": mosca_report_dict(scan),
            "recommendations": recommendation_report_dict(scan),
            "cbom": CBOMSerializer().to_json_dict(scan.assets, deterministic=False, scan_timestamp=ts),
        }
        return Response(
            content=jsonlib.dumps(envelope, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="qnetra-report-{scan_id}.json"'},
        )

    # format == "csv" — one row per asset, joining the risk/mosca/recommendation
    # engines' own output by asset_id. No column here is computed by this route.
    risk_by_asset = {a["asset_id"]: a for a in risk_report_dict(scan)["assessments"]}
    mosca_by_asset = {a["asset_id"]: a for a in mosca_report_dict(scan)["assessments"]}

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for rec in recommendation_report_dict(scan)["recommendations"]:
        r = risk_by_asset.get(rec["asset_id"], {})
        m = mosca_by_asset.get(rec["asset_id"], {})
        writer.writerow(
            {
                "asset_id": rec["asset_id"],
                "algorithm": rec["current_algorithm"],
                "primitive_type": rec["current_primitive"],
                "risk_score": r.get("risk_score"),
                "risk_severity": r.get("severity"),
                "risk_rationale": r.get("rationale"),
                "mosca_urgency": m.get("urgency"),
                "hndl_exposure": m.get("hndl_exposure"),
                "x_plus_y_years": m.get("x_plus_y"),
                "z_years": m.get("z_quantum_arrival_years"),
                "exposure_gap_years": m.get("exposure_gap_years"),
                "recommendation_type": rec["recommendation_type"],
                "recommended_algorithm": rec["recommended_algorithm"],
                "pqc_standard": rec["pqc_standard"],
                "hybrid_scheme": rec["hybrid_recommendation"],
                "migration_complexity": rec["migration_complexity"],
            }
        )
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="qnetra-inventory-{scan_id}.csv"'},
    )
