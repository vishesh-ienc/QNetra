"""
Report & Export Endpoints for QNetra.

Exposes dedicated routes for:
- Executive Cryptographic Assessment (PDF)
- PQC Migration Plan (PDF, CSV, JSON)
- Complete Technical Assessment (PDF)
- Normalized Crypto Assets (CSV, JSON)
- Evidence & Findings (CSV, JSON)
- Custom Export Center (PDF, CSV, JSON)

Performance: Fully optimized with lazy section parsing and thread-safe in-memory caching.
"""

from __future__ import annotations

import json as jsonlib
from typing import List, Literal, Optional

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, Field

from backend.errors import ApiError, scan_not_found, validation_error
from backend.reports.cache import report_cache
from backend.reports.csv_builder import (
    build_assets_csv,
    build_custom_csv,
    build_findings_csv,
    build_migration_csv,
)
from backend.reports.data import extract_report_data, sanitize_target_name
from backend.reports.json_builder import build_custom_json
from backend.reports.pdf import (
    build_custom_pdf,
    build_executive_pdf,
    build_migration_pdf,
    build_technical_pdf,
)
from backend.store import store

router = APIRouter(prefix="/scans/{scan_id}/reports", tags=["reports"])

VALID_SECTIONS = {"assets", "findings", "risk", "quantum", "mosca", "migration", "cbom"}


class CustomExportRequest(BaseModel):
    sections: List[str] = Field(
        ...,
        description="Selected sections: assets, findings, risk, quantum, mosca, migration, cbom",
    )
    format: Literal["pdf", "json", "csv"] = Field(
        "pdf", description="Export format: pdf, json, or csv"
    )


def _check_scan_ready(scan_id: str):
    scan = store.get_scan(scan_id)
    if scan is None:
        raise scan_not_found(scan_id)
    if scan.status not in ("COMPLETED", "PARTIAL"):
        raise ApiError(
            400,
            "SCAN_NOT_READY",
            f"Cannot generate report for scan {scan_id} in status {scan.status}. Scan must be COMPLETED.",
        )
    return scan


def _cached_or_build(scan_id: str, report_type: str, format_type: str, builder_fn):
    """Fast path: serves cached report bytes instantly if already compiled."""
    cached = report_cache.get(scan_id, report_type, format_type)
    if cached is not None:
        content, media_type, filename = cached
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Report-Cache": "HIT",
            },
        )

    content, media_type, filename = builder_fn()
    report_cache.set(scan_id, report_type, format_type, content, media_type, filename)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Cache": "MISS",
        },
    )


@router.get("/executive")
def export_executive_report(scan_id: str):
    scan = _check_scan_ready(scan_id)

    def _build():
        # Fast path: executive report does not need raw findings table
        data = extract_report_data(scan, include_findings=False)
        pdf_bytes = build_executive_pdf(data)
        filename = f"qnetra-executive-assessment-{data.safe_target}.pdf"
        return pdf_bytes, "application/pdf", filename

    return _cached_or_build(scan_id, "executive", "pdf", _build)


@router.get("/migration")
def export_migration_report(
    scan_id: str,
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),
):
    scan = _check_scan_ready(scan_id)

    def _build():
        # Fast path: migration report does not need raw findings table
        data = extract_report_data(scan, include_findings=False)
        if format == "pdf":
            content = build_migration_pdf(data)
            media_type = "application/pdf"
            filename = f"qnetra-pqc-migration-plan-{data.safe_target}.pdf"
        elif format == "csv":
            content = build_migration_csv(data)
            media_type = "text/csv"
            filename = f"qnetra-pqc-migration-plan-{data.safe_target}.csv"
        else:
            content = jsonlib.dumps(
                {
                    "scan": data.scan_meta,
                    "summary": {
                        "direct_pqc_count": data.direct_pqc_count,
                        "classical_upgrade_count": data.classical_upgrade_count,
                        "hybrid_count": data.hybrid_count,
                        "already_pqc_count": data.already_pqc_count,
                        "no_migration_required_count": data.no_migration_required_count,
                    },
                    "migration_actions": data.migration_actions,
                },
                indent=2,
            )
            media_type = "application/json"
            filename = f"qnetra-pqc-migration-plan-{data.safe_target}.json"
        return content, media_type, filename

    return _cached_or_build(scan_id, "migration", format, _build)


@router.get("/technical")
def export_technical_report(scan_id: str):
    scan = _check_scan_ready(scan_id)

    def _build():
        data = extract_report_data(scan, include_findings=True)
        pdf_bytes = build_technical_pdf(data)
        filename = f"qnetra-complete-assessment-{data.safe_target}.pdf"
        return pdf_bytes, "application/pdf", filename

    return _cached_or_build(scan_id, "technical", "pdf", _build)


@router.get("/assets")
def export_assets(
    scan_id: str,
    format: str = Query("csv", pattern="^(csv|json)$"),
):
    scan = _check_scan_ready(scan_id)

    def _build():
        data = extract_report_data(scan, include_findings=False)
        if format == "csv":
            content = build_assets_csv(data)
            media_type = "text/csv"
            filename = f"qnetra-crypto-assets-{data.safe_target}.csv"
        else:
            content = jsonlib.dumps(
                {"scan": data.scan_meta, "assets": data.assets},
                indent=2,
            )
            media_type = "application/json"
            filename = f"qnetra-crypto-assets-{data.safe_target}.json"
        return content, media_type, filename

    return _cached_or_build(scan_id, "assets", format, _build)


@router.get("/findings")
def export_findings(
    scan_id: str,
    format: str = Query("csv", pattern="^(csv|json)$"),
):
    scan = _check_scan_ready(scan_id)

    def _build():
        data = extract_report_data(scan, include_findings=True)
        if format == "csv":
            content = build_findings_csv(data)
            media_type = "text/csv"
            filename = f"qnetra-evidence-{data.safe_target}.csv"
        else:
            content = jsonlib.dumps(
                {"scan": data.scan_meta, "findings": data.findings},
                indent=2,
            )
            media_type = "application/json"
            filename = f"qnetra-evidence-{data.safe_target}.json"
        return content, media_type, filename

    return _cached_or_build(scan_id, "findings", format, _build)


@router.post("/custom")
def export_custom_report(scan_id: str, body: CustomExportRequest):
    scan = _check_scan_ready(scan_id)

    # Validate sections
    cleaned_sections = [s.strip().lower() for s in body.sections if s.strip().lower() in VALID_SECTIONS]
    if not cleaned_sections:
        raise validation_error("At least one valid section must be selected for custom export.")

    # Compatibility guard for CSV
    if body.format == "csv":
        tabular_sections = {"assets", "findings", "migration"}
        if not (set(cleaned_sections) & tabular_sections):
            raise validation_error(
                f"Selected sections {cleaned_sections} cannot be represented as CSV. "
                "Please select Assets, Evidence & Findings, or Migration Plan, or choose PDF/JSON format."
            )

    sections_key = "-".join(sorted(cleaned_sections))
    cache_key = f"custom-{sections_key}"

    def _build():
        need_findings = "findings" in cleaned_sections
        data = extract_report_data(scan, include_findings=need_findings)

        if body.format == "pdf":
            content = build_custom_pdf(data, cleaned_sections)
            media_type = "application/pdf"
            filename = f"qnetra-custom-assessment-{data.safe_target}.pdf"
        elif body.format == "csv":
            content = build_custom_csv(data, cleaned_sections)
            media_type = "text/csv"
            filename = f"qnetra-custom-assessment-{data.safe_target}.csv"
        else:
            json_obj = build_custom_json(data, cleaned_sections, raw_assets=scan.assets)
            content = jsonlib.dumps(json_obj, indent=2)
            media_type = "application/json"
            filename = f"qnetra-custom-assessment-{data.safe_target}.json"

        return content, media_type, filename

    return _cached_or_build(scan_id, cache_key, body.format, _build)
