"""
Response shaping.

These functions only rearrange fields already present on scanner/core objects
into the JSON shapes the frontend expects. No field here is computed — every
value is read off a RawFinding, CryptoAsset, RiskAssessment, MoscaAssessment,
PQCRecommendation or their aggregate reports, all produced upstream by the
unmodified pipeline in scanners/ and core/.
"""

from __future__ import annotations

from typing import Any

from core.models import CryptoAsset
from scanners.framework.models import FileLocation, RawFinding

from backend.store import STAGE_ORDER, ScanRecord


def location_dict(loc: FileLocation) -> dict[str, Any]:
    return {
        "file_path": loc.file_path,
        "start_line": loc.start_line,
        "end_line": loc.end_line,
        "byte_offset": loc.byte_offset,
        "snippet": loc.snippet,
    }


def finding_dict(f: RawFinding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "scanner_name": f.scanner_name,
        "scanner_version": f.scanner_version,
        "discovery_method": f.discovery_method.value,
        "raw_symbol": f.raw_symbol,
        "suspected_algorithm": f.suspected_algorithm,
        "artifact_category": f.artifact_category.value,
        "library_hint": f.library_hint,
        "key_size_hint": f.key_size_hint,
        "mode_hint": f.mode_hint,
        "curve_hint": f.curve_hint,
        "location": location_dict(f.location),
        "confidence_score": round(f.confidence_score, 4),
        "confidence_level": f.confidence_level.value,
        "confidence_rationale": f.confidence_rationale,
        "binary_format": f.binary_format.value if f.binary_format else None,
        "symbol_name": f.symbol_name,
        "container_context": (
            f.container_context.model_dump() if f.container_context else None
        ),
        "raw_parameters": f.raw_parameters,
        "discovered_at": f.discovered_at.isoformat().replace("+00:00", "Z"),
    }


def asset_dict(a: CryptoAsset) -> dict[str, Any]:
    payload = a.to_api_dict()
    payload["locations"] = [location_dict(loc) for loc in a.locations]
    payload["confidence_rationale"] = a.confidence_rationale
    payload["supporting_findings"] = [
        {
            "finding_id": e.finding_id,
            "scanner_name": e.scanner_name,
            "discovery_method": e.discovery_method,
            "raw_symbol": e.raw_symbol,
            "location": location_dict(e.location),
            "confidence_score": round(e.confidence_score, 4),
            "confidence_rationale": e.confidence_rationale,
        }
        for e in a.supporting_findings
    ]
    return payload


def scan_dict(scan: ScanRecord) -> dict[str, Any]:
    def iso(dt):
        return dt.isoformat().replace("+00:00", "Z") if dt else None

    return {
        "scan_id": scan.scan_id,
        "name": scan.name,
        "artifact_id": scan.artifact_id,
        "target": {
            "target_id": scan.scan_id,
            "name": scan.target_name,
            "target_type": scan.target_type,
            "path": scan.target_path,
        },
        "status": scan.status,
        "current_stage": scan.current_stage,
        "created_at": iso(scan.created_at),
        "started_at": iso(scan.started_at),
        "completed_at": iso(scan.completed_at),
        "duration_seconds": scan.duration_seconds,
        "progress": {
            "stages": [
                {"name": name, "status": scan.stage_status.get(name, "WAITING")}
                for name in STAGE_ORDER
            ],
            "directories_visited": scan.directories_visited,
            "files_discovered": scan.files_discovered,
            "files_scanned": scan.files_scanned,
            "files_skipped": scan.files_skipped,
            "files_errored": scan.files_errored,
            "raw_findings_count": len(scan.findings),
            "assets_count": len(scan.assets),
        },
        "discovery": {
            "findings_by_method": scan.findings_by_method,
            "findings_by_category": scan.findings_by_category,
        }
        if scan.status in ("COMPLETED", "PARTIAL")
        else None,
        "normalization": scan.normalization_stats,
        "errors": scan.errors,
        "warnings": scan.warnings,
    }


def progress_dict(scan: ScanRecord) -> dict[str, Any]:
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "current_stage": scan.current_stage,
        "files_discovered": scan.files_discovered,
        "files_scanned": scan.files_scanned,
        "raw_findings_count": len(scan.findings),
        "assets_count": len(scan.assets),
    }


def risk_report_dict(scan: ScanRecord) -> dict[str, Any]:
    report = scan.risk_report
    if report is None:
        return {
            "scan_id": scan.scan_id,
            "overall_risk_score": 0.0,
            "overall_severity": "LOW",
            "total_assets_discovered": 0,
            "vulnerable_assets_count": 0,
            "shor_vulnerable_count": 0,
            "grover_impacted_count": 0,
            "classically_broken_count": 0,
            "quantum_resistant_count": 0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "asset_scores": [],
            "assessments": [],
            "calculated_at": None,
        }
    payload = report.to_dict()
    payload["scan_id"] = scan.scan_id
    payload["assessments"] = [a.to_dict() for a in scan.risk_assessments]
    payload["calculated_at"] = (
        scan.completed_at.isoformat().replace("+00:00", "Z") if scan.completed_at else None
    )
    return payload


def mosca_report_dict(scan: ScanRecord) -> dict[str, Any]:
    report = scan.mosca_report
    if report is None:
        return {
            "scan_id": scan.scan_id,
            "parameters": scan.mosca_params,
            "total_assets": len(scan.assets),
            "mosca_applicable_assets": 0,
            "mosca_triggered_assets": 0,
            "hndl_exposed_assets": 0,
            "urgency_distribution": {},
            "hndl_distribution": {},
            "highest_urgency_assets": [],
            "assessments": [],
            "assessment_date": None,
            "assessed_at": None,
        }
    payload = report.to_dict()
    payload["scan_id"] = scan.scan_id
    payload["parameters"] = scan.mosca_params
    payload["assessments"] = [a.to_dict() for a in scan.mosca_assessments]
    payload["assessment_date"] = scan.mosca_params.get("assessment_date")
    payload["assessed_at"] = (
        scan.completed_at.isoformat().replace("+00:00", "Z") if scan.completed_at else None
    )
    return payload


def recommendation_report_dict(scan: ScanRecord) -> dict[str, Any]:
    report = scan.recommendation_report
    if report is None:
        return {
            "scan_id": scan.scan_id,
            "total_assets": 0,
            "direct_pqc_count": 0,
            "classical_upgrade_count": 0,
            "hybrid_count": 0,
            "already_pqc_count": 0,
            "no_migration_required_count": 0,
            "unknown_count": 0,
            "recommendations_by_target_algorithm": {},
            "recommendations_by_current_algorithm": {},
            "recommendations_by_primitive": {},
            "recommendations": [],
        }
    payload = report.to_dict()
    payload["scan_id"] = scan.scan_id
    payload["recommendations"] = [r.to_dict() for r in scan.recommendations]
    return payload
