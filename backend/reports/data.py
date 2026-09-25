"""
Unified Report Data Extraction & Transformation Layer.

Extracts normalized information from an existing ScanRecord and pre-computed
intelligence engines (Risk, Mosca, Recommendations, CBOM).
Does NOT re-calculate or alter any scan conclusions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from backend.serializers import (
    asset_dict,
    finding_dict,
    mosca_report_dict,
    recommendation_report_dict,
    risk_report_dict,
    scan_dict,
)
from backend.store import ScanRecord


def sanitize_target_name(target: Optional[str]) -> str:
    """
    Sanitize repository or target name into a safe string for filenames.
    Prevents path traversal and unwanted characters.
    """
    if not target:
        return "unnamed"

    # If it's a URL, take the repo segment
    clean = target.rstrip("/")
    if "github.com/" in clean:
        clean = clean.split("github.com/")[-1]

    # Replace slashes, colons, spaces, and punctuation with hyphens
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "-", clean)
    clean = re.sub(r"-+", "-", clean).strip("-_")
    return clean.lower() or "target"


@dataclass
class ReportData:
    scan_id: str
    target_name: str
    safe_target: str
    source_type: str
    source_url: Optional[str]
    status: str
    completed_at: Optional[datetime]
    completed_at_str: str
    duration_seconds: Optional[float]
    scan_meta: dict[str, Any]

    # Risk metrics
    overall_risk_score: float
    overall_severity: str
    total_assets: int
    vulnerable_assets_count: int
    shor_vulnerable_count: int
    grover_impacted_count: int
    classically_broken_count: int
    quantum_resistant_count: int
    severity_distribution: dict[str, int]
    risk_report: dict[str, Any]

    # Mosca metrics
    mosca_parameters: dict[str, Any]
    mosca_applicable_count: int
    mosca_triggered_count: int
    hndl_exposed_count: int
    mosca_urgency_distribution: dict[str, int]
    mosca_report: dict[str, Any]

    # Recommendations
    direct_pqc_count: int
    classical_upgrade_count: int
    hybrid_count: int
    already_pqc_count: int
    no_migration_required_count: int
    recommendation_report: dict[str, Any]

    # Catalogs
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    migration_actions: list[dict[str, Any]] = field(default_factory=list)
    cbom_component_count: int = 0


def extract_report_data(scan: ScanRecord, include_findings: bool = True) -> ReportData:
    """
    Assemble the complete joined report dataset from a ScanRecord.
    All data is read directly from what the scan pipeline already produced.
    Fast path: memoized on scan record and supports include_findings=False for speed.
    """
    cache_attr = "_cached_report_full" if include_findings else "_cached_report_lean"
    cached = getattr(scan, cache_attr, None)
    if cached is not None:
        return cached

    s_dict = scan_dict(scan)
    r_dict = risk_report_dict(scan)
    m_dict = mosca_report_dict(scan)
    rec_dict = recommendation_report_dict(scan)

    target_name = scan.target_name or scan.name or "Scan Target"
    safe_target = sanitize_target_name(target_name)

    completed_dt = scan.completed_at
    completed_str = (
        completed_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        if completed_dt
        else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    # Index risk assessments by asset_id
    risk_by_asset: dict[str, dict[str, Any]] = {
        a["asset_id"]: a for a in r_dict.get("assessments", [])
    }
    # Index mosca assessments by asset_id
    mosca_by_asset: dict[str, dict[str, Any]] = {
        a["asset_id"]: a for a in m_dict.get("assessments", [])
    }
    # Index recommendations by asset_id
    rec_by_asset: dict[str, dict[str, Any]] = {
        r["asset_id"]: r for r in rec_dict.get("recommendations", [])
    }

    # Normalized assets with joined intelligence
    joined_assets: list[dict[str, Any]] = []
    for raw_asset in scan.assets:
        a_dict = asset_dict(raw_asset)
        asset_id = a_dict["asset_id"]

        r_item = risk_by_asset.get(asset_id, {})
        m_item = mosca_by_asset.get(asset_id, {})
        rec_item = rec_by_asset.get(asset_id, {})

        a_dict["risk_score"] = r_item.get("risk_score", a_dict.get("risk_score"))
        a_dict["risk_severity"] = r_item.get("severity", a_dict.get("risk_severity"))
        a_dict["risk_rationale"] = r_item.get("rationale")

        a_dict["mosca_urgency"] = m_item.get("urgency")
        a_dict["hndl_exposure"] = m_item.get("hndl_exposure")
        a_dict["x_plus_y"] = m_item.get("x_plus_y")
        a_dict["z_years"] = m_item.get("z_quantum_arrival_years")
        a_dict["exposure_gap_years"] = m_item.get("exposure_gap_years")

        a_dict["recommendation_type"] = rec_item.get("recommendation_type")
        a_dict["recommended_algorithm"] = rec_item.get("recommended_algorithm")
        a_dict["pqc_standard"] = rec_item.get("pqc_standard")
        a_dict["hybrid_recommendation"] = rec_item.get("hybrid_recommendation")
        a_dict["migration_complexity"] = rec_item.get("migration_complexity")
        a_dict["guidance_steps"] = rec_item.get("guidance_steps", [])

        # Format primary location readable
        loc = a_dict.get("location") or {}
        file_path = loc.get("file_path", "unknown")
        start_line = loc.get("start_line")
        a_dict["location_str"] = f"{file_path}:{start_line}" if start_line else file_path

        joined_assets.append(a_dict)

    # Fast O(1) asset index for recommendations
    joined_assets_by_id: dict[str, dict[str, Any]] = {
        a["asset_id"]: a for a in joined_assets
    }

    # Findings (only processed if requested)
    formatted_findings: list[dict[str, Any]] = []
    if include_findings and scan.findings:
        finding_to_asset: dict[str, str] = {}
        for asset in scan.assets:
            for finding_id in asset.supporting_finding_ids:
                finding_to_asset[finding_id] = asset.asset_id

        for raw_finding in scan.findings:
            f_item = finding_dict(raw_finding)
            f_id = f_item["finding_id"]
            f_item["associated_asset_id"] = finding_to_asset.get(f_id)

            loc = f_item.get("location") or {}
            file_path = loc.get("file_path", "unknown")
            start_line = loc.get("start_line")
            end_line = loc.get("end_line")
            line_str = f"{start_line}-{end_line}" if (start_line and end_line and start_line != end_line) else (str(start_line) if start_line else "")
            f_item["location_str"] = f"{file_path}:{line_str}" if line_str else file_path

            formatted_findings.append(f_item)

    # Prioritized migration actions with O(1) lookup
    migration_actions: list[dict[str, Any]] = []
    urgency_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
    for rec in rec_dict.get("recommendations", []):
        asset_id = rec["asset_id"]
        r_item = risk_by_asset.get(asset_id, {})
        m_item = mosca_by_asset.get(asset_id, {})
        matched_asset = joined_assets_by_id.get(asset_id)

        action = {
            "asset_id": asset_id,
            "current_algorithm": rec.get("current_algorithm", ""),
            "current_primitive": rec.get("current_primitive", ""),
            "risk_score": r_item.get("risk_score", 0),
            "risk_severity": r_item.get("severity", "LOW"),
            "quantum_threat": matched_asset.get("quantum_threat_type") if matched_asset else "UNKNOWN",
            "quantum_security_status": matched_asset.get("quantum_security_status") if matched_asset else "UNKNOWN",
            "migration_category": rec.get("recommendation_type", "NO_MIGRATION_REQUIRED"),
            "recommendation": rec.get("recommendation_type", ""),
            "recommended_algorithm": rec.get("recommended_algorithm", "N/A"),
            "pqc_standard": rec.get("pqc_standard", "N/A"),
            "hybrid_scheme": rec.get("hybrid_recommendation"),
            "urgency": m_item.get("urgency", "LOW"),
            "hndl_exposure": m_item.get("hndl_exposure", False),
            "exposure_gap_years": m_item.get("exposure_gap_years"),
            "migration_complexity": rec.get("migration_complexity", "MEDIUM"),
            "location_str": matched_asset.get("location_str", "") if matched_asset else "",
            "rationale": rec.get("rationale", ""),
            "guidance_steps": rec.get("guidance_steps", []),
        }
        migration_actions.append(action)

    migration_actions.sort(
        key=lambda x: (
            urgency_order.get(x["risk_severity"], 4),
            -(x["risk_score"] or 0),
            urgency_order.get(x["urgency"], 4),
        )
    )

    report_data = ReportData(
        scan_id=scan.scan_id,
        target_name=target_name,
        safe_target=safe_target,
        source_type=scan.source_type,
        source_url=scan.source_url,
        status=scan.status,
        completed_at=completed_dt,
        completed_at_str=completed_str,
        duration_seconds=scan.duration_seconds,
        scan_meta=s_dict,
        overall_risk_score=r_dict.get("overall_risk_score", 0.0),
        overall_severity=r_dict.get("overall_severity", "LOW"),
        total_assets=len(scan.assets),
        vulnerable_assets_count=r_dict.get("vulnerable_assets_count", 0),
        shor_vulnerable_count=r_dict.get("shor_vulnerable_count", 0),
        grover_impacted_count=r_dict.get("grover_impacted_count", 0),
        classically_broken_count=r_dict.get("classically_broken_count", 0),
        quantum_resistant_count=r_dict.get("quantum_resistant_count", 0),
        severity_distribution=r_dict.get("severity_distribution", {}),
        risk_report=r_dict,
        mosca_parameters=m_dict.get("parameters", {}),
        mosca_applicable_count=m_dict.get("mosca_applicable_assets", 0),
        mosca_triggered_count=m_dict.get("mosca_triggered_assets", 0),
        hndl_exposed_count=m_dict.get("hndl_exposed_assets", 0),
        mosca_urgency_distribution=m_dict.get("urgency_distribution", {}),
        mosca_report=m_dict,
        direct_pqc_count=rec_dict.get("direct_pqc_count", 0),
        classical_upgrade_count=rec_dict.get("classical_upgrade_count", 0),
        hybrid_count=rec_dict.get("hybrid_count", 0),
        already_pqc_count=rec_dict.get("already_pqc_count", 0),
        no_migration_required_count=rec_dict.get("no_migration_required_count", 0),
        recommendation_report=rec_dict,
        assets=joined_assets,
        findings=formatted_findings,
        migration_actions=migration_actions,
        cbom_component_count=len(scan.assets),
    )
    try:
        setattr(scan, cache_attr, report_data)
    except Exception:
        pass
    return report_data
