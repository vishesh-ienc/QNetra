"""
Structured CSV serialization for QNetra reports.

Provides dedicated CSV exports for Crypto Assets, Evidence & Findings,
PQC Migration Plan, and Custom Export selections.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from backend.reports.data import ReportData

ASSET_CSV_COLUMNS = [
    "asset_id",
    "algorithm",
    "primitive_type",
    "key_length_bits",
    "curve",
    "mode",
    "padding",
    "implementation_library",
    "primary_location",
    "confidence_level",
    "confidence_score",
    "classical_security_status",
    "effective_classical_security_bits",
    "quantum_vulnerable",
    "quantum_threat_type",
    "quantum_security_status",
    "effective_quantum_security_bits",
    "risk_score",
    "risk_severity",
    "mosca_urgency",
    "hndl_exposure",
    "exposure_gap_years",
    "recommendation_type",
    "recommended_algorithm",
    "pqc_standard",
    "hybrid_recommendation",
    "supporting_finding_ids",
]

FINDINGS_CSV_COLUMNS = [
    "finding_id",
    "scanner_name",
    "discovery_method",
    "suspected_algorithm",
    "artifact_category",
    "file_path",
    "start_line",
    "end_line",
    "confidence_level",
    "confidence_score",
    "raw_symbol",
    "snippet",
    "associated_asset_id",
]

MIGRATION_CSV_COLUMNS = [
    "asset_id",
    "current_algorithm",
    "current_primitive",
    "risk_score",
    "risk_severity",
    "quantum_threat",
    "quantum_security_status",
    "migration_category",
    "recommended_algorithm",
    "pqc_standard",
    "hybrid_scheme",
    "urgency",
    "hndl_exposure",
    "exposure_gap_years",
    "migration_complexity",
    "primary_location",
    "rationale",
]


def build_assets_csv(data: ReportData) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=ASSET_CSV_COLUMNS)
    writer.writeheader()
    for a in data.assets:
        loc = a.get("location") or {}
        loc_str = f"{loc.get('file_path', '')}:{loc.get('start_line', '')}".rstrip(":")
        finding_ids = ";".join(a.get("supporting_finding_ids", []))
        writer.writerow(
            {
                "asset_id": a.get("asset_id"),
                "algorithm": a.get("algorithm"),
                "primitive_type": a.get("primitive_type"),
                "key_length_bits": a.get("key_length_bits"),
                "curve": a.get("curve"),
                "mode": a.get("mode"),
                "padding": a.get("padding"),
                "implementation_library": a.get("implementation_library"),
                "primary_location": loc_str,
                "confidence_level": a.get("confidence_level"),
                "confidence_score": a.get("confidence_score"),
                "classical_security_status": a.get("classical_security_status"),
                "effective_classical_security_bits": a.get("effective_classical_security_bits"),
                "quantum_vulnerable": a.get("quantum_vulnerable"),
                "quantum_threat_type": a.get("quantum_threat_type"),
                "quantum_security_status": a.get("quantum_security_status"),
                "effective_quantum_security_bits": a.get("effective_quantum_security_bits"),
                "risk_score": a.get("risk_score"),
                "risk_severity": a.get("risk_severity"),
                "mosca_urgency": a.get("mosca_urgency"),
                "hndl_exposure": a.get("hndl_exposure"),
                "exposure_gap_years": a.get("exposure_gap_years"),
                "recommendation_type": a.get("recommendation_type"),
                "recommended_algorithm": a.get("recommended_algorithm"),
                "pqc_standard": a.get("pqc_standard"),
                "hybrid_recommendation": a.get("hybrid_recommendation"),
                "supporting_finding_ids": finding_ids,
            }
        )
    return buffer.getvalue()


def build_findings_csv(data: ReportData) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FINDINGS_CSV_COLUMNS)
    writer.writeheader()
    for f in data.findings:
        loc = f.get("location") or {}
        writer.writerow(
            {
                "finding_id": f.get("finding_id"),
                "scanner_name": f.get("scanner_name"),
                "discovery_method": f.get("discovery_method"),
                "suspected_algorithm": f.get("suspected_algorithm"),
                "artifact_category": f.get("artifact_category"),
                "file_path": loc.get("file_path"),
                "start_line": loc.get("start_line"),
                "end_line": loc.get("end_line"),
                "confidence_level": f.get("confidence_level"),
                "confidence_score": f.get("confidence_score"),
                "raw_symbol": f.get("raw_symbol"),
                "snippet": (loc.get("snippet") or "").strip().replace("\n", " "),
                "associated_asset_id": f.get("associated_asset_id"),
            }
        )
    return buffer.getvalue()


def build_migration_csv(data: ReportData) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=MIGRATION_CSV_COLUMNS)
    writer.writeheader()
    for m in data.migration_actions:
        writer.writerow(
            {
                "asset_id": m.get("asset_id"),
                "current_algorithm": m.get("current_algorithm"),
                "current_primitive": m.get("current_primitive"),
                "risk_score": m.get("risk_score"),
                "risk_severity": m.get("risk_severity"),
                "quantum_threat": m.get("quantum_threat"),
                "quantum_security_status": m.get("quantum_security_status"),
                "migration_category": m.get("migration_category"),
                "recommended_algorithm": m.get("recommended_algorithm"),
                "pqc_standard": m.get("pqc_standard"),
                "hybrid_scheme": m.get("hybrid_scheme"),
                "urgency": m.get("urgency"),
                "hndl_exposure": m.get("hndl_exposure"),
                "exposure_gap_years": m.get("exposure_gap_years"),
                "migration_complexity": m.get("migration_complexity"),
                "primary_location": m.get("location_str"),
                "rationale": m.get("rationale"),
            }
        )
    return buffer.getvalue()


def build_custom_csv(data: ReportData, sections: list[str]) -> str:
    """
    Format selected sections into CSV.
    If a single domain is selected, returns its full dedicated schema.
    If multiple domains are selected, combines them into a sectioned CSV.
    """
    selected = set(sections)
    if selected == {"findings"}:
        return build_findings_csv(data)
    if selected == {"migration"}:
        return build_migration_csv(data)
    if selected == {"assets"} or (selected and not (selected & {"findings", "migration"})):
        return build_assets_csv(data)

    # Multi-section CSV: write each selected tabular section separated by headers
    out = []
    if "assets" in selected:
        out.append("# --- CRYPTO ASSETS ---")
        out.append(build_assets_csv(data))
    if "migration" in selected:
        out.append("# --- PQC MIGRATION PLAN ---")
        out.append(build_migration_csv(data))
    if "findings" in selected:
        out.append("# --- EVIDENCE & FINDINGS ---")
        out.append(build_findings_csv(data))
    return "\n\n".join(out)
