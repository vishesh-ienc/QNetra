"""
Structured JSON serialization for QNetra reports and custom exports.
"""

from __future__ import annotations

from typing import Any

from backend.reports.data import ReportData
from core.cbom_generator.serializer import CBOMSerializer


def build_custom_json(data: ReportData, sections: list[str], raw_assets: list[Any] = None) -> dict[str, Any]:
    """
    Build a JSON envelope containing scan metadata and only the requested sections.
    """
    selected = set(sections)
    envelope: dict[str, Any] = {
        "scan": data.scan_meta,
        "exported_sections": list(selected),
    }

    if "assets" in selected:
        envelope["assets"] = data.assets

    if "findings" in selected:
        envelope["findings"] = data.findings

    if "risk" in selected:
        envelope["risk"] = data.risk_report

    if "quantum" in selected:
        envelope["quantum"] = {
            "vulnerable_assets_count": data.vulnerable_assets_count,
            "shor_vulnerable_count": data.shor_vulnerable_count,
            "grover_impacted_count": data.grover_impacted_count,
            "classically_broken_count": data.classically_broken_count,
            "quantum_resistant_count": data.quantum_resistant_count,
            "affected_algorithms": list(
                {a["algorithm"] for a in data.assets if a.get("quantum_vulnerable")}
            ),
        }

    if "mosca" in selected:
        envelope["mosca"] = data.mosca_report

    if "migration" in selected:
        envelope["migration"] = {
            "summary": {
                "direct_pqc_count": data.direct_pqc_count,
                "classical_upgrade_count": data.classical_upgrade_count,
                "hybrid_count": data.hybrid_count,
                "already_pqc_count": data.already_pqc_count,
                "no_migration_required_count": data.no_migration_required_count,
            },
            "actions": data.migration_actions,
        }

    if "cbom" in selected:
        if raw_assets:
            envelope["cbom"] = CBOMSerializer().to_json_dict(
                raw_assets, deterministic=False, scan_timestamp=data.completed_at
            )
        else:
            envelope["cbom"] = {
                "component_count": data.cbom_component_count,
                "assets": data.assets,
            }

    return envelope
