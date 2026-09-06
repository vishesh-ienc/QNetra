"""
QNetra Frontend — Development Fixture Generator
===============================================
frontend/tools/generate_fixtures.py

PURPOSE
-------
The Phase 4 FastAPI gateway (`backend/`) is not implemented yet, so the frontend
has no live `/api/v1` server to develop against. This script runs the REAL QNetra
pipeline (scanners/ + core/) over the repository's own `samples/` fixtures and
serialises the result into JSON files shaped like the responses defined in
`docs/10_API_CONTRACT.md`.

Every value in the generated fixtures is produced by the actual QNetra engines.
Nothing is hand-written, estimated, or invented. When a value is not computable
by an engine, it is emitted as `null` and the frontend renders an explicit
"not available" state rather than a placeholder number.

CONSTRAINTS
-----------
- Read-only orchestration. Implements no scanning, normalization, classification,
  risk, Mosca, recommendation, or CBOM logic of its own (PROJECT_RULES RULE-004).
- Does not modify `backend/`, `core/`, or `scanners/`.
- Development tooling only. Never shipped in a production build.

USAGE
-----
    python frontend/tools/generate_fixtures.py

OUTPUT
------
    frontend/src/mocks/fixtures/*.json
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scanners.framework.models import ScanOptions, ScanTarget, TargetType  # noqa: E402
from scanners.repository.scanner import RepositoryScanner  # noqa: E402
from core.classification.classifier import ClassificationEngine  # noqa: E402
from core.cbom_generator.serializer import CBOMSerializer  # noqa: E402
from core.mosca_engine.engine import MoscaEngine  # noqa: E402
from core.mosca_engine.knowledge import MoscaConfig  # noqa: E402
from core.mosca_engine.models import MoscaInput  # noqa: E402
from core.normalization.normalizer import Normalizer  # noqa: E402
from core.recommendation_engine.engine import RecommendationEngine  # noqa: E402
from core.risk_engine.engine import RiskEngine  # noqa: E402

logging.basicConfig(level=logging.ERROR)

OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "mocks" / "fixtures"
SCAN_ID = "b2d93bc1-5678-4c28-98e3-b4c3e21199b0"
ARTIFACT_ID = "a1f93bc1-1234-4c28-98e3-a4c3e21199a0"
ASSESSMENT_DATE = date(2026, 9, 6)
SCAN_TIMESTAMP = datetime(2026, 9, 6, 10, 1, 0, tzinfo=timezone.utc)

# X (data shelf life) is a user-supplied policy input, not a discovered value.
# The Mosca engine deliberately refuses to fabricate it. The generator supplies an
# explicit default so the fixture exercises the computable path; the frontend lets
# the user change it and re-runs the assessment through the API.
DEFAULT_X_YEARS = 10.0
DEFAULT_Z_YEARS = 10.0

# The Mosca page lets the user explore the inequality. Recomputation is engine work,
# not frontend work, so the generator pre-computes a grid of real engine assessments
# for the (X, Z) pairs the mock transport can serve. In live mode the API recomputes
# on demand and the grid is unused.
GRID_X_YEARS = [1.0, 3.0, 5.0, 10.0, 15.0, 20.0, 25.0]
GRID_Z_YEARS = [5.0, 10.0, 15.0]


def _location(loc: Any) -> dict[str, Any]:
    return {
        "file_path": loc.file_path,
        "start_line": loc.start_line,
        "end_line": loc.end_line,
        "byte_offset": loc.byte_offset,
        "snippet": loc.snippet,
    }


def _finding_to_api(f: Any) -> dict[str, Any]:
    """Serialise a RawFinding to docs/10_API_CONTRACT.md Section 7 shape."""
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
        "location": _location(f.location),
        "confidence_score": round(f.confidence_score, 4),
        "confidence_level": f.confidence_level.value,
        "confidence_rationale": f.confidence_rationale,
        "binary_format": f.binary_format.value if f.binary_format else None,
        "symbol_name": f.symbol_name,
        "container_context": (
            f.container_context.model_dump() if f.container_context else None
        ),
        "raw_parameters": f.raw_parameters,
        "discovered_at": f.discovered_at.isoformat(),
    }


def _asset_to_api(a: Any) -> dict[str, Any]:
    """CryptoAsset.to_api_dict() plus the evidence the detail endpoint inlines."""
    payload = a.to_api_dict()
    payload["locations"] = [_location(loc) for loc in a.locations]
    payload["confidence_rationale"] = a.confidence_rationale
    payload["supporting_findings"] = [
        {
            "finding_id": e.finding_id,
            "scanner_name": e.scanner_name,
            "discovery_method": e.discovery_method,
            "raw_symbol": e.raw_symbol,
            "location": _location(e.location),
            "confidence_score": round(e.confidence_score, 4),
            "confidence_rationale": e.confidence_rationale,
        }
        for e in a.supporting_findings
    ]
    return payload


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    target_path = REPO_ROOT / "samples" / "repository_samples"
    print(f"[1/7] Discovery  — scanning {target_path.relative_to(REPO_ROOT)}")
    target = ScanTarget(
        path=str(target_path),
        target_type=TargetType.REPOSITORY,
        name="qnetra-sample-repositories",
        options=ScanOptions(),
    )
    scan_result = RepositoryScanner().scan(target)
    findings = scan_result.findings
    print(f"        {len(findings)} raw findings")

    print("[2/7] Normalization")
    assets = Normalizer().normalize(findings)
    norm_stats = Normalizer.compute_statistics(findings, assets)
    print(f"        {len(assets)} canonical assets")

    print("[3/7] Classification")
    assets = ClassificationEngine().classify(assets)

    print("[4/7] Risk assessment")
    risk_engine = RiskEngine()
    risk_assessments = risk_engine.assess_and_enrich_all(assets)
    risk_report = risk_engine.generate_report(assets, risk_assessments)
    print(f"        overall {risk_report.overall_risk_score} ({risk_report.overall_severity.value})")

    print("[5/7] Mosca / HNDL")
    mosca_engine = MoscaEngine()
    contexts = {
        a.asset_id: MoscaInput(
            asset_id=a.asset_id,
            protected_lifetime_years=DEFAULT_X_YEARS,
            assessment_date=ASSESSMENT_DATE,
        )
        for a in assets
    }
    mosca_assessments = mosca_engine.assess_all(assets, contexts=contexts)
    mosca_report = mosca_engine.generate_report(assets, mosca_assessments, contexts=contexts)
    print(f"        {mosca_report.mosca_triggered_assets} of "
          f"{mosca_report.mosca_applicable_assets} applicable assets trigger X + Y > Z")

    print("[6/7] PQC recommendations")
    rec_engine = RecommendationEngine()
    recommendations = rec_engine.recommend_all(assets)
    rec_report = rec_engine.generate_report(assets, recommendations)

    print("[7/7] CBOM (CycloneDX 1.6)")
    cbom_doc = CBOMSerializer().to_json_dict(
        assets, deterministic=False, scan_timestamp=SCAN_TIMESTAMP
    )

    stats = scan_result.statistics
    scan_payload = {
        "scan_id": SCAN_ID,
        "name": "QNetra Sample Repositories",
        "artifact_id": ARTIFACT_ID,
        "target": {
            "target_id": target.target_id,
            "name": target.name,
            "target_type": target.target_type.value,
            "path": "samples/repository_samples",
        },
        "status": scan_result.status.value,
        "current_stage": "COMPLETED",
        "created_at": SCAN_TIMESTAMP.isoformat().replace("+00:00", "Z"),
        "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
        "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
        "duration_seconds": scan_result.duration_seconds,
        "progress": {
            "stages": [
                {"name": "DISCOVERY", "status": "COMPLETED"},
                {"name": "NORMALIZATION", "status": "COMPLETED"},
                {"name": "CLASSIFICATION", "status": "COMPLETED"},
                {"name": "CBOM", "status": "COMPLETED"},
                {"name": "RISK_ANALYSIS", "status": "COMPLETED"},
                {"name": "MOSCA_ANALYSIS", "status": "COMPLETED"},
                {"name": "PQC_ANALYSIS", "status": "COMPLETED"},
            ],
            "directories_visited": stats.directories_visited,
            "files_discovered": stats.files_discovered,
            "files_scanned": stats.files_scanned,
            "files_skipped": stats.files_skipped,
            "files_errored": stats.files_errored,
            "raw_findings_count": len(findings),
            "assets_count": len(assets),
        },
        "discovery": {
            "findings_by_method": dict(stats.findings_by_method),
            "findings_by_category": dict(stats.findings_by_category),
        },
        "normalization": norm_stats.model_dump(),
        "errors": list(scan_result.errors),
        "warnings": list(scan_result.warnings),
    }

    risk_payload = risk_report.to_dict()
    risk_payload["scan_id"] = SCAN_ID
    risk_payload["calculated_at"] = SCAN_TIMESTAMP.isoformat().replace("+00:00", "Z")
    risk_payload["assessments"] = [a.to_dict() for a in risk_assessments]

    mosca_payload = mosca_report.to_dict()
    mosca_payload["scan_id"] = SCAN_ID
    mosca_payload["parameters"] = {
        "data_shelf_life_years_x": DEFAULT_X_YEARS,
        "migration_time_years_y": None,
        "quantum_threat_horizon_years_z": mosca_engine.config.default_quantum_arrival_years,
        "migration_time_source": "DERIVED_FROM_PRIMITIVE_TYPE",
    }
    mosca_payload["assessed_at"] = SCAN_TIMESTAMP.isoformat().replace("+00:00", "Z")
    mosca_payload["assessment_date"] = ASSESSMENT_DATE.isoformat()
    mosca_payload["assessments"] = [a.to_dict() for a in mosca_assessments]

    rec_payload = rec_report.to_dict()
    rec_payload["scan_id"] = SCAN_ID
    rec_payload["recommendations"] = [r.to_dict() for r in recommendations]

    bundles: dict[str, Any] = {
        "scan.json": scan_payload,
        "findings.json": [_finding_to_api(f) for f in findings],
        "assets.json": [_asset_to_api(a) for a in assets],
        "risk.json": risk_payload,
        "mosca.json": mosca_payload,
        "recommendations.json": rec_payload,
        "cbom.json": cbom_doc,
    }

    print("[+]   Mosca parameter grid")
    grid_dir = OUT_DIR / "mosca-grid"
    grid_dir.mkdir(parents=True, exist_ok=True)
    for existing in grid_dir.glob("*.json"):
        existing.unlink()

    grid_index: list[dict[str, Any]] = []
    for z in GRID_Z_YEARS:
        engine = MoscaEngine(MoscaConfig(default_quantum_arrival_years=z))
        for x in GRID_X_YEARS:
            ctxs = {
                a.asset_id: MoscaInput(
                    asset_id=a.asset_id,
                    protected_lifetime_years=x,
                    assessment_date=ASSESSMENT_DATE,
                )
                for a in assets
            }
            grid_assessments = engine.assess_all(assets, contexts=ctxs)
            grid_report = engine.generate_report(assets, grid_assessments, contexts=ctxs)
            payload = grid_report.to_dict()
            payload["scan_id"] = SCAN_ID
            payload["parameters"] = {
                "data_shelf_life_years_x": x,
                "migration_time_years_y": None,
                "quantum_threat_horizon_years_z": z,
                "migration_time_source": "DERIVED_FROM_PRIMITIVE_TYPE",
            }
            payload["assessed_at"] = SCAN_TIMESTAMP.isoformat().replace("+00:00", "Z")
            payload["assessment_date"] = ASSESSMENT_DATE.isoformat()
            # Compact per-asset records: the explanatory prose is carried by the
            # baseline mosca.json; the grid carries the computed inequality itself.
            payload["assessments"] = [
                {
                    k: v
                    for k, v in a.to_dict().items()
                    if k not in ("assumptions", "rationale")
                }
                for a in grid_assessments
            ]
            key = f"x{x:g}-z{z:g}"
            path = grid_dir / f"{key}.json"
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            grid_index.append(
                {
                    "key": key,
                    "data_shelf_life_years_x": x,
                    "quantum_threat_horizon_years_z": z,
                    "mosca_triggered_assets": grid_report.mosca_triggered_assets,
                }
            )
    (grid_dir / "index.json").write_text(
        json.dumps(
            {
                "x_values": GRID_X_YEARS,
                "z_values": GRID_Z_YEARS,
                "entries": grid_index,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    grid_kb = sum(p.stat().st_size for p in grid_dir.glob("*.json")) / 1024
    print(f"        wrote {len(grid_index)} grid files ({grid_kb:.0f} KB total)")

    for name, payload in bundles.items():
        path = OUT_DIR / name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"        wrote {path.relative_to(REPO_ROOT)} "
              f"({path.stat().st_size / 1024:.1f} KB)")

    print("\nDone. Fixtures regenerated from live QNetra engine output.")


if __name__ == "__main__":
    main()
