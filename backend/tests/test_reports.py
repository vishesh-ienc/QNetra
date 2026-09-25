"""
Tests for QNetra Reports & Exports Subsystem.
Verifies Executive, Technical, Migration, Assets, Findings, and Custom Export routes.
"""

from __future__ import annotations

import csv
import io

from backend.reports.data import sanitize_target_name


def test_sanitize_target_name():
    assert sanitize_target_name("WebGoat/WebGoat") == "webgoat-webgoat"
    assert sanitize_target_name("https://github.com/org/crypto-repo.git") == "org-crypto-repo-git"
    assert sanitize_target_name("../../../etc/passwd") == "etc-passwd"
    assert sanitize_target_name("  --my-app!!  ") == "my-app"
    assert sanitize_target_name(None) == "unnamed"


def test_executive_report_pdf(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/reports/executive")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert len(r.content) > 1000
    disp = r.headers.get("content-disposition", "")
    assert "qnetra-executive-assessment-" in disp
    assert disp.endswith('.pdf"')


def test_migration_report_pdf(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/reports/migration?format=pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert "qnetra-pqc-migration-plan-" in r.headers.get("content-disposition", "")


def test_migration_report_csv(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/reports/migration?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    reader = list(csv.DictReader(io.StringIO(r.content.decode("utf-8"))))
    assert len(reader) > 0
    assert "current_algorithm" in reader[0]
    assert "migration_category" in reader[0]
    assert "recommended_algorithm" in reader[0]
    assert "urgency" in reader[0]


def test_migration_report_json(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/reports/migration?format=json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "summary" in body
    assert "migration_actions" in body
    assert len(body["migration_actions"]) > 0


def test_technical_report_pdf(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/reports/technical")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert len(r.content) > 1000
    assert "qnetra-complete-assessment-" in r.headers.get("content-disposition", "")


def test_assets_export_csv_and_json(completed_scan, client):
    # CSV
    r_csv = client.get(f"/api/v1/scans/{completed_scan}/reports/assets?format=csv")
    assert r_csv.status_code == 200
    assert r_csv.headers["content-type"].startswith("text/csv")
    reader = list(csv.DictReader(io.StringIO(r_csv.content.decode("utf-8"))))
    assert len(reader) == 130
    assert "algorithm" in reader[0]
    assert "risk_score" in reader[0]
    assert "quantum_threat_type" in reader[0]
    assert "primary_location" in reader[0]

    # JSON
    r_json = client.get(f"/api/v1/scans/{completed_scan}/reports/assets?format=json")
    assert r_json.status_code == 200
    assert r_json.headers["content-type"].startswith("application/json")
    body = r_json.json()
    assert len(body["assets"]) == 130


def test_findings_export_csv_and_json(completed_scan, client):
    # CSV
    r_csv = client.get(f"/api/v1/scans/{completed_scan}/reports/findings?format=csv")
    assert r_csv.status_code == 200
    assert r_csv.headers["content-type"].startswith("text/csv")
    reader = list(csv.DictReader(io.StringIO(r_csv.content.decode("utf-8"))))
    assert len(reader) == 269
    assert "finding_id" in reader[0]
    assert "scanner_name" in reader[0]
    assert "file_path" in reader[0]

    # JSON
    r_json = client.get(f"/api/v1/scans/{completed_scan}/reports/findings?format=json")
    assert r_json.status_code == 200
    assert r_json.headers["content-type"].startswith("application/json")
    body = r_json.json()
    assert len(body["findings"]) == 269


def test_custom_export_pdf(completed_scan, client):
    payload = {
        "sections": ["assets", "risk", "migration"],
        "format": "pdf",
    }
    r = client.post(f"/api/v1/scans/{completed_scan}/reports/custom", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert "qnetra-custom-assessment-" in r.headers.get("content-disposition", "")


def test_custom_export_json(completed_scan, client):
    payload = {
        "sections": ["assets", "quantum", "mosca"],
        "format": "json",
    }
    r = client.post(f"/api/v1/scans/{completed_scan}/reports/custom", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "assets" in body
    assert "quantum" in body
    assert "mosca" in body
    assert "findings" not in body


def test_custom_export_csv(completed_scan, client):
    payload = {
        "sections": ["assets", "migration"],
        "format": "csv",
    }
    r = client.post(f"/api/v1/scans/{completed_scan}/reports/custom", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    content = r.content.decode("utf-8")
    assert "# --- CRYPTO ASSETS ---" in content
    assert "# --- PQC MIGRATION PLAN ---" in content


def test_custom_export_csv_incompatible(completed_scan, client):
    payload = {
        "sections": ["cbom"],
        "format": "csv",
    }
    r = client.post(f"/api/v1/scans/{completed_scan}/reports/custom", json=payload)
    assert r.status_code == 422  # validation_error returns 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_custom_export_empty_sections(completed_scan, client):
    payload = {
        "sections": [],
        "format": "pdf",
    }
    r = client.post(f"/api/v1/scans/{completed_scan}/reports/custom", json=payload)
    assert r.status_code == 422


def test_report_cache_hit_and_headers(completed_scan, client):
    from backend.reports.cache import report_cache

    report_cache.clear()

    # First request should be a MISS
    r1 = client.get(f"/api/v1/scans/{completed_scan}/reports/executive")
    assert r1.status_code == 200
    assert r1.headers.get("x-report-cache") == "MISS"

    # Second request should be a HIT
    r2 = client.get(f"/api/v1/scans/{completed_scan}/reports/executive")
    assert r2.status_code == 200
    assert r2.headers.get("x-report-cache") == "HIT"
    assert r1.content == r2.content

    # Invalidate cache for scan
    report_cache.invalidate_scan(completed_scan)
    r3 = client.get(f"/api/v1/scans/{completed_scan}/reports/executive")
    assert r3.status_code == 200
    assert r3.headers.get("x-report-cache") == "MISS"

