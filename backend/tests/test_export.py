import csv
import io


def test_json_export_bundles_every_result(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/export", params={"format": "json"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["scan"]["scan_id"] == completed_scan
    assert len(body["findings"]) == 269
    assert len(body["assets"]) == 130
    assert body["risk"]["overall_risk_score"] == 85.2
    assert len(body["cbom"]["components"]) == 130


def test_csv_export_has_one_row_per_asset(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/export", params={"format": "csv"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.content.decode())))
    assert len(rows) == 130
    assert rows[0]["algorithm"]
    assert rows[0]["risk_score"]


def test_pdf_export_returns_technical_report_pdf(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/export", params={"format": "pdf"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert len(r.content) > 1000
