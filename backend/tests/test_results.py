"""
Verifies the results endpoints return data genuinely produced by the
engines — matching the values obtained by running scanners+core directly in
frontend/tools/generate_fixtures.py over the identical sample fixture.
"""


def test_risk_matches_ground_truth(completed_scan, client):
    r = client.get(f"/api/v1/scans/{completed_scan}/risk")
    assert r.status_code == 200
    body = r.json()
    assert body["overall_risk_score"] == 85.2
    assert body["overall_severity"] == "CRITICAL"
    assert body["total_assets_discovered"] == 130
    assert body["vulnerable_assets_count"] == 64
    assert body["shor_vulnerable_count"] == 28
    assert body["classically_broken_count"] == 14
    assert len(body["assessments"]) == 130
    # Every asset_id on a risk assessment must trace back to a real asset.
    asset_ids = {
        a["asset_id"]
        for a in client.get(
            f"/api/v1/scans/{completed_scan}/assets", params={"page_size": 200}
        ).json()["data"]
    }
    assert {a["asset_id"] for a in body["assessments"]} <= asset_ids


def test_recommendations_match_ground_truth(completed_scan, client):
    body = client.get(f"/api/v1/scans/{completed_scan}/recommendations").json()
    assert body["total_assets"] == 130
    assert body["direct_pqc_count"] == 3
    assert body["classical_upgrade_count"] == 36
    assert body["hybrid_count"] == 25
    # A classical upgrade must never be mislabeled as a direct PQC replacement
    # (this was the exact bug the Phase 3.3 corrective pass fixed in core/).
    for rec in body["recommendations"]:
        if rec["recommendation_type"] == "CLASSICAL_UPGRADE":
            assert rec["pqc_standard"] is None


def test_cbom_component_count_matches_asset_count(completed_scan, client):
    body = client.get(f"/api/v1/scans/{completed_scan}/cbom").json()
    assert body["bomFormat"] == "CycloneDX"
    assert body["specVersion"] == "1.6"
    assert len(body["components"]) == 130


def test_cbom_xml_export_is_well_formed(completed_scan, client):
    import xml.etree.ElementTree as ET

    r = client.get(
        f"/api/v1/scans/{completed_scan}/cbom/export", params={"format": "xml"}
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/xml")
    ET.fromstring(r.content)  # raises if malformed


def test_mosca_recompute_is_live_not_cached(completed_scan, client):
    low = client.get(
        f"/api/v1/scans/{completed_scan}/mosca",
        params={"data_shelf_life_years_x": 1},
    ).json()
    high = client.get(
        f"/api/v1/scans/{completed_scan}/mosca",
        params={"data_shelf_life_years_x": 25},
    ).json()
    assert low["mosca_triggered_assets"] == 0
    assert high["mosca_triggered_assets"] == 111
    # A bare GET (no override) must not have been mutated by the probes above.
    baseline = client.get(f"/api/v1/scans/{completed_scan}/mosca").json()
    assert baseline["parameters"]["data_shelf_life_years_x"] == 10.0


def test_mosca_post_persists_new_baseline(completed_scan, client):
    r = client.post(
        f"/api/v1/scans/{completed_scan}/mosca",
        json={"data_shelf_life_years_x": 3, "quantum_threat_horizon_years_z": 10},
    )
    assert r.status_code == 200
    assert r.json()["parameters"]["data_shelf_life_years_x"] == 3
    baseline = client.get(f"/api/v1/scans/{completed_scan}/mosca").json()
    assert baseline["parameters"]["data_shelf_life_years_x"] == 3


def test_mosca_rejects_non_positive_x(completed_scan, client):
    r = client.post(
        f"/api/v1/scans/{completed_scan}/mosca", json={"data_shelf_life_years_x": 0}
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"
