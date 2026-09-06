def test_create_scan_runs_the_real_pipeline_end_to_end(completed_scan, client):
    scan = client.get(f"/api/v1/scans/{completed_scan}").json()
    assert scan["status"] == "COMPLETED"
    assert scan["current_stage"] == "COMPLETED"
    assert all(s["status"] == "COMPLETED" for s in scan["progress"]["stages"])
    # Ground truth from running the same engines directly over the same fixture
    # (frontend/tools/generate_fixtures.py): 269 raw findings -> 130 assets.
    assert scan["progress"]["raw_findings_count"] == 269
    assert scan["progress"]["assets_count"] == 130
    assert scan["errors"] == []


def test_scan_creation_rejects_unknown_artifact(client):
    r = client.post(
        "/api/v1/scans",
        json={"artifact_id": "missing", "target_type": "REPOSITORY"},
    )
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"


def test_scan_creation_rejects_invalid_target_type(client, sample_zip_bytes):
    artifact_id = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("s.zip", sample_zip_bytes, "application/zip")},
    ).json()["artifact_id"]
    r = client.post(
        "/api/v1/scans",
        json={"artifact_id": artifact_id, "target_type": "NOT_REAL"},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_get_unknown_scan_is_404(client):
    for path in ["", "/progress", "/risk", "/mosca", "/recommendations", "/cbom"]:
        r = client.get(f"/api/v1/scans/does-not-exist{path}")
        assert r.status_code == 404, path
        assert r.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_list_scans_includes_created_scan(completed_scan, client):
    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    ids = [s["scan_id"] for s in r.json()["data"]]
    assert completed_scan in ids
