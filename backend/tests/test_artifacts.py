def test_upload_zip_returns_ready_artifact(client, sample_zip_bytes):
    r = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("samples.zip", sample_zip_bytes, "application/zip")},
        data={"name": "My Target"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "READY"
    assert body["name"] == "My Target"
    assert body["file_size_bytes"] == len(sample_zip_bytes)
    assert body["artifact_type"] == "SOURCE_REPOSITORY"


def test_get_artifact_round_trips(client, sample_zip_bytes):
    upload = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("s.zip", sample_zip_bytes, "application/zip")},
    ).json()
    r = client.get(f"/api/v1/artifacts/{upload['artifact_id']}")
    assert r.status_code == 200
    assert r.json()["artifact_id"] == upload["artifact_id"]


def test_get_unknown_artifact_is_404(client):
    r = client.get("/api/v1/artifacts/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "ARTIFACT_NOT_FOUND"


def test_rejects_invalid_zip(client):
    r = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("broken.zip", b"not a real zip", "application/zip")},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "VALIDATION_ERROR"


def test_rejects_zip_slip_archive(client):
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../evil.txt", "escaped")
    r = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("evil.zip", buffer.getvalue(), "application/zip")},
    )
    assert r.status_code == 422
