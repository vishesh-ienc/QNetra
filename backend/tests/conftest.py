import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.store import store

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES = REPO_ROOT / "samples" / "repository_samples"


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def sample_zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in SAMPLES.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(SAMPLES))
    return buffer.getvalue()


@pytest.fixture()
def completed_scan(client: TestClient, sample_zip_bytes: bytes) -> str:
    """Uploads the real sample repository and runs it through the real pipeline."""
    upload = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("samples.zip", sample_zip_bytes, "application/zip")},
    )
    assert upload.status_code == 201
    artifact_id = upload.json()["artifact_id"]

    created = client.post(
        "/api/v1/scans",
        json={
            "name": "pytest scan",
            "artifact_id": artifact_id,
            "target_type": "REPOSITORY",
            "mosca_params": {
                "data_shelf_life_years_x": 10.0,
                "quantum_threat_horizon_years_z": 10.0,
            },
        },
    )
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]

    for _ in range(100):
        progress = client.get(f"/api/v1/scans/{scan_id}/progress").json()
        if progress["status"] in ("COMPLETED", "PARTIAL", "FAILED"):
            assert progress["status"] in ("COMPLETED", "PARTIAL"), progress
            break
    else:
        pytest.fail("Scan did not reach a terminal state in time.")

    return scan_id


@pytest.fixture(autouse=True)
def _clear_store():
    yield
    store.scans.clear()
    store.artifacts.clear()
