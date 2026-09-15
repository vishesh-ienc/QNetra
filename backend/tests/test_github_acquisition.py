import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.github import (
    acquire_github_repository,
    normalize_github_url,
    verify_public_repo,
)
from backend.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES = REPO_ROOT / "samples" / "repository_samples"


# --------------------------------------------------------------------------
# URL normalization & validation
# --------------------------------------------------------------------------


def test_normalize_github_url_standard():
    url, owner, repo = normalize_github_url("https://github.com/google/crypto-test")
    assert url == "https://github.com/google/crypto-test"
    assert owner == "google"
    assert repo == "crypto-test"


def test_normalize_github_url_variations():
    cases = [
        ("http://github.com/owner/repo", "https://github.com/owner/repo", "owner", "repo"),
        ("github.com/owner/repo", "https://github.com/owner/repo", "owner", "repo"),
        ("www.github.com/owner/repo", "https://github.com/owner/repo", "owner", "repo"),
        ("https://github.com/owner/repo.git", "https://github.com/owner/repo", "owner", "repo"),
        ("https://github.com/owner/repo/", "https://github.com/owner/repo", "owner", "repo"),
        ("https://github.com/owner/repo.git/", "https://github.com/owner/repo", "owner", "repo"),
        ("  https://github.com/owner/repo.js  ", "https://github.com/owner/repo.js", "owner", "repo.js"),
    ]
    for raw, expected_url, exp_owner, exp_repo in cases:
        url, owner, repo = normalize_github_url(raw)
        assert url == expected_url
        assert owner == exp_owner
        assert repo == exp_repo


def test_normalize_github_url_disallowed():
    invalid_cases = [
        "",
        None,
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/subpath",
        "https://user:token@github.com/owner/repo",
        "https://github.com/owner/repo;rm -rf /",
        "https://github.com/owner/repo`whoami`",
        "https://github.com/owner/repo$(id)",
        "https://github.com/owner/repo|sh",
        "https://github.com/owner/..",
        "https://github.com/owner/.",
        "https://github.com/owner/-flag",
    ]
    for invalid in invalid_cases:
        with pytest.raises(ValueError):
            normalize_github_url(invalid)


# --------------------------------------------------------------------------
# verify_public_repo
# --------------------------------------------------------------------------


def test_verify_public_repo_success():
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="refs/heads/main\n", stderr="")
        ok, reason = verify_public_repo("https://github.com/google/crypto-test")
        assert ok is True
        assert reason == ""


def test_verify_public_repo_private_or_auth():
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=128,
            stdout="",
            stderr="fatal: Authentication failed for 'https://github.com/secret/repo'",
        )
        ok, reason = verify_public_repo("https://github.com/secret/repo")
        assert ok is False
        assert "private or requires authentication" in reason


def test_verify_public_repo_not_found():
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=128,
            stdout="",
            stderr="fatal: Repository not found",
        )
        ok, reason = verify_public_repo("https://github.com/nonexistent/repo")
        assert ok is False
        assert "Repository not found" in reason


def test_verify_public_repo_timeout():
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=15)
        ok, reason = verify_public_repo("https://github.com/slow/repo")
        assert ok is False
        assert "timed out" in reason


# --------------------------------------------------------------------------
# acquire_github_repository
# --------------------------------------------------------------------------


def test_acquire_github_repository_success(tmp_path):
    scan_id = "test-scan-123"

    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        dest.mkdir(parents=True, exist_ok=True)
        # Create a sample file and a .git dir
        (dest / "crypto.py").write_text("import hashlib\nhashlib.sha256(b'test')\n")
        git_dir = dest / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("backend.github.subprocess.run", side_effect=fake_clone):
        dest_dir = acquire_github_repository("https://github.com/owner/sample-repo", scan_id)
        assert dest_dir.exists()
        assert (dest_dir / "crypto.py").exists()
        # .git should have been removed
        assert not (dest_dir / ".git").exists()

        # Clean up
        shutil.rmtree(dest_dir, ignore_errors=True)


def test_acquire_github_repository_failure():
    scan_id = "test-scan-fail"
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=128, stdout="", stderr="fatal: clone failed")
        with pytest.raises(RuntimeError, match="Failed to clone repository"):
            acquire_github_repository("https://github.com/owner/fail-repo", scan_id)


# --------------------------------------------------------------------------
# Full scan endpoint lifecycle with GITHUB source_type
# --------------------------------------------------------------------------


def test_create_scan_github_lifecycle(tmp_path):
    client = TestClient(app)

    # Mock accessibility check and clone
    def fake_clone(cmd, **kwargs):
        dest = Path(cmd[-1])
        # Copy samples/repository_samples into dest to run real pipeline
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(SAMPLES, dest)
        git_dir = dest / ".git"
        git_dir.mkdir(exist_ok=True)
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch("backend.routes.scans.verify_public_repo", return_value=(True, "")),
        patch("backend.github.subprocess.run", side_effect=fake_clone),
    ):
        res = client.post(
            "/api/v1/scans",
            json={
                "source_type": "GITHUB",
                "repository_url": "https://github.com/example/cryptolib",
                "mosca_params": {
                    "data_shelf_life_years_x": 5.0,
                    "quantum_threat_horizon_years_z": 10.0,
                },
            },
        )
        assert res.status_code == 202
        data = res.json()
        assert data["source_type"] == "GITHUB"
        assert data["source_url"] == "https://github.com/example/cryptolib"
        assert data["target"]["source_type"] == "GITHUB"
        assert data["target"]["source_url"] == "https://github.com/example/cryptolib"
        # Progress stages must include ACQUISITION as first stage
        stage_names = [s["name"] for s in data["progress"]["stages"]]
        assert stage_names[0] == "ACQUISITION"
        assert stage_names[1] == "DISCOVERY"

        scan_id = data["scan_id"]

        # Poll until complete
        for _ in range(100):
            status_res = client.get(f"/api/v1/scans/{scan_id}")
            assert status_res.status_code == 200
            scan_data = status_res.json()
            if scan_data["status"] in ("COMPLETED", "PARTIAL", "FAILED"):
                assert scan_data["status"] in ("COMPLETED", "PARTIAL"), scan_data
                break
        else:
            pytest.fail("Scan timed out")

        # Verify ACQUISITION stage was COMPLETED
        acquisition_stage = next(
            s for s in scan_data["progress"]["stages"] if s["name"] == "ACQUISITION"
        )
        assert acquisition_stage["status"] == "COMPLETED"
        assert scan_data["progress"]["assets_count"] is not None
        assert scan_data["progress"]["assets_count"] > 0


def test_create_scan_github_inaccessible():
    client = TestClient(app)
    with patch(
        "backend.routes.scans.verify_public_repo",
        return_value=(False, "Repository is private or requires authentication."),
    ):
        res = client.post(
            "/api/v1/scans",
            json={
                "source_type": "GITHUB",
                "repository_url": "https://github.com/private/repo",
            },
        )
        assert res.status_code == 400
        data = res.json()
        assert data["error"]["code"] == "GITHUB_REPO_INACCESSIBLE"
        assert "private or requires authentication" in data["error"]["message"]


def test_create_scan_github_missing_url():
    client = TestClient(app)
    res = client.post(
        "/api/v1/scans",
        json={
            "source_type": "GITHUB",
        },
    )
    assert res.status_code == 422
    data = res.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_verify_public_repo_network_error():
    with patch("backend.github.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=128,
            stdout="",
            stderr="fatal: unable to access 'https://github.com/org/repo/': Could not resolve host: github.com",
        )
        ok, reason = verify_public_repo("https://github.com/org/repo")
        assert ok is False
        assert "QNetra could not reach GitHub" in reason


def test_pipeline_github_workspace_cleanup(tmp_path):
    from backend.pipeline import run_pipeline
    from backend.store import ScanRecord

    # Create a dummy cloned folder
    cloned_dir = tmp_path / "dummy_repo"
    cloned_dir.mkdir()
    (cloned_dir / "test.py").write_text("import hashlib\n")

    scan = ScanRecord(
        scan_id="cleanup-test-scan",
        name="cleanup-test",
        artifact_id=None,
        target_path="",
        target_type="REPOSITORY",
        target_name="org/dummy_repo",
        source_type="GITHUB",
        source_url="https://github.com/org/dummy_repo",
    )

    with patch("backend.github.acquire_github_repository", return_value=cloned_dir):
        run_pipeline(
            scan,
            data_shelf_life_years_x=10.0,
            migration_time_years_y=5.0,
            quantum_threat_horizon_years_z=10.0,
        )

    # The directory should be cleaned up after scan completion
    assert not cloned_dir.exists()
    assert scan.status in ("COMPLETED", "PARTIAL")

