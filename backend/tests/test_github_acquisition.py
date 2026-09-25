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

    def fake_git_v6(cmd, **kwargs):
        """v6.0 two-phase sparse-checkout mock (clone, sparse-checkout, checkout)."""
        subcommand = next(
            (p for p in cmd if p in ("clone", "sparse-checkout", "checkout")), ""
        )
        if subcommand == "clone":
            # Phase 1: blobless clone creates dest + .git only, no working-tree files.
            dest = Path(cmd[-1])
            dest.mkdir(parents=True, exist_ok=True)
            git_dir = dest / ".git"
            git_dir.mkdir(exist_ok=True)
            (git_dir / "config").write_text("[core]\n")
            return MagicMock(returncode=0, stdout="", stderr="")
        if subcommand == "sparse-checkout":
            # Phase 2a (init) and 2b (set): no-op in mock.
            return MagicMock(returncode=0, stdout="", stderr="")
        if subcommand == "checkout":
            # Phase 2c: populate working tree; dest is argv[2] (git -C <dest> checkout HEAD).
            dest = Path(cmd[2])
            (dest / "crypto.py").write_text("import hashlib\nhashlib.sha256(b'test')\n")
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("backend.github.subprocess.run", side_effect=fake_git_v6):
        dest_dir = acquire_github_repository("https://github.com/owner/sample-repo", scan_id)
        assert dest_dir.exists()
        assert (dest_dir / "crypto.py").exists()
        # .git should have been removed after acquisition
        assert not (dest_dir / ".git").exists()
        shutil.rmtree(dest_dir, ignore_errors=True)


def test_acquire_github_repository_failure():
    scan_id = "test-scan-fail"
    with patch("backend.github.subprocess.run") as mock_run:
        # v6.0: Phase 1 (blobless clone) fails — error now prefixed with "Phase 1"
        mock_run.return_value = MagicMock(returncode=128, stdout="", stderr="fatal: clone failed")
        with pytest.raises(RuntimeError, match="Phase 1"):
            acquire_github_repository("https://github.com/owner/fail-repo", scan_id)


# --------------------------------------------------------------------------
# Full scan endpoint lifecycle with GITHUB source_type
# --------------------------------------------------------------------------


def test_create_scan_github_lifecycle(tmp_path):
    client = TestClient(app)

    # Mock both verify (git ls-remote) and clone (git clone) calls.
    # verify_public_repo now runs in the background pipeline thread, so
    # subprocess.run handles both commands sequentially.
    def fake_git_subprocess(cmd, **kwargs):
        """Handle all git subcommands used by the v6.0 two-phase sparse-checkout."""
        # Determine the git subcommand
        # cmd may be: ["git", "-c", ..., "clone", ...] or ["git", "-C", dest, "sparse-checkout", ...]
        subcommand = ""
        for i, part in enumerate(cmd):
            if part in ("ls-remote", "clone", "sparse-checkout", "checkout"):
                subcommand = part
                break

        if subcommand == "ls-remote":
            return MagicMock(returncode=0, stdout="abc123\trefs/heads/main", stderr="")

        if subcommand == "clone":
            # Phase 1: blobless clone with --no-checkout.
            # cmd[-1] is the destination directory; create it with .git dir.
            dest = Path(cmd[-1])
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir(parents=True, exist_ok=True)
            git_dir = dest / ".git"
            git_dir.mkdir(exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        if subcommand == "sparse-checkout":
            # Phase 2a (init) and 2b (set): no-ops in the mock.
            return MagicMock(returncode=0, stdout="", stderr="")

        if subcommand == "checkout":
            # Phase 2c: populate working tree from SAMPLES fixture.
            # Destination is in cmd: ["git", "-C", dest_str, "checkout", "HEAD"]
            dest = Path(cmd[2])
            # Copy fixture files into dest (simulating checked-out source)
            for src in SAMPLES.rglob("*"):
                if src.is_file():
                    rel = src.relative_to(SAMPLES)
                    target = dest / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, target)
            return MagicMock(returncode=0, stdout="", stderr="")

        # Unknown subcommand — succeed silently
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch("backend.github.subprocess.run", side_effect=fake_git_subprocess),
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
    """Inaccessible repos now surface as a FAILED scan (async), not a 400 response."""
    client = TestClient(app)

    def fake_ls_remote(cmd, **kwargs):
        """Simulate git ls-remote returning auth failure."""
        return MagicMock(
            returncode=128,
            stdout="",
            stderr="fatal: Authentication failed for 'https://github.com/private/repo'",
        )

    with patch("backend.github.subprocess.run", side_effect=fake_ls_remote):
        res = client.post(
            "/api/v1/scans",
            json={
                "source_type": "GITHUB",
                "repository_url": "https://github.com/private/repo",
            },
        )
        # Route now returns 202 immediately (verification happens in background)
        assert res.status_code == 202
        data = res.json()
        scan_id = data["scan_id"]

        # Poll until the scan fails
        for _ in range(50):
            status_res = client.get(f"/api/v1/scans/{scan_id}")
            assert status_res.status_code == 200
            scan_data = status_res.json()
            if scan_data["status"] in ("COMPLETED", "PARTIAL", "FAILED"):
                assert scan_data["status"] == "FAILED", f"Expected FAILED, got {scan_data['status']}"
                # The inaccessible error message should appear in the scan errors
                assert any(
                    "private" in e.lower() or "authentication" in e.lower() or "accessible" in e.lower()
                    for e in scan_data.get("errors", [])
                ), f"Expected auth error in errors: {scan_data.get('errors')}"
                break
        else:
            pytest.fail("Scan did not transition to FAILED within polling limit")


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

    with (
        patch("backend.github.verify_public_repo", return_value=(True, "")),
        patch("backend.github.acquire_github_repository", return_value=cloned_dir),
    ):
        run_pipeline(
            scan,
            data_shelf_life_years_x=10.0,
            migration_time_years_y=5.0,
            quantum_threat_horizon_years_z=10.0,
        )

    # The directory should be cleaned up after scan completion
    assert not cloned_dir.exists()
    assert scan.status in ("COMPLETED", "PARTIAL")

