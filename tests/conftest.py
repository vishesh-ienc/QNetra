"""
QNetra Test Suite — Shared Fixtures and Configuration

Provides pytest fixtures used across all scanner test modules.
"""

import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Path fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def samples_root() -> Path:
    """Root directory of the test samples."""
    return Path(__file__).parent.parent / "samples"


@pytest.fixture(scope="session")
def python_samples_dir(samples_root) -> Path:
    return samples_root / "repository_samples" / "python_crypto"


@pytest.fixture(scope="session")
def javascript_samples_dir(samples_root) -> Path:
    return samples_root / "repository_samples" / "javascript_crypto"


@pytest.fixture(scope="session")
def java_samples_dir(samples_root) -> Path:
    return samples_root / "repository_samples" / "java_crypto"


@pytest.fixture(scope="session")
def cpp_samples_dir(samples_root) -> Path:
    return samples_root / "repository_samples" / "cpp_crypto"


@pytest.fixture(scope="session")
def container_samples_dir(samples_root) -> Path:
    return samples_root / "container_samples"


# ---------------------------------------------------------------------------
# ScanTarget fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_scan_options():
    from scanners.framework.models import ScanOptions
    return ScanOptions()


@pytest.fixture
def make_scan_target(default_scan_options):
    """Factory fixture for creating ScanTarget objects."""
    from scanners.framework.models import ScanTarget, TargetType

    def _make(path: str, target_type: TargetType = TargetType.REPOSITORY, **kwargs):
        return ScanTarget(
            path=path,
            target_type=target_type,
            options=default_scan_options,
            **kwargs,
        )
    return _make
