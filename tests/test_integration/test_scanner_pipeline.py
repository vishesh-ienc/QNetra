"""
Integration test: Full scan pipeline from ScanTarget to ScanResult.
Validates that the complete discovery layer produces valid RawFindings.
"""

import pytest
from pathlib import Path
import tempfile
import shutil

from scanners.framework.models import (
    ScanTarget, TargetType, ScanStatus, RawFinding
)
from scanners.framework.router import ScannerRouter


@pytest.fixture(scope="session")
def samples_python_dir():
    return Path(__file__).parent.parent.parent / "samples" / "repository_samples" / "python_crypto"


class TestRepositoryScannerIntegration:
    """Integration tests: RepositoryScanner against sample fixtures."""

    def test_scans_python_samples_successfully(self, samples_python_dir):
        if not samples_python_dir.exists():
            pytest.skip("Python samples directory not found")

        from scanners.repository.scanner import RepositoryScanner
        scanner = RepositoryScanner()
        target = ScanTarget(path=str(samples_python_dir), target_type=TargetType.REPOSITORY)
        result = scanner.scan(target)

        assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        assert len(result.findings) > 0

    def test_python_scan_finds_rsa(self, samples_python_dir):
        if not samples_python_dir.exists():
            pytest.skip("Python samples directory not found")

        from scanners.repository.scanner import RepositoryScanner
        scanner = RepositoryScanner()
        target = ScanTarget(path=str(samples_python_dir), target_type=TargetType.REPOSITORY)
        result = scanner.scan(target)

        rsa_findings = [f for f in result.findings if f.suspected_algorithm == "RSA"]
        assert len(rsa_findings) > 0, "Should find at least one RSA indicator"

    def test_python_scan_finds_aes(self, samples_python_dir):
        if not samples_python_dir.exists():
            pytest.skip("Python samples directory not found")

        from scanners.repository.scanner import RepositoryScanner
        scanner = RepositoryScanner()
        target = ScanTarget(path=str(samples_python_dir), target_type=TargetType.REPOSITORY)
        result = scanner.scan(target)

        aes_findings = [f for f in result.findings if f.suspected_algorithm == "AES"]
        assert len(aes_findings) > 0, "Should find at least one AES indicator"

    def test_scan_result_is_valid_schema(self, samples_python_dir):
        if not samples_python_dir.exists():
            pytest.skip("Python samples directory not found")

        from scanners.repository.scanner import RepositoryScanner
        scanner = RepositoryScanner()
        target = ScanTarget(path=str(samples_python_dir), target_type=TargetType.REPOSITORY)
        result = scanner.scan(target)

        # Verify all findings conform to RawFinding schema requirements
        for f in result.findings:
            assert isinstance(f, RawFinding)
            assert f.finding_id
            assert f.scanner_name
            assert f.raw_symbol
            assert 0.0 <= f.confidence_score <= 1.0

    def test_scan_empty_directory_produces_warning(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from scanners.repository.scanner import RepositoryScanner
            scanner = RepositoryScanner()
            target = ScanTarget(path=tmpdir, target_type=TargetType.REPOSITORY)
            result = scanner.scan(target)
            # Empty directory should not crash — should produce warning
            assert result.warnings or result.status == ScanStatus.COMPLETED

    def test_scanner_router_default_factory(self, samples_python_dir):
        if not samples_python_dir.exists():
            pytest.skip("Python samples directory not found")

        router = ScannerRouter.create_default()
        target = ScanTarget(path=str(samples_python_dir), target_type=TargetType.AUTO)
        result = router.route(target)

        assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)


class TestBinaryStringAnalyzer:
    """Integration tests for binary string extraction."""

    def test_string_extractor_on_real_binary(self):
        from scanners.utils.string_extractor import extract_strings_list
        import sys

        # Use the Python interpreter binary as a test target (always available)
        python_binary = Path(sys.executable)
        if not python_binary.exists():
            pytest.skip("Cannot locate Python binary")

        strings = extract_strings_list(python_binary, min_length=6, max_strings=1000, max_bytes=1 * 1024 * 1024)
        assert len(strings) > 0
        # Verify format: each item is (string, offset)
        for s, offset in strings:
            assert isinstance(s, str)
            assert isinstance(offset, int)
            assert offset >= 0

    def test_format_detector_on_python_binary(self):
        from scanners.binary.format_detector import detect_format
        from scanners.framework.models import BinaryFormat
        import sys

        python_binary = Path(sys.executable)
        if not python_binary.exists():
            pytest.skip("Cannot locate Python binary")

        fmt = detect_format(python_binary)
        # Python binary should be ELF on Linux or PE on Windows
        import platform
        if platform.system() == "Windows":
            assert fmt == BinaryFormat.PE
        elif platform.system() == "Linux":
            assert fmt == BinaryFormat.ELF
        # Other platforms: just check it doesn't crash
