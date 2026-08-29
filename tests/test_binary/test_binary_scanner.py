"""
Tests for BinaryScanner — format detection, string analysis, and correlation.
"""

import pytest
from pathlib import Path
import tempfile
import sys

from scanners.binary.scanner import BinaryScanner
from scanners.binary.format_detector import detect_format
from scanners.framework.models import ScanTarget, TargetType, ScanStatus, BinaryFormat, DiscoveryMethod, ArtifactCategory


class TestBinaryScanner:
    """Tests for BinaryScanner."""

    def test_validation_rejects_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = BinaryScanner()
            target = ScanTarget(path=tmpdir, target_type=TargetType.BINARY)
            result = scanner.scan(target)
            assert result.status == ScanStatus.FAILED
            assert any("requires a single binary file" in e for e in result.errors)

    def test_validation_rejects_nonexistent_file(self):
        scanner = BinaryScanner()
        target = ScanTarget(path="/nonexistent/path/test.bin", target_type=TargetType.BINARY)
        result = scanner.scan(target)
        assert result.status == ScanStatus.FAILED

    def test_binary_scan_on_synthetic_binary_with_strings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_path = Path(tmpdir) / "sample_crypto.bin"
            # Write synthetic binary with embedded crypto strings
            data = (
                b"\x7fELF\x02\x01\x01\x00" +  # ELF header
                b"\x00" * 32 +
                b"OpenSSL 1.1.1k  25 Mar 2021\x00" +
                b"\x00" * 16 +
                b"TLS_RSA_WITH_AES_256_GCM_SHA384\x00" +
                b"\x00" * 16 +
                b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\x00" +
                b"\x00" * 64
            )
            bin_path.write_bytes(data)

            scanner = BinaryScanner()
            target = ScanTarget(path=str(bin_path), target_type=TargetType.BINARY)
            result = scanner.scan(target)

            assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
            assert len(result.findings) > 0
            
            # Check version string detection
            lib_findings = [f for f in result.findings if f.artifact_category == ArtifactCategory.LIBRARY]
            assert len(lib_findings) > 0
            assert any("OpenSSL" in f.library_hint for f in lib_findings if f.library_hint)

    def test_binary_scan_on_current_python_interpreter(self):
        python_bin = Path(sys.executable)
        if not python_bin.exists():
            pytest.skip("Cannot find python executable")

        scanner = BinaryScanner()
        target = ScanTarget(path=str(python_bin), target_type=TargetType.BINARY)
        result = scanner.scan(target)

        assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
        # Python interpreter binary often contains SSL/hashlib strings
        assert result.statistics.files_scanned == 1
