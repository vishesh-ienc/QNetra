"""
Tests for ContainerScanner — filesystem traversal, shared library detection, dpkg/npm/pip package inspection, and TLS config scanning.
"""

import pytest
from pathlib import Path
import tempfile
import os

from scanners.container.scanner import ContainerScanner
from scanners.framework.models import ScanTarget, TargetType, ScanStatus, ArtifactCategory, DiscoveryMethod


class TestContainerScanner:
    """Tests for ContainerScanner on synthetic container filesystems."""

    def _setup_mock_container_fs(self, root: Path):
        """Build a mock Linux container filesystem layout."""
        # /usr/lib with crypto libraries
        usr_lib = root / "usr" / "lib"
        usr_lib.mkdir(parents=True, exist_ok=True)
        (usr_lib / "libssl.so.3").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (usr_lib / "libcrypto.so.3").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (usr_lib / "libunrelated.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        # /var/lib/dpkg/status
        dpkg_dir = root / "var" / "lib" / "dpkg"
        dpkg_dir.mkdir(parents=True, exist_ok=True)
        (dpkg_dir / "status").write_text(
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Priority: optional\n"
            "Section: utils\n"
            "Installed-Size: 1540\n"
            "Maintainer: Ubuntu Developers\n"
            "Architecture: amd64\n"
            "Version: 3.0.2-0ubuntu1.10\n"
            "\n"
            "Package: curl\n"
            "Status: install ok installed\n"
            "Version: 7.81.0-1ubuntu1.14\n",
            encoding="utf-8"
        )

        # /etc/ssl with cert
        ssl_dir = root / "etc" / "ssl" / "certs"
        ssl_dir.mkdir(parents=True, exist_ok=True)
        (ssl_dir / "test_cert.pem").write_text(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBkDCB+wIJALa123...\n"
            "-----END CERTIFICATE-----\n",
            encoding="utf-8"
        )

    def test_container_scanner_validation(self):
        scanner = ContainerScanner()
        target = ScanTarget(path="/nonexistent/container/path", target_type=TargetType.CONTAINER_FS)
        result = scanner.scan(target)
        assert result.status == ScanStatus.FAILED

    def test_container_scanner_finds_shared_libraries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fs_root = Path(tmpdir)
            self._setup_mock_container_fs(fs_root)

            scanner = ContainerScanner()
            target = ScanTarget(
                path=str(fs_root),
                target_type=TargetType.CONTAINER_FS,
                metadata={"image_reference": "ubuntu:22.04"}
            )
            result = scanner.scan(target)

            assert result.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
            lib_findings = [f for f in result.findings if f.discovery_method == DiscoveryMethod.LIBRARY_DETECTION]
            assert len(lib_findings) > 0
            assert any("libssl" in f.raw_symbol for f in lib_findings)

    def test_container_scanner_finds_dpkg_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fs_root = Path(tmpdir)
            self._setup_mock_container_fs(fs_root)

            scanner = ContainerScanner()
            target = ScanTarget(
                path=str(fs_root),
                target_type=TargetType.CONTAINER_FS,
            )
            result = scanner.scan(target)

            pkg_findings = [f for f in result.findings if f.discovery_method == DiscoveryMethod.PACKAGE_INSPECTION]
            assert len(pkg_findings) > 0
            assert any("openssl" in f.raw_symbol for f in pkg_findings)

    def test_container_scanner_finds_tls_certs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fs_root = Path(tmpdir)
            self._setup_mock_container_fs(fs_root)

            scanner = ContainerScanner()
            target = ScanTarget(
                path=str(fs_root),
                target_type=TargetType.CONTAINER_FS,
            )
            result = scanner.scan(target)

            cert_findings = [f for f in result.findings if f.artifact_category == ArtifactCategory.CERTIFICATE]
            assert len(cert_findings) > 0
