"""Tests for ScannerRouter — format detection and scanner dispatch."""

import pytest
from scanners.framework.models import ScanTarget, TargetType
from scanners.framework.router import ScannerRouter, _auto_detect_target_type, _detect_binary_format
from scanners.framework.models import BinaryFormat
from pathlib import Path
import tempfile
import os


class TestFormatDetection:
    """Test binary format detection from magic bytes."""

    def _write_magic(self, tmp_dir: str, name: str, magic: bytes) -> Path:
        path = Path(tmp_dir) / name
        path.write_bytes(magic + b"\x00" * 128)
        return path

    def test_detects_elf(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_magic(d, "test.elf", b"\x7fELF\x02\x01\x01\x00")
            fmt = _detect_binary_format(p)
            assert fmt == BinaryFormat.ELF

    def test_detects_pe(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_magic(d, "test.exe", b"MZ\x90\x00\x03\x00")
            fmt = _detect_binary_format(p)
            assert fmt == BinaryFormat.PE

    def test_unknown_format(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_magic(d, "test.bin", b"\x00\x01\x02\x03")
            fmt = _detect_binary_format(p)
            assert fmt == BinaryFormat.UNKNOWN

    def test_nonexistent_file_returns_unknown(self):
        fmt = _detect_binary_format(Path("/nonexistent/file.bin"))
        assert fmt == BinaryFormat.UNKNOWN


class TestAutoDetectTargetType:
    """Test target type auto-detection heuristics."""

    def test_directory_detected_as_repository(self):
        with tempfile.TemporaryDirectory() as d:
            t = _auto_detect_target_type(Path(d))
            assert t == TargetType.REPOSITORY

    def test_elf_file_detected_as_binary(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "mylib.so"
            p.write_bytes(b"\x7fELF" + b"\x00" * 60)
            t = _auto_detect_target_type(p)
            assert t == TargetType.BINARY


class TestScannerRouter:
    """Test ScannerRouter registration and routing logic."""

    def _make_mock_scanner(self, name: str, status="COMPLETED"):
        """Create a minimal mock scanner that returns a success result."""
        from unittest.mock import MagicMock
        from scanners.framework.models import ScanResult, ScanStatus
        mock = MagicMock()
        mock.name = name
        mock.scan.return_value = ScanResult(
            target=ScanTarget(path="/tmp/test"),
            scanner_name=name,
            status=ScanStatus.COMPLETED,
        )
        return mock

    def test_register_and_route(self):
        router = ScannerRouter()
        mock = self._make_mock_scanner("MockRepoScanner")
        router.register(TargetType.REPOSITORY, mock)
        assert TargetType.REPOSITORY in router.registered_types()

    def test_route_to_correct_scanner(self):
        with tempfile.TemporaryDirectory() as d:
            router = ScannerRouter()
            mock = self._make_mock_scanner("MockRepoScanner")
            router.register(TargetType.REPOSITORY, mock)

            target = ScanTarget(path=d, target_type=TargetType.REPOSITORY)
            result = router.route(target)
            mock.scan.assert_called_once()

    def test_unregistered_type_returns_failed(self):
        router = ScannerRouter()
        target = ScanTarget(path="/tmp/test.bin", target_type=TargetType.BINARY)
        result = router.route(target)
        from scanners.framework.models import ScanStatus
        assert result.status == ScanStatus.FAILED
        assert result.errors

    def test_cannot_register_auto_type(self):
        router = ScannerRouter()
        mock = self._make_mock_scanner("TestScanner")
        with pytest.raises(ValueError):
            router.register(TargetType.AUTO, mock)
