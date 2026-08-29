"""
Tests for QNetra Framework Models — RawFinding, ScanTarget, ScanResult
"""

import pytest
from scanners.framework.models import (
    ArtifactCategory,
    ConfidenceLevel,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
    ScanOptions,
    ScanResult,
    ScanStatus,
    ScanTarget,
    TargetType,
)


class TestRawFinding:
    """Unit tests for RawFinding model."""

    def _make_finding(self, confidence_score: float = 0.90, **kwargs) -> RawFinding:
        defaults = dict(
            scanner_name="TestScanner",
            discovery_method=DiscoveryMethod.AST,
            raw_symbol="RSA.generate(2048)",
            suspected_algorithm="RSA",
            artifact_category=ArtifactCategory.ASYMMETRIC_PKC,
            location=FileLocation(file_path="src/crypto.py", start_line=42),
            confidence_score=confidence_score,
            confidence_rationale="Test finding",
        )
        defaults.update(kwargs)
        return RawFinding(**defaults)

    def test_finding_id_auto_generated(self):
        f = self._make_finding()
        assert f.finding_id
        assert len(f.finding_id) == 36  # UUID format

    def test_confidence_level_very_high(self):
        f = self._make_finding(confidence_score=0.92)
        assert f.confidence_level == ConfidenceLevel.VERY_HIGH

    def test_confidence_level_high(self):
        f = self._make_finding(confidence_score=0.75)
        assert f.confidence_level == ConfidenceLevel.HIGH

    def test_confidence_level_medium(self):
        f = self._make_finding(confidence_score=0.55)
        assert f.confidence_level == ConfidenceLevel.MEDIUM

    def test_confidence_level_low(self):
        f = self._make_finding(confidence_score=0.30)
        assert f.confidence_level == ConfidenceLevel.LOW

    def test_confidence_level_very_low(self):
        f = self._make_finding(confidence_score=0.10)
        assert f.confidence_level == ConfidenceLevel.VERY_LOW

    def test_confidence_score_bounds(self):
        """Confidence score must be in [0.0, 1.0]."""
        with pytest.raises(Exception):
            self._make_finding(confidence_score=1.5)
        with pytest.raises(Exception):
            self._make_finding(confidence_score=-0.1)

    def test_to_v1_dict_compatibility(self):
        """v1.0.0-draft backward-compatible serialization."""
        f = self._make_finding()
        v1 = f.to_v1_dict()
        assert "finding_id" in v1
        assert "source_file" in v1
        assert "confidence" in v1
        assert "scanner_type" in v1
        # Confidence should be a string enum value
        assert isinstance(v1["confidence"], str)

    def test_finding_with_key_size_hint(self):
        f = self._make_finding(key_size_hint=2048)
        assert f.key_size_hint == 2048

    def test_optional_fields_default_none(self):
        f = self._make_finding()
        assert f.key_size_hint is None
        assert f.mode_hint is None
        assert f.curve_hint is None
        assert f.symbol_name is None
        assert f.container_context is None


class TestScanTarget:
    """Unit tests for ScanTarget model."""

    def test_target_id_auto_generated(self):
        t = ScanTarget(path="/tmp/repo", target_type=TargetType.REPOSITORY)
        assert t.target_id
        assert len(t.target_id) == 36

    def test_default_target_type_is_auto(self):
        t = ScanTarget(path="/tmp/repo")
        assert t.target_type == TargetType.AUTO

    def test_custom_options(self):
        opts = ScanOptions(max_file_size_bytes=5 * 1024 * 1024, enable_ast=False)
        t = ScanTarget(path="/tmp/repo", options=opts)
        assert t.options.max_file_size_bytes == 5 * 1024 * 1024
        assert not t.options.enable_ast


class TestScanResult:
    """Unit tests for ScanResult model."""

    def _make_target(self) -> ScanTarget:
        return ScanTarget(path="/tmp/test", target_type=TargetType.REPOSITORY)

    def test_result_initial_state(self):
        target = self._make_target()
        result = ScanResult(target=target, scanner_name="TestScanner")
        assert result.status == ScanStatus.PENDING
        assert result.findings == []
        assert result.warnings == []
        assert result.errors == []

    def test_is_successful_completed(self):
        target = self._make_target()
        result = ScanResult(target=target, scanner_name="TestScanner", status=ScanStatus.COMPLETED)
        assert result.is_successful

    def test_is_successful_partial(self):
        target = self._make_target()
        result = ScanResult(target=target, scanner_name="TestScanner", status=ScanStatus.PARTIAL)
        assert result.is_successful

    def test_not_successful_failed(self):
        target = self._make_target()
        result = ScanResult(target=target, scanner_name="TestScanner", status=ScanStatus.FAILED)
        assert not result.is_successful
