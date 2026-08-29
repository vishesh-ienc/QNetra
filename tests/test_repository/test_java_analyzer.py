"""
Tests for JavaAnalyzer — javax.crypto, java.security, getInstance() calls and algorithms.
"""

import pytest
from pathlib import Path
from scanners.repository.languages.java_analyzer import JavaAnalyzer
from scanners.framework.models import ArtifactCategory, DiscoveryMethod


@pytest.fixture
def analyzer():
    return JavaAnalyzer()


@pytest.fixture
def crypto_service_java(java_samples_dir):
    return (java_samples_dir / "CryptoService.java").read_text(encoding="utf-8")


class TestJavaAnalyzer:
    """Tests for Java analyzer."""

    def test_detects_java_imports(self, analyzer, crypto_service_java):
        findings = analyzer.analyze(Path("CryptoService.java"), crypto_service_java)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        libs = {f.library_hint for f in import_findings if f.library_hint}
        assert "javax.crypto" in libs or "java.security" in libs

    def test_detects_get_instance_aes(self, analyzer, crypto_service_java):
        findings = analyzer.analyze(Path("CryptoService.java"), crypto_service_java)
        aes_calls = [f for f in findings if f.suspected_algorithm == "AES"]
        assert len(aes_calls) > 0

    def test_detects_get_instance_rsa(self, analyzer, crypto_service_java):
        findings = analyzer.analyze(Path("CryptoService.java"), crypto_service_java)
        rsa_calls = [f for f in findings if f.suspected_algorithm == "RSA"]
        assert len(rsa_calls) > 0

    def test_detects_message_digest_algorithms(self, analyzer, crypto_service_java):
        findings = analyzer.analyze(Path("CryptoService.java"), crypto_service_java)
        digests = [f for f in findings if f.artifact_category == ArtifactCategory.HASH_FUNCTION]
        assert len(digests) > 0

    def test_detects_des(self, analyzer, crypto_service_java):
        findings = analyzer.analyze(Path("CryptoService.java"), crypto_service_java)
        des_calls = [f for f in findings if f.suspected_algorithm in ("DES", "3DES")]
        assert len(des_calls) > 0

    def test_handles_empty_java_file(self, analyzer):
        findings = analyzer.analyze(Path("Empty.java"), "")
        assert findings == []
