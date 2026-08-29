"""
Tests for CppAnalyzer — OpenSSL includes, EVP APIs, RSA key generation, and ciphers.
"""

import pytest
from pathlib import Path
from scanners.repository.languages.cpp_analyzer import CppAnalyzer
from scanners.framework.models import ArtifactCategory, DiscoveryMethod


@pytest.fixture
def analyzer():
    return CppAnalyzer()


@pytest.fixture
def crypto_utils_c(cpp_samples_dir):
    return (cpp_samples_dir / "crypto_utils.c").read_text(encoding="utf-8")


class TestCppAnalyzer:
    """Tests for C/C++ analyzer."""

    def test_detects_openssl_includes(self, analyzer, crypto_utils_c):
        findings = analyzer.analyze(Path("crypto_utils.c"), crypto_utils_c)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        libs = {f.library_hint for f in import_findings if f.library_hint}
        assert "OpenSSL" in libs

    def test_detects_rsa_calls(self, analyzer, crypto_utils_c):
        findings = analyzer.analyze(Path("crypto_utils.c"), crypto_utils_c)
        rsa_calls = [f for f in findings if f.suspected_algorithm == "RSA"]
        assert len(rsa_calls) > 0

    def test_detects_evp_ciphers(self, analyzer, crypto_utils_c):
        findings = analyzer.analyze(Path("crypto_utils.c"), crypto_utils_c)
        aes_calls = [f for f in findings if f.suspected_algorithm == "AES"]
        assert len(aes_calls) > 0

    def test_detects_sha_functions(self, analyzer, crypto_utils_c):
        findings = analyzer.analyze(Path("crypto_utils.c"), crypto_utils_c)
        sha_calls = [f for f in findings if f.artifact_category == ArtifactCategory.HASH_FUNCTION]
        assert len(sha_calls) > 0

    def test_handles_empty_c_file(self, analyzer):
        findings = analyzer.analyze(Path("empty.c"), "")
        assert findings == []
