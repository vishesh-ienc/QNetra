"""
Tests for JavaScriptAnalyzer — require, ES6 import, API call pattern, and crypto algorithm detection.
"""

import pytest
from pathlib import Path
from scanners.repository.languages.javascript_analyzer import JavaScriptAnalyzer
from scanners.framework.models import ArtifactCategory, DiscoveryMethod


@pytest.fixture
def analyzer():
    return JavaScriptAnalyzer()


@pytest.fixture
def crypto_service_js(javascript_samples_dir):
    return (javascript_samples_dir / "crypto_service.js").read_text(encoding="utf-8")


class TestJavaScriptAnalyzer:
    """Tests for JavaScript analyzer."""

    def test_detects_crypto_imports(self, analyzer, crypto_service_js):
        findings = analyzer.analyze(Path("crypto_service.js"), crypto_service_js)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        libs = {f.library_hint for f in import_findings if f.library_hint}
        assert "node:crypto" in libs or "jsonwebtoken" in libs or "crypto-js" in libs

    def test_detects_aes_cipher(self, analyzer, crypto_service_js):
        findings = analyzer.analyze(Path("crypto_service.js"), crypto_service_js)
        aes_findings = [f for f in findings if f.suspected_algorithm == "AES"]
        assert len(aes_findings) > 0

    def test_detects_rsa_keygen(self, analyzer, crypto_service_js):
        findings = analyzer.analyze(Path("crypto_service.js"), crypto_service_js)
        rsa_findings = [f for f in findings if f.suspected_algorithm == "RSA"]
        assert len(rsa_findings) > 0

    def test_detects_hash_functions(self, analyzer, crypto_service_js):
        findings = analyzer.analyze(Path("crypto_service.js"), crypto_service_js)
        hash_findings = [f for f in findings if f.artifact_category == ArtifactCategory.HASH_FUNCTION]
        assert len(hash_findings) > 0

    def test_detects_hmac(self, analyzer, crypto_service_js):
        findings = analyzer.analyze(Path("crypto_service.js"), crypto_service_js)
        hmac_findings = [f for f in findings if f.suspected_algorithm == "HMAC"]
        assert len(hmac_findings) > 0

    def test_handles_empty_js_file(self, analyzer):
        findings = analyzer.analyze(Path("empty.js"), "")
        assert findings == []
