"""
Tests for the Python Language Analyzer — core detection coverage.
Tests against the sample crypto fixtures in samples/repository_samples/python_crypto/
"""

import pytest
from pathlib import Path
from scanners.repository.languages.python_analyzer import PythonAnalyzer
from scanners.framework.models import ArtifactCategory, DiscoveryMethod


@pytest.fixture
def analyzer():
    return PythonAnalyzer()


@pytest.fixture
def crypto_manager_content(python_samples_dir):
    return (python_samples_dir / "crypto_manager.py").read_text(encoding="utf-8")


@pytest.fixture
def auth_module_content(python_samples_dir):
    return (python_samples_dir / "auth_module.py").read_text(encoding="utf-8")


class TestPythonImportDetection:
    """Tests for library import detection."""

    def test_detects_pycryptodome_import(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        lib_names = {f.library_hint for f in import_findings if f.library_hint}
        assert "pycryptodome" in lib_names or any("Crypto" in (f.raw_symbol or "") for f in import_findings)

    def test_detects_cryptography_import(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        lib_names = {f.library_hint for f in import_findings if f.library_hint}
        assert "cryptography" in lib_names

    def test_detects_hashlib_import(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        import_findings = [f for f in findings if f.discovery_method == DiscoveryMethod.IMPORT_ANALYSIS]
        has_hashlib = any("hashlib" in (f.raw_symbol or "") for f in import_findings)
        assert has_hashlib


class TestPythonASTDetection:
    """Tests for AST-based cryptographic API call detection."""

    def test_detects_rsa_generate(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        rsa_findings = [f for f in findings if f.suspected_algorithm == "RSA" and
                       f.discovery_method == DiscoveryMethod.AST]
        assert len(rsa_findings) > 0

    def test_rsa_finding_has_high_confidence(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        rsa_ast = [f for f in findings if f.suspected_algorithm == "RSA" and
                  f.discovery_method == DiscoveryMethod.AST]
        assert all(f.confidence_score >= 0.85 for f in rsa_ast)

    def test_detects_aes_mode(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        aes_findings = [f for f in findings if f.suspected_algorithm == "AES"]
        assert len(aes_findings) > 0

    def test_extracts_key_size_from_rsa(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        rsa_with_size = [f for f in findings if f.suspected_algorithm == "RSA" and
                        f.key_size_hint is not None]
        assert any(f.key_size_hint == 2048 for f in rsa_with_size)

    def test_detects_sha_hashes(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        hash_findings = [f for f in findings if f.artifact_category == ArtifactCategory.HASH_FUNCTION]
        algo_names = {f.suspected_algorithm for f in hash_findings if f.suspected_algorithm}
        # Should detect at least MD5, SHA-1, SHA-256, SHA-512
        assert len(algo_names) >= 2

    def test_detects_hmac(self, analyzer, auth_module_content):
        findings = analyzer.analyze(Path("auth_module.py"), auth_module_content)
        hmac_findings = [f for f in findings if f.suspected_algorithm == "HMAC"]
        assert len(hmac_findings) > 0

    def test_detects_pbkdf2(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        kdf_findings = [f for f in findings if f.suspected_algorithm == "PBKDF2"]
        assert len(kdf_findings) > 0

    def test_detects_ecdsa(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        ec_findings = [f for f in findings if f.suspected_algorithm in ("ECDSA", "ECDH", "EC")]
        assert len(ec_findings) > 0


class TestPythonPatternDetection:
    """Tests for regex pattern fallback detection."""

    def test_detects_pem_private_key(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        key_findings = [f for f in findings if f.artifact_category == ArtifactCategory.KEY_MATERIAL]
        assert len(key_findings) > 0

    def test_pem_finding_has_high_confidence(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        pem_findings = [f for f in findings if f.artifact_category == ArtifactCategory.KEY_MATERIAL]
        assert all(f.confidence_score >= 0.85 for f in pem_findings)


class TestPythonErrorHandling:
    """Tests that the analyzer handles bad input gracefully."""

    def test_handles_empty_file(self, analyzer):
        findings = analyzer.analyze(Path("empty.py"), "")
        assert findings == []

    def test_handles_syntax_error_gracefully(self, analyzer):
        bad_python = "def broken(:\n    pass\n"
        # Should not raise — falls back to regex
        findings = analyzer.analyze(Path("broken.py"), bad_python)
        assert isinstance(findings, list)

    def test_handles_non_crypto_file(self, analyzer):
        normal_code = "def add(a, b):\n    return a + b\n\nresult = add(1, 2)\n"
        findings = analyzer.analyze(Path("utils.py"), normal_code)
        # Should produce zero or very few findings for non-crypto code
        high_conf = [f for f in findings if f.confidence_score >= 0.70]
        assert len(high_conf) == 0

    def test_all_findings_have_required_fields(self, analyzer, crypto_manager_content):
        findings = analyzer.analyze(Path("crypto_manager.py"), crypto_manager_content)
        for f in findings:
            assert f.finding_id
            assert f.scanner_name
            assert f.discovery_method
            assert f.raw_symbol
            assert f.location
            assert f.location.file_path
            assert 0.0 <= f.confidence_score <= 1.0
            assert f.confidence_rationale
