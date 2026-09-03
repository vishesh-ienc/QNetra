"""
Tests for QNetra Normalization Subsystem (core/normalization/)
==============================================================

Verifies all normalization requirements:
  1. Single finding -> single CryptoAsset
  2. Multiple identical findings -> one asset
  3. Different algorithms -> separate assets
  4. Algorithm naming normalization (AES, RSA, SHA, ECC, PQC)
  5. Parameter normalization (key size, mode, curve, padding)
  6. Multiple scanner findings supporting one asset
  7. Ambiguous findings remain separate
  8. Supporting finding IDs preserved
  9. Evidence preserved (locations, snippets, rationales)
  10. Confidence aggregation (monotonic, bounded, explainable)
  11. Deterministic asset IDs (RFC 4122 UUIDv5)
  12. Empty input
  13. Malformed / partial findings
  14. Duplicate findings
  15. Repeated runs produce identical results
"""

import copy
import uuid
import pytest

from core.models import CryptoAsset, PrimitiveType
from core.normalization import Normalizer
from core.normalization.algorithm_normalizer import AlgorithmNormalizer
from core.normalization.confidence_aggregator import ConfidenceAggregator
from core.normalization.deduplicator import Deduplicator
from scanners.framework.models import (
    ArtifactCategory,
    ConfidenceLevel,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)


def _make_finding(
    raw_symbol: str = "RSA.generate(2048)",
    suspected_algorithm: str = "RSA",
    artifact_category: ArtifactCategory = ArtifactCategory.ASYMMETRIC_PKC,
    file_path: str = "src/crypto.py",
    start_line: int = 10,
    end_line: int = 12,
    snippet: str = "key = RSA.generate(2048)",
    key_size_hint: int = None,
    mode_hint: str = None,
    curve_hint: str = None,
    library_hint: str = "pycryptodome",
    confidence_score: float = 0.95,
    discovery_method: DiscoveryMethod = DiscoveryMethod.AST,
    scanner_name: str = "RepositoryScanner/PythonAnalyzer",
) -> RawFinding:
    """Helper to construct a RawFinding instance for testing."""
    effective_key_size = key_size_hint
    if effective_key_size is None and "2048" in raw_symbol:
        effective_key_size = 2048
    return RawFinding(
        finding_id=str(uuid.uuid4()),
        scanner_name=scanner_name,
        discovery_method=discovery_method,
        raw_symbol=raw_symbol,
        suspected_algorithm=suspected_algorithm,
        artifact_category=artifact_category,
        library_hint=library_hint,
        key_size_hint=effective_key_size,
        mode_hint=mode_hint,
        curve_hint=curve_hint,
        location=FileLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=snippet,
        ),
        confidence_score=confidence_score,
        confidence_rationale=f"Test rationale for {raw_symbol}",
    )


class TestNormalization:
    """Core Normalization Test Suite."""

    def test_single_finding_to_single_asset(self):
        """1. Verify a single RawFinding normalizes to exactly one CryptoAsset."""
        finding = _make_finding()
        normalizer = Normalizer()
        assets = normalizer.normalize([finding])

        assert len(assets) == 1
        asset = assets[0]
        assert asset.algorithm == "RSA"
        assert asset.algorithm_family == "RSA"
        assert asset.primitive_type == PrimitiveType.ASYMMETRIC_ENCRYPTION
        assert asset.key_length_bits == 2048
        assert asset.implementation_library == "pycryptodome"
        assert asset.location.file_path == "src/crypto.py"
        assert asset.location.start_line == 10
        assert asset.location.snippet == "key = RSA.generate(2048)"
        assert asset.supporting_finding_ids == [finding.finding_id]
        assert len(asset.supporting_findings) == 1
        assert asset.confidence_score == 0.95
        assert asset.confidence_level == ConfidenceLevel.VERY_HIGH

    def test_multiple_identical_findings_merge(self):
        """2. Verify multiple identical findings on the same line merge into one asset."""
        f1 = _make_finding(start_line=20, confidence_score=0.70)
        f2 = _make_finding(start_line=20, confidence_score=0.80)
        f3 = _make_finding(start_line=20, confidence_score=0.60)

        normalizer = Normalizer()
        assets = normalizer.normalize([f1, f2, f3])

        assert len(assets) == 1
        asset = assets[0]
        assert set(asset.supporting_finding_ids) == {f1.finding_id, f2.finding_id, f3.finding_id}
        assert len(asset.supporting_findings) == 3
        # Confidence aggregated monotonically
        assert asset.confidence_score > 0.80

    def test_different_algorithms_separate(self):
        """3. Verify findings with different algorithms produce separate assets."""
        f_rsa = _make_finding(
            raw_symbol="RSA.generate(2048)",
            suspected_algorithm="RSA",
            artifact_category=ArtifactCategory.ASYMMETRIC_PKC,
            start_line=10,
        )
        f_aes = _make_finding(
            raw_symbol="Cipher.AES.new(key, AES.MODE_GCM)",
            suspected_algorithm="AES",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            start_line=10,
            key_size_hint=256,
            mode_hint="GCM",
        )

        normalizer = Normalizer()
        assets = normalizer.normalize([f_rsa, f_aes])

        assert len(assets) == 2
        algs = {a.algorithm for a in assets}
        assert "RSA" in algs
        assert any("AES" in a for a in algs)

    def test_algorithm_naming_normalization(self):
        """4. Verify canonical naming across various algorithm styles."""
        test_cases = [
            ("AES_256_GCM", "AES-256-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER),
            ("AES-128-CBC", "AES-128-CBC", "AES", PrimitiveType.SYMMETRIC_CIPHER),
            ("AES/GCM/NoPadding", "AES-GCM", "AES", PrimitiveType.SYMMETRIC_CIPHER),
            ("aes256", "AES-256", "AES", PrimitiveType.SYMMETRIC_CIPHER),
            ("EVP_sha256", "SHA-256", "SHA", PrimitiveType.HASH_FUNCTION),
            ("sha512", "SHA-512", "SHA", PrimitiveType.HASH_FUNCTION),
            ("secp256r1", "ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE),
            ("prime256v1", "ECDSA", "ECC", PrimitiveType.DIGITAL_SIGNATURE),
            ("Ed25519", "Ed25519", "ECC", PrimitiveType.DIGITAL_SIGNATURE),
            ("x25519", "ECDH", "ECC", PrimitiveType.KEY_EXCHANGE),
            ("ML-KEM-768", "ML-KEM", "ML-KEM", PrimitiveType.KEY_EXCHANGE),
            ("ML-DSA-65", "ML-DSA", "ML-DSA", PrimitiveType.DIGITAL_SIGNATURE),
            ("SLH-DSA-128s", "SLH-DSA", "SLH-DSA", PrimitiveType.DIGITAL_SIGNATURE),
            ("TLSv1.2", "TLS", "PROTOCOL", PrimitiveType.PROTOCOL),
        ]

        normalizer = Normalizer()
        for raw, expected_alg, expected_fam, expected_type in test_cases:
            f = _make_finding(raw_symbol=raw, suspected_algorithm=raw)
            assets = normalizer.normalize([f])
            assert len(assets) == 1, f"Failed for {raw}"
            asset = assets[0]
            assert expected_alg in asset.algorithm, f"Expected {expected_alg} in {asset.algorithm} for {raw}"
            assert asset.algorithm_family == expected_fam, f"Expected {expected_fam} for {raw}"
            assert asset.primitive_type == expected_type, f"Expected {expected_type} for {raw}"

    def test_parameter_normalization(self):
        """5. Verify parameter normalization (key size, mode, curve, padding)."""
        # Java JCA pattern
        f_jca = _make_finding(
            raw_symbol='Cipher.getInstance("AES/CBC/PKCS5Padding")',
            suspected_algorithm="AES/CBC/PKCS5Padding",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            start_line=15,
        )
        assets = Normalizer().normalize([f_jca])
        assert len(assets) == 1
        a = assets[0]
        assert a.mode == "CBC"
        assert a.padding == "PKCS7"

        # ECC curve
        f_ecc = _make_finding(
            raw_symbol="ec.generate_private_key(ec.SECP256R1())",
            suspected_algorithm="ECDSA",
            artifact_category=ArtifactCategory.DIGITAL_SIGNATURE,
            curve_hint="prime256v1",
            start_line=30,
        )
        assets_ecc = Normalizer().normalize([f_ecc])
        assert len(assets_ecc) == 1
        assert assets_ecc[0].curve == "secp256r1"

    def test_multiple_scanners_supporting_one_asset(self):
        """6. Verify AST + REGEX findings in same file/line corroborate into one asset."""
        f_ast = _make_finding(
            raw_symbol="RSA.generate(2048)",
            suspected_algorithm="RSA",
            discovery_method=DiscoveryMethod.AST,
            scanner_name="RepositoryScanner/PythonAnalyzer",
            start_line=42,
            key_size_hint=2048,
            confidence_score=0.95,
        )
        f_regex = _make_finding(
            raw_symbol="RSA",
            suspected_algorithm="RSA",
            discovery_method=DiscoveryMethod.REGEX,
            scanner_name="RepositoryScanner/PythonAnalyzer",
            start_line=42,
            key_size_hint=None,
            confidence_score=0.40,
        )

        assets = Normalizer().normalize([f_ast, f_regex])
        assert len(assets) == 1
        asset = assets[0]
        assert asset.key_length_bits == 2048
        assert set(asset.supporting_finding_ids) == {f_ast.finding_id, f_regex.finding_id}
        assert "AST" in asset.metadata["discovery_methods"]
        assert "REGEX" in asset.metadata["discovery_methods"]
        # Confidence score boosted above 0.95 by corroboration
        assert asset.confidence_score > 0.95

    def test_ambiguous_findings_remain_separate(self):
        """7. Verify findings at distinct locations or conflicting parameters remain separate."""
        # Same file but lines far apart
        f_line10 = _make_finding(start_line=10, key_size_hint=2048)
        f_line80 = _make_finding(start_line=80, key_size_hint=2048)
        assets = Normalizer().normalize([f_line10, f_line80])
        assert len(assets) == 2

        # Same line but conflicting key size (e.g. 1024 vs 2048)
        f_k1 = _make_finding(start_line=15, key_size_hint=1024)
        f_k2 = _make_finding(start_line=15, key_size_hint=2048)
        assets_conflicting = Normalizer().normalize([f_k1, f_k2])
        assert len(assets_conflicting) == 2

    def test_supporting_finding_ids_preserved(self):
        """8. Verify all supporting finding IDs are retained."""
        findings = [_make_finding(start_line=5, confidence_score=0.5 + i * 0.1) for i in range(4)]
        assets = Normalizer().normalize(findings)
        assert len(assets) == 1
        assert sorted(assets[0].supporting_finding_ids) == sorted(f.finding_id for f in findings)

    def test_evidence_preserved(self):
        """9. Verify line numbers, snippets, and finding details are preserved in evidence."""
        f = _make_finding(snippet="secret_key = RSA.generate(4096)", key_size_hint=4096)
        assets = Normalizer().normalize([f])
        assert len(assets) == 1
        a = assets[0]
        assert a.location.snippet == "secret_key = RSA.generate(4096)"
        assert len(a.supporting_findings) == 1
        sf = a.supporting_findings[0]
        assert sf.finding_id == f.finding_id
        assert sf.raw_symbol == f.raw_symbol
        assert sf.location.snippet == f.location.snippet

    def test_confidence_aggregation_formula(self):
        """10. Verify confidence aggregation is monotonic, bounded by 1.0, and explainable."""
        # Single finding
        f1 = _make_finding(confidence_score=0.75)
        score, level, rationale = ConfidenceAggregator.aggregate([f1])
        assert score == 0.75
        assert level == ConfidenceLevel.HIGH

        # Multiple findings
        f2 = _make_finding(confidence_score=0.60)
        f3 = _make_finding(confidence_score=0.80)
        # Expected: max(0.75, 0.60, 0.80) = 0.80 + 0.05 * 0.75 + 0.05 * 0.60 = 0.80 + 0.0375 + 0.03 = 0.8675
        score_multi, level_multi, rat_multi = ConfidenceAggregator.aggregate([f1, f2, f3])
        assert score_multi == pytest.approx(0.8675, rel=1e-3)
        assert level_multi == ConfidenceLevel.VERY_HIGH
        assert "corroboration bonus" in rat_multi

        # Capped at 1.0
        high_findings = [_make_finding(confidence_score=0.99) for _ in range(5)]
        score_capped, _, _ = ConfidenceAggregator.aggregate(high_findings)
        assert score_capped == 1.0

    def test_deterministic_asset_ids(self):
        """11. Verify RFC 4122 UUIDv5 produces identical asset IDs for identical seeds."""
        f1 = _make_finding(raw_symbol="AES-256-GCM", suspected_algorithm="AES-256-GCM", start_line=50)
        f2 = _make_finding(raw_symbol="AES-256-GCM", suspected_algorithm="AES-256-GCM", start_line=50)

        assets1 = Normalizer().normalize([f1])
        assets2 = Normalizer().normalize([f2])

        assert len(assets1) == 1
        assert len(assets2) == 1
        assert assets1[0].asset_id == assets2[0].asset_id
        # Verify it is a valid UUID string
        uuid_obj = uuid.UUID(assets1[0].asset_id)
        assert uuid_obj.version == 5

    def test_empty_input(self):
        """12. Verify empty input returns empty list without errors."""
        normalizer = Normalizer()
        assert normalizer.normalize([]) == []

    def test_malformed_partial_findings(self):
        """13. Verify findings with missing/None optional fields normalize safely."""
        partial_finding = RawFinding(
            finding_id=str(uuid.uuid4()),
            scanner_name="TestScanner",
            discovery_method=DiscoveryMethod.STRING_ANALYSIS,
            raw_symbol="unknown_str",
            suspected_algorithm=None,  # missing
            artifact_category=ArtifactCategory.UNKNOWN,
            location=FileLocation(file_path="bin/unknown.elf"),
            confidence_score=0.30,
            confidence_rationale="Partial finding",
        )

        assets = Normalizer().normalize([partial_finding])
        assert len(assets) == 1
        assert assets[0].algorithm == "Unknown Algorithm"
        assert assets[0].primitive_type == PrimitiveType.UNKNOWN
        assert assets[0].location.start_line is None

    def test_duplicate_findings_idempotency(self):
        """14. Verify feeding duplicate identical finding records produces 1 asset."""
        f = _make_finding(start_line=10)
        f_dup = copy.deepcopy(f)

        assets = Normalizer().normalize([f, f_dup])
        assert len(assets) == 1

    def test_repeated_runs_produce_identical_results(self):
        """15. Verify normalization is 100% idempotent across repeated runs."""
        findings = [
            _make_finding(raw_symbol="RSA.generate(2048)", start_line=10),
            _make_finding(raw_symbol="AES.new(key)", suspected_algorithm="AES", start_line=20),
            _make_finding(raw_symbol="SHA256.new()", suspected_algorithm="SHA-256", start_line=30),
        ]

        normalizer = Normalizer()
        run1 = normalizer.normalize(findings)
        run2 = normalizer.normalize(findings)

        assert len(run1) == len(run2)
        for a1, a2 in zip(run1, run2):
            assert a1.asset_id == a2.asset_id
            assert a1.algorithm == a2.algorithm
            assert a1.confidence_score == a2.confidence_score

    def test_to_api_dict_contract(self):
        """16. Verify to_api_dict produces expected keys from docs/10_API_CONTRACT.md."""
        f = _make_finding()
        assets = Normalizer().normalize([f])
        api_dict = assets[0].to_api_dict()

        required_keys = {
            "asset_id", "algorithm", "algorithm_family", "primitive_type",
            "key_length_bits", "curve", "mode", "padding", "implementation_library",
            "location", "confidence_score", "confidence_level", "risk_score",
            "risk_severity", "supporting_finding_ids", "recommendation_id",
        }
        assert required_keys.issubset(set(api_dict.keys()))

    def test_binary_findings_aggregation(self):
        """17. Verify multiple string/symbol findings in a binary merge into the binary's asset."""
        from scanners.framework.models import BinaryFormat

        f_str = RawFinding(
            finding_id="bin-find-1",
            scanner_name="BinaryScanner/StringAnalyzer",
            discovery_method=DiscoveryMethod.STRING_ANALYSIS,
            raw_symbol="AES-256-GCM",
            suspected_algorithm="AES-256-GCM",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            binary_format=BinaryFormat.ELF,
            location=FileLocation(file_path="bin/crypto_app.elf", byte_offset=0x1024),
            confidence_score=0.85,
            confidence_rationale="String analysis matched cipher suite",
        )
        f_sym = RawFinding(
            finding_id="bin-find-2",
            scanner_name="BinaryScanner/SymbolInspector",
            discovery_method=DiscoveryMethod.SYMBOL_INSPECTION,
            raw_symbol="EVP_aes_256_gcm",
            symbol_name="EVP_aes_256_gcm",
            suspected_algorithm="AES-256-GCM",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            binary_format=BinaryFormat.ELF,
            location=FileLocation(file_path="bin/crypto_app.elf", byte_offset=0x2048),
            confidence_score=0.90,
            confidence_rationale="Symbol table inspection matched OpenSSL symbol",
        )

        assets = Normalizer().normalize([f_str, f_sym])
        assert len(assets) == 1
        asset = assets[0]
        assert asset.algorithm == "AES-256-GCM"
        assert asset.key_length_bits == 256
        assert asset.mode == "GCM"
        assert set(asset.supporting_finding_ids) == {"bin-find-1", "bin-find-2"}
        assert asset.metadata["binary_format"] == "ELF"
        assert "EVP_aes_256_gcm" in asset.metadata["symbols"]
        assert asset.confidence_score > 0.90

    def test_container_findings_aggregation(self):
        """18. Verify multiple findings in a container file merge into 1 asset."""
        from scanners.framework.models import ContainerContext

        ctx = ContainerContext(image_reference="ubuntu:22.04", filesystem_path="/usr/lib/libcrypto.so.3")
        f1 = RawFinding(
            finding_id="cont-find-1",
            scanner_name="ContainerScanner/FilesystemInspector",
            discovery_method=DiscoveryMethod.LIBRARY_DETECTION,
            raw_symbol="libcrypto.so.3",
            suspected_algorithm=None,
            artifact_category=ArtifactCategory.LIBRARY,
            library_hint="OpenSSL",
            container_context=ctx,
            location=FileLocation(file_path="/usr/lib/libcrypto.so.3"),
            confidence_score=0.80,
            confidence_rationale="Shared library found",
        )
        f2 = RawFinding(
            finding_id="cont-find-2",
            scanner_name="ContainerScanner/PackageInspector",
            discovery_method=DiscoveryMethod.PACKAGE_INSPECTION,
            raw_symbol="openssl==3.0.2",
            suspected_algorithm=None,
            artifact_category=ArtifactCategory.LIBRARY,
            library_hint="OpenSSL",
            container_context=ctx,
            location=FileLocation(file_path="/usr/lib/libcrypto.so.3"),
            confidence_score=0.75,
            confidence_rationale="dpkg package matched",
        )

        assets = Normalizer().normalize([f1, f2])
        assert len(assets) == 1
        asset = assets[0]
        assert "OpenSSL" in asset.algorithm
        assert asset.primitive_type == PrimitiveType.LIBRARY
        assert asset.implementation_library == "OpenSSL"
        assert set(asset.supporting_finding_ids) == {"cont-find-1", "cont-find-2"}

    def test_compute_statistics(self):
        """19. Verify Normalizer.compute_statistics computes accurate metrics."""
        f1 = _make_finding(start_line=10)
        f2 = _make_finding(start_line=10)  # duplicates f1
        f3 = _make_finding(raw_symbol="AES.new()", suspected_algorithm="AES", start_line=50)

        findings = [f1, f2, f3]
        normalizer = Normalizer()
        assets = normalizer.normalize(findings)
        stats = normalizer.compute_statistics(findings, assets)

        assert stats.raw_findings_count == 3
        assert stats.assets_produced_count == 2
        assert stats.findings_merged_count == 1
        assert stats.merge_ratio == pytest.approx(0.3333, rel=1e-3)
        assert stats.assets_by_primitive_type[PrimitiveType.ASYMMETRIC_ENCRYPTION.value] == 1
        assert stats.assets_by_primitive_type[PrimitiveType.SYMMETRIC_CIPHER.value] == 1


class TestNormalizationRegressions:
    """
    Regression tests for normalization correctness.
    These specifically target bugs that were identified and fixed.
    """

    def test_aes_jca_no_key_size_without_hint(self):
        """
        REGRESSION: AES/GCM/NoPadding must NOT fabricate key_length_bits.

        'AES/GCM/NoPadding' specifies algorithm, mode, and padding but provides
        NO key size information. key_length_bits must remain None.
        Fabricating 128 (or any default) would corrupt downstream quantum classification.
        """
        f = _make_finding(
            raw_symbol='Cipher.getInstance("AES/GCM/NoPadding")',
            suspected_algorithm="AES/GCM/NoPadding",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            key_size_hint=None,
            mode_hint=None,
            start_line=20,
            library_hint="javax.crypto",
        )
        assets = Normalizer().normalize([f])
        assert len(assets) == 1
        asset = assets[0]
        assert "AES" in asset.algorithm
        assert asset.mode == "GCM"
        # KEY ASSERTION: No key size must be fabricated
        assert asset.key_length_bits is None, (
            f"key_length_bits must be None for AES/GCM/NoPadding without explicit key hint, "
            f"got {asset.key_length_bits}"
        )

    def test_aes_new_call_no_explicit_key(self):
        """
        REGRESSION: AES.new(key, AES.MODE_GCM) must NOT fabricate key_length_bits.

        The raw symbol does not contain any numeric key size literal.
        key_length_bits must remain None because no key size is observable.
        """
        f = _make_finding(
            raw_symbol="AES.new(key, AES.MODE_GCM)",
            suspected_algorithm="AES",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            key_size_hint=None,
            mode_hint="GCM",
            start_line=35,
        )
        assets = Normalizer().normalize([f])
        assert len(assets) == 1
        assert assets[0].key_length_bits is None, (
            f"key_length_bits must be None for AES.new(key, AES.MODE_GCM), "
            f"got {assets[0].key_length_bits}"
        )

    def test_aes_raw_symbol_with_unrelated_numbers_no_key_injection(self):
        """
        REGRESSION: Numbers in raw_sym that are NOT structured key-size parameters
        must not be injected as AES key size.

        Scenarios tested:
        - Raw symbol contains '128' as a variable name component
        - Raw symbol contains '256' in a hex address or unrelated constant
        None of these must cause key_length_bits to be populated.
        """
        # Case 1: '128' appears in a variable name, not a key size parameter
        f_var_name = _make_finding(
            raw_symbol="cipher = AES_helper_128bit_mode.init(key)",
            suspected_algorithm="AES",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            key_size_hint=None,
            start_line=55,
        )
        assets = Normalizer().normalize([f_var_name])
        assert assets[0].key_length_bits is None, (
            "Variable name containing '128' must not inject AES key size"
        )

        # Case 2: '256' appears as a buffer size, not a key size
        f_buf_size = _make_finding(
            raw_symbol="aes_ctx = setup_AES_cipher(buf, sizeof_buf=256)",
            suspected_algorithm="AES",
            artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
            key_size_hint=None,
            start_line=70,
        )
        assets2 = Normalizer().normalize([f_buf_size])
        assert assets2[0].key_length_bits is None, (
            "Buffer size '256' in raw_sym must not inject AES key size"
        )


