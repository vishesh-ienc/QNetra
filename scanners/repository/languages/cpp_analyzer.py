"""
QNetra Repository Scanner — C / C++ Language Analyzer

Analyzes C and C++ source files for cryptographic indicators using:
1. Include Analysis: Detect #include directives for known crypto headers.
2. API Pattern Matching: Identify OpenSSL, mbedTLS, and libsodium function calls.
3. Crypto Pattern Matching: General algorithm identifier and key material detection.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_api_map import CPP_API_MAP
from scanners.registry.crypto_libraries import find_library_by_import
from scanners.registry.crypto_patterns import ALL_PATTERNS, is_comment_line
from scanners.repository.confidence import SignalType, calculate_confidence
from scanners.repository.languages.base_analyzer import LanguageAnalyzer

logger = logging.getLogger(__name__)

_SCANNER_NAME = "RepositoryScanner/CppAnalyzer"

# C/C++ #include pattern
_INCLUDE_PATTERN = re.compile(r'^\s*#include\s*[<"]([^>"]+)[>"]', re.MULTILINE)

# Function call patterns for known C crypto APIs
_C_API_PATTERNS: list[tuple[re.Pattern, str, str, str]] = []
for _e in CPP_API_MAP:
    short_name = _e.api_name.split(".")[-1]
    _pat = re.compile(r'\b' + re.escape(short_name) + r'\s*\(')
    _C_API_PATTERNS.append((_pat, _e.api_name, _e.algorithm, _e.category))

# Specific OpenSSL cipher type patterns (EVP_aes_256_gcm(), etc.)
_EVP_CIPHER_PATTERN = re.compile(
    r'\bEVP_(aes|des|chacha20|rc4)_?(\d*)_?(cbc|gcm|ctr|cfb|ofb|ecb|ccm)?\s*\(\)',
    re.IGNORECASE
)

# RSA key size in EVP context
_RSA_KEY_SIZE = re.compile(r'RSA_generate_key(?:_ex)?\s*\([^,]+,\s*(\d+)')


class CppAnalyzer(LanguageAnalyzer):
    """C/C++ cryptographic code analyzer."""

    LANGUAGE_NAME = "cpp"

    def analyze(self, file_path: Path, content: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        lines = content.splitlines()

        # Phase 1: Include detection
        detected_headers: set[str] = set()
        for match in _INCLUDE_PATTERN.finditer(content):
            header = match.group(1)
            entry = find_library_by_import(header)
            if entry:
                detected_headers.add(header)
                line_idx = content[:match.start()].count("\n")
                conf = calculate_confidence(SignalType.KNOWN_IMPORT, base_override=entry.base_confidence)
                snippet = self._truncate_snippet(self._snippet(lines, line_idx))
                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.IMPORT_ANALYSIS,
                    raw_symbol=match.group(0).strip(),
                    artifact_category=ArtifactCategory.LIBRARY,
                    library_hint=entry.canonical_name,
                    location=FileLocation(
                        file_path=str(file_path),
                        start_line=line_idx + 1,
                        snippet=snippet,
                    ),
                    confidence_score=conf.score,
                    confidence_rationale=conf.rationale,
                ))

        # Phase 2: API call detection
        has_crypto_include = bool(detected_headers)
        for api_pat, api_name, algorithm, category_str in _C_API_PATTERNS:
            for match in api_pat.finditer(content):
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""
                if is_comment_line(line_text, "cpp"):
                    continue

                # Try to extract key size for RSA calls
                key_size_hint = None
                ks_match = _RSA_KEY_SIZE.search(content[max(0, match.start() - 20):match.end() + 100])
                if ks_match:
                    try:
                        key_size_hint = int(ks_match.group(1))
                    except ValueError:
                        pass

                conf = calculate_confidence(
                    SignalType.REGEX_EXECUTABLE,
                    has_import_corroboration=has_crypto_include,
                    has_api_mapping=True,
                )
                adj_score = min(conf.score + 0.08, 0.88)
                snippet = self._truncate_snippet(self._snippet(lines, line_idx))
                try:
                    cat = ArtifactCategory(category_str)
                except ValueError:
                    cat = ArtifactCategory.UNKNOWN

                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.API_CALL,
                    raw_symbol=match.group(0),
                    suspected_algorithm=algorithm,
                    artifact_category=cat,
                    key_size_hint=key_size_hint,
                    location=FileLocation(
                        file_path=str(file_path),
                        start_line=line_idx + 1,
                        snippet=snippet,
                    ),
                    confidence_score=adj_score,
                    confidence_rationale=f"C/C++ known crypto API: {api_name} | score={adj_score:.2f}",
                ))

        # Phase 3: EVP cipher type patterns
        for match in _EVP_CIPHER_PATTERN.finditer(content):
            line_idx = content[:match.start()].count("\n")
            snippet = self._truncate_snippet(self._snippet(lines, line_idx))
            algo_part = match.group(1).upper()
            algo = {"AES": "AES", "DES": "DES", "CHACHA20": "ChaCha20", "RC4": "RC4"}.get(algo_part, algo_part)
            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.API_CALL,
                raw_symbol=match.group(0),
                suspected_algorithm=algo,
                artifact_category=ArtifactCategory.SYMMETRIC_CIPHER,
                mode_hint=match.group(3).upper() if match.group(3) else None,
                location=FileLocation(
                    file_path=str(file_path),
                    start_line=line_idx + 1,
                    snippet=snippet,
                ),
                confidence_score=0.92,
                confidence_rationale=f"OpenSSL EVP cipher type: {match.group(0)} | score=0.92",
            ))

        # Phase 4: General pattern pass
        for pattern in ALL_PATTERNS:
            for match in pattern.pattern.finditer(content):
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""
                in_comment = is_comment_line(line_text, "cpp")
                conf_score = pattern.comment_confidence if in_comment else pattern.base_confidence
                if in_comment and conf_score < 0.22:
                    continue
                snippet = self._truncate_snippet(self._snippet(lines, line_idx))
                try:
                    cat = ArtifactCategory(pattern.category)
                except ValueError:
                    cat = ArtifactCategory.UNKNOWN
                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.REGEX,
                    raw_symbol=match.group(0),
                    suspected_algorithm=pattern.algorithm,
                    artifact_category=cat,
                    location=FileLocation(
                        file_path=str(file_path),
                        start_line=line_idx + 1,
                        snippet=snippet,
                    ),
                    confidence_score=conf_score,
                    confidence_rationale=f"C/C++ regex pattern '{pattern.name}' | score={conf_score:.2f}",
                ))

        return findings
