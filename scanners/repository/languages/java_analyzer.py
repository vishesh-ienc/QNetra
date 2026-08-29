"""
QNetra Repository Scanner — Java Language Analyzer

Analyzes Java source files for cryptographic indicators using:
1. Import Analysis: Detect javax.crypto, java.security, and third-party library imports.
2. API Pattern Matching: Identify known Java crypto API calls (getInstance patterns).
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
from scanners.registry.crypto_api_map import JAVA_API_MAP
from scanners.registry.crypto_libraries import find_library_by_import
from scanners.registry.crypto_patterns import ALL_PATTERNS, is_comment_line
from scanners.repository.confidence import SignalType, calculate_confidence
from scanners.repository.languages.base_analyzer import LanguageAnalyzer

logger = logging.getLogger(__name__)

_SCANNER_NAME = "RepositoryScanner/JavaAnalyzer"

# Java import pattern
_JAVA_IMPORT = re.compile(r'^\s*import\s+([\w.]+)\s*;', re.MULTILINE)

# Java getInstance patterns (common crypto factory pattern)
_GET_INSTANCE = re.compile(
    r'(\w+)\s*\.\s*getInstance\s*\(\s*"([^"]+)"',
    re.MULTILINE
)

# Java KeyPairGenerator.initialize pattern (key size extraction)
_KPG_INIT = re.compile(
    r'(\w+)\s*\.\s*initialize\s*\(\s*(\d+)',
    re.MULTILINE
)

# Build API short-name lookup
_JAVA_API_SHORT: dict[str, tuple[str, str]] = {}  # short_name -> (algorithm, category)
for _e in JAVA_API_MAP:
    short = _e.api_name.split(".")[-1]
    _JAVA_API_SHORT[short] = (_e.algorithm, _e.category)


class JavaAnalyzer(LanguageAnalyzer):
    """Java cryptographic code analyzer."""

    LANGUAGE_NAME = "java"

    def analyze(self, file_path: Path, content: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        lines = content.splitlines()

        # Phase 1: Import detection
        detected_imports: set[str] = set()
        for match in _JAVA_IMPORT.finditer(content):
            module = match.group(1)
            entry = find_library_by_import(module)
            if entry:
                detected_imports.add(module)
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

        # Phase 2: getInstance pattern — most common Java crypto API pattern
        for match in _GET_INSTANCE.finditer(content):
            class_name = match.group(1)
            algo_string = match.group(2)  # e.g. "AES/GCM/NoPadding", "SHA-256", "RSA"
            line_idx = content[:match.start()].count("\n")
            line_text = lines[line_idx] if line_idx < len(lines) else ""
            if is_comment_line(line_text, "java"):
                continue

            # Resolve algorithm from the string literal
            suspected_algo, category = self._resolve_java_algo(algo_string)
            has_import = bool(detected_imports)

            conf = calculate_confidence(
                SignalType.REGEX_EXECUTABLE,
                has_import_corroboration=has_import,
                has_argument_extracted=True,
                has_api_mapping=class_name in _JAVA_API_SHORT,
            )
            adj_score = min(conf.score + 0.10, 0.90)  # Bump for extractable algo literal

            snippet = self._truncate_snippet(self._snippet(lines, line_idx))
            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.API_CALL,
                raw_symbol=match.group(0),
                suspected_algorithm=suspected_algo,
                artifact_category=category,
                raw_parameters={"transformation": algo_string},
                location=FileLocation(
                    file_path=str(file_path),
                    start_line=line_idx + 1,
                    snippet=snippet,
                ),
                confidence_score=adj_score,
                confidence_rationale=f"Java getInstance(\"{algo_string}\") | class={class_name} | score={adj_score:.2f}",
            ))

        # Phase 3: Crypto pattern pass
        for pattern in ALL_PATTERNS:
            for match in pattern.pattern.finditer(content):
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""
                in_comment = is_comment_line(line_text, "java")
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
                    confidence_rationale=f"Java regex pattern '{pattern.name}' | score={conf_score:.2f}",
                ))

        return findings

    def _resolve_java_algo(self, transformation: str) -> tuple[str | None, ArtifactCategory]:
        """
        Parse a Java transformation string like 'AES/GCM/NoPadding' or 'SHA-256'.
        Returns (canonical_algorithm, ArtifactCategory).
        """
        upper = transformation.upper()
        if "AES" in upper:
            return "AES", ArtifactCategory.SYMMETRIC_CIPHER
        if "RSA" in upper:
            return "RSA", ArtifactCategory.ASYMMETRIC_PKC
        if "SHA-256" in upper or "SHA256" in upper:
            return "SHA-256", ArtifactCategory.HASH_FUNCTION
        if "SHA-512" in upper or "SHA512" in upper:
            return "SHA-512", ArtifactCategory.HASH_FUNCTION
        if "SHA-1" in upper or "SHA1" in upper:
            return "SHA-1", ArtifactCategory.HASH_FUNCTION
        if "MD5" in upper:
            return "MD5", ArtifactCategory.HASH_FUNCTION
        if "ECDSA" in upper or "EC" in upper:
            return "ECDSA", ArtifactCategory.DIGITAL_SIGNATURE
        if "DH" in upper:
            return "DH", ArtifactCategory.KEY_EXCHANGE
        if "HMAC" in upper:
            return "HMAC", ArtifactCategory.MAC
        if "PBKDF2" in upper:
            return "PBKDF2", ArtifactCategory.KDF
        if "DES" in upper:
            return "DES" if "3DES" not in upper else "3DES", ArtifactCategory.SYMMETRIC_CIPHER
        return None, ArtifactCategory.UNKNOWN
