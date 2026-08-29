"""
QNetra Repository Scanner — JavaScript / TypeScript Language Analyzer

Analyzes JavaScript and TypeScript source files for cryptographic indicators
using two techniques:

1. Import Analysis: Regex-based detection of require() and ES6 import statements
   for known cryptographic libraries. Provides library-level findings.

2. Pattern Matching (Alg-02): Apply structured regex patterns to identify:
   - Cryptographic API call patterns (crypto.createCipheriv, jwt.sign, etc.)
   - Algorithm identifiers in string literals
   - PEM blocks and key material
   - TLS cipher suite strings

Note: Full AST analysis for JavaScript is not implemented in Phase 1
because JavaScript/TypeScript parsing requires external libraries (acorn, esprima)
which conflict with RULE-007 (no heavy external dependencies). Regex-based
import detection + API pattern matching provides MEDIUM confidence findings.
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
from scanners.registry.crypto_api_map import JAVASCRIPT_API_MAP
from scanners.registry.crypto_libraries import find_library_by_import
from scanners.registry.crypto_patterns import ALL_PATTERNS, is_comment_line
from scanners.repository.confidence import SignalType, calculate_confidence
from scanners.repository.languages.base_analyzer import LanguageAnalyzer

logger = logging.getLogger(__name__)

_SCANNER_NAME = "RepositoryScanner/JavaScriptAnalyzer"

# CommonJS require pattern: require('crypto'), require("jsonwebtoken")
_REQUIRE_PATTERN = re.compile(
    r"""(?:const|let|var)\s+(?P<alias>\w+|{[^}]+})\s*=\s*require\s*\(\s*['"](?P<module>[^'"]+)['"]\s*\)""",
    re.MULTILINE
)

# ES6 import pattern: import crypto from 'crypto'; import { createHash } from 'node:crypto'
_IMPORT_PATTERN = re.compile(
    r"""import\s+(?:(?P<default>\w+)|(?:\*\s+as\s+(?P<namespace>\w+))|(?:\{[^}]+\}))\s+from\s+['"](?P<module>[^'"]+)['"]""",
    re.MULTILINE
)

# ES6 bare import: import 'crypto'
_BARE_IMPORT_PATTERN = re.compile(
    r"""import\s+['"](?P<module>[^'"]+)['"]""",
    re.MULTILINE
)

# Pre-built API call patterns for JavaScript known APIs
_JS_API_PATTERNS: list[tuple[re.Pattern, str, str, str]] = []  # (pattern, api_name, algorithm, category)
for _entry in JAVASCRIPT_API_MAP:
    # Build a pattern that matches the short name of the call
    short_name = _entry.api_name.split(".")[-1]
    _pat = re.compile(r'\b' + re.escape(short_name) + r'\s*\(', re.IGNORECASE)
    _JS_API_PATTERNS.append((_pat, _entry.api_name, _entry.algorithm, _entry.category))


class JavaScriptAnalyzer(LanguageAnalyzer):
    """
    JavaScript/TypeScript cryptographic code analyzer.

    Uses regex-based import detection and API pattern matching.
    Provides MEDIUM confidence findings (no full AST in Phase 1).
    """

    LANGUAGE_NAME = "javascript"

    def analyze(self, file_path: Path, content: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        lines = content.splitlines()

        # Track detected imports for corroboration
        detected_imports: set[str] = set()

        # Phase 1: Import detection
        import_findings, detected_imports = self._detect_imports(file_path, content, lines)
        findings.extend(import_findings)

        # Phase 2: API call pattern detection
        call_findings = self._detect_api_calls(file_path, content, lines, detected_imports)
        findings.extend(call_findings)

        # Phase 3: General crypto pattern matching
        pattern_findings = self._apply_patterns(file_path, content, lines)
        findings.extend(pattern_findings)

        return findings

    def _detect_imports(
        self, file_path: Path, content: str, lines: list[str]
    ) -> tuple[list[RawFinding], set[str]]:
        findings = []
        detected_modules: set[str] = set()

        for match in list(_REQUIRE_PATTERN.finditer(content)) + list(_IMPORT_PATTERN.finditer(content)) + list(_BARE_IMPORT_PATTERN.finditer(content)):
            module = match.group("module")
            if not module:
                continue

            # Strip node: prefix (node:crypto -> crypto)
            normalized = module.replace("node:", "")
            entry = find_library_by_import(normalized) or find_library_by_import(module)
            if not entry:
                continue

            detected_modules.add(normalized)
            line_idx = content[:match.start()].count("\n")
            snippet = self._truncate_snippet(self._snippet(lines, line_idx))

            conf = calculate_confidence(SignalType.KNOWN_IMPORT, base_override=entry.base_confidence)
            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.IMPORT_ANALYSIS,
                raw_symbol=match.group(0)[:120],
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

        return findings, detected_modules

    def _detect_api_calls(
        self, file_path: Path, content: str, lines: list[str], detected_imports: set[str]
    ) -> list[RawFinding]:
        findings = []

        for api_pat, api_name, algorithm, category_str in _JS_API_PATTERNS:
            for match in api_pat.finditer(content):
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""

                if is_comment_line(line_text, "javascript"):
                    continue  # Skip comments for API call detection

                has_import = any(mod in content for mod in ("crypto", "jsonwebtoken", "crypto-js"))
                conf = calculate_confidence(
                    SignalType.REGEX_EXECUTABLE,
                    has_import_corroboration=has_import,
                    has_api_mapping=True,
                )

                # Bump base since this is a known API match, not just an algorithm string
                adj_score = min(conf.score + 0.08, 0.82)

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
                    location=FileLocation(
                        file_path=str(file_path),
                        start_line=line_idx + 1,
                        snippet=snippet,
                    ),
                    confidence_score=adj_score,
                    confidence_rationale=f"Known JS crypto API call: {api_name} | score={adj_score:.2f}",
                ))

        return findings

    def _apply_patterns(self, file_path: Path, content: str, lines: list[str]) -> list[RawFinding]:
        findings = []
        for pattern in ALL_PATTERNS:
            for match in pattern.pattern.finditer(content):
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""
                in_comment = is_comment_line(line_text, "javascript")
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
                    confidence_rationale=f"JS regex pattern '{pattern.name}' | {'comment' if in_comment else 'code'} | {conf_score:.2f}",
                ))
        return findings
