"""
QNetra Repository Scanner — Python Language Analyzer

Analyzes Python source files for cryptographic indicators using three techniques:

1. AST Analysis (Alg-01): Parse the Python AST using the stdlib `ast` module to:
   - Detect crypto library imports (import/from-import statements)
   - Identify cryptographic function calls and class instantiations
   - Extract literal arguments (key sizes, modes, curves)

2. Pattern Matching (Alg-02): Apply regex patterns to source lines for:
   - Hardcoded key material (PEM blocks)
   - Cipher suite identifiers in configuration strings
   - Crypto algorithm strings in assignment contexts

3. Import Corroboration: Track detected imports to boost confidence for
   API calls that confirm use of imported crypto libraries.

Discovery confidence follows the model in scanners/repository/confidence.py.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Any, Optional

from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_api_map import find_api_entry, PYTHON_API_MAP
from scanners.registry.crypto_libraries import find_library_by_import
from scanners.registry.crypto_patterns import ALL_PATTERNS, is_comment_line
from scanners.repository.confidence import SignalType, calculate_confidence
from scanners.repository.languages.base_analyzer import LanguageAnalyzer

logger = logging.getLogger(__name__)

_SCANNER_NAME = "RepositoryScanner/PythonAnalyzer"

# Pre-build set of all known Python API names (short names) for fast filtering
_KNOWN_API_SHORT_NAMES: set[str] = set()
for _entry in PYTHON_API_MAP:
    _KNOWN_API_SHORT_NAMES.add(_entry.api_name.split(".")[-1].lower())
    _KNOWN_API_SHORT_NAMES.add(_entry.api_name.lower())


class _ImportRecord:
    """Tracks a detected crypto library import and its aliases."""
    def __init__(self, module: str, alias: Optional[str], line: int):
        self.module = module
        self.alias = alias or module.split(".")[-1]
        self.line = line


class PythonAnalyzer(LanguageAnalyzer):
    """
    Python-specific cryptographic code analyzer.

    Uses Python's stdlib ast module for robust, syntax-aware analysis.
    Falls back to regex scanning for non-parseable files.
    """

    LANGUAGE_NAME = "python"

    def analyze(self, file_path: Path, content: str) -> list[RawFinding]:
        """
        Analyze a Python source file for cryptographic indicators.

        Analysis pipeline:
          1. Attempt AST parse → if successful: AST analysis
          2. Regardless: Regex pattern pass (for PEM blocks, cipher strings)
          3. Deduplicate findings from same line
        """
        findings: list[RawFinding] = []
        detected_imports: dict[str, _ImportRecord] = {}  # alias -> ImportRecord

        # --- Phase 1: AST Analysis ---
        try:
            tree = ast.parse(content, filename=str(file_path))
            import_findings, detected_imports = self._extract_ast_imports(
                tree, file_path, content
            )
            findings.extend(import_findings)

            call_findings = self._extract_ast_calls(
                tree, file_path, content, detected_imports
            )
            findings.extend(call_findings)

        except SyntaxError as e:
            logger.debug("AST parse failed for %s (SyntaxError: %s) — falling back to regex", file_path, e)
        except Exception as e:
            logger.debug("AST parse failed for %s (%s) — falling back to regex", file_path, type(e).__name__)

        # --- Phase 2: Regex Pattern Pass ---
        regex_findings = self._apply_patterns(file_path, content)
        findings.extend(regex_findings)

        return findings

    def _extract_ast_imports(
        self,
        tree: ast.AST,
        file_path: Path,
        content: str,
    ) -> tuple[list[RawFinding], dict[str, _ImportRecord]]:
        """
        Walk AST for import statements. Identify crypto library imports.
        Emit a LIBRARY finding for each recognized crypto import.
        """
        findings: list[RawFinding] = []
        detected_imports: dict[str, _ImportRecord] = {}
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    asname = alias.asname
                    entry = find_library_by_import(module)
                    if entry:
                        rec = _ImportRecord(module, asname, node.lineno)
                        # Store by both module name and alias for call lookup
                        detected_imports[rec.alias] = rec
                        detected_imports[module] = rec
                        if module.split(".")[0] != module:
                            detected_imports[module.split(".")[0]] = rec

                        conf = calculate_confidence(
                            SignalType.KNOWN_IMPORT,
                            base_override=entry.base_confidence,
                        )
                        snippet = self._truncate_snippet(
                            self._snippet(lines, node.lineno - 1)
                        )
                        findings.append(RawFinding(
                            scanner_name=_SCANNER_NAME,
                            discovery_method=DiscoveryMethod.IMPORT_ANALYSIS,
                            raw_symbol=f"import {module}" + (f" as {asname}" if asname else ""),
                            suspected_algorithm=None,  # Import alone doesn't tell us the algo
                            artifact_category=ArtifactCategory.LIBRARY,
                            library_hint=entry.canonical_name,
                            location=FileLocation(
                                file_path=str(file_path),
                                start_line=node.lineno,
                                snippet=snippet,
                            ),
                            confidence_score=conf.score,
                            confidence_rationale=conf.rationale,
                        ))

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                entry = find_library_by_import(module)
                if entry:
                    for alias in node.names:
                        asname = alias.asname or alias.name
                        rec = _ImportRecord(module, asname, node.lineno)
                        detected_imports[asname] = rec
                        detected_imports[alias.name] = rec

                    conf = calculate_confidence(
                        SignalType.KNOWN_IMPORT,
                        base_override=entry.base_confidence,
                    )
                    snippet = self._truncate_snippet(
                        self._snippet(lines, node.lineno - 1)
                    )
                    imported_names = ", ".join(a.name for a in node.names)
                    findings.append(RawFinding(
                        scanner_name=_SCANNER_NAME,
                        discovery_method=DiscoveryMethod.IMPORT_ANALYSIS,
                        raw_symbol=f"from {module} import {imported_names}",
                        artifact_category=ArtifactCategory.LIBRARY,
                        library_hint=entry.canonical_name,
                        location=FileLocation(
                            file_path=str(file_path),
                            start_line=node.lineno,
                            snippet=snippet,
                        ),
                        confidence_score=conf.score,
                        confidence_rationale=conf.rationale,
                    ))

        return findings, detected_imports

    def _extract_ast_calls(
        self,
        tree: ast.AST,
        file_path: Path,
        content: str,
        detected_imports: dict[str, _ImportRecord],
    ) -> list[RawFinding]:
        """
        Walk AST for function calls matching known crypto APIs.
        Emits an API_CALL finding for each recognized cryptographic call.
        """
        findings: list[RawFinding] = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name, full_name = self._extract_call_name(node)
            if not call_name:
                continue

            # Quick filter: skip calls whose short name is not in any known API
            if call_name.lower() not in _KNOWN_API_SHORT_NAMES and \
               full_name.lower() not in _KNOWN_API_SHORT_NAMES:
                continue

            # Try to find in API registry
            api_entry = find_api_entry("python", full_name) or find_api_entry("python", call_name)
            if not api_entry:
                continue

            # Check if we also detected the corresponding import
            has_import = self._has_corresponding_import(api_entry.library, detected_imports)

            # Extract arguments
            raw_params, key_size_hint, mode_hint, curve_hint = self._extract_args(
                node, api_entry
            )

            conf = calculate_confidence(
                SignalType.AST_API_CALL,
                base_override=api_entry.base_confidence,
                has_import_corroboration=has_import,
                has_argument_extracted=bool(raw_params),
                has_api_mapping=True,
            )

            snippet = self._truncate_snippet(
                self._snippet(lines, node.lineno - 1)
            )

            try:
                category = ArtifactCategory(api_entry.category)
            except ValueError:
                category = ArtifactCategory.UNKNOWN

            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.AST,
                raw_symbol=full_name or call_name,
                suspected_algorithm=api_entry.algorithm,
                artifact_category=category,
                library_hint=api_entry.library,
                key_size_hint=key_size_hint,
                mode_hint=mode_hint,
                curve_hint=curve_hint,
                raw_parameters=raw_params,
                location=FileLocation(
                    file_path=str(file_path),
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    snippet=snippet,
                ),
                confidence_score=conf.score,
                confidence_rationale=conf.rationale,
            ))

        return findings

    def _extract_call_name(self, node: ast.Call) -> tuple[str, str]:
        """Extract (short_name, full_dotted_name) from a Call node."""
        func = node.func
        if isinstance(func, ast.Attribute):
            short = func.attr
            # Try to reconstruct dotted name up to 3 levels deep
            if isinstance(func.value, ast.Attribute):
                mid = func.value.attr
                if isinstance(func.value.value, ast.Name):
                    full = f"{func.value.value.id}.{mid}.{short}"
                else:
                    full = f"{mid}.{short}"
            elif isinstance(func.value, ast.Name):
                full = f"{func.value.id}.{short}"
            else:
                full = short
            return short, full
        elif isinstance(func, ast.Name):
            return func.id, func.id
        return "", ""

    def _has_corresponding_import(
        self, library_name: str, detected_imports: dict[str, _ImportRecord]
    ) -> bool:
        """Check if a library name corresponds to a detected import."""
        lib_lower = library_name.lower()
        for alias, rec in detected_imports.items():
            if lib_lower in rec.module.lower():
                return True
        return False

    def _extract_args(
        self, node: ast.Call, api_entry: Any
    ) -> tuple[dict | None, int | None, str | None, str | None]:
        """
        Attempt to extract literal argument values from a function call.

        Returns: (raw_params_dict, key_size_hint, mode_hint, curve_hint)
        """
        raw_params: dict = {}
        key_size: int | None = None
        mode: str | None = None
        curve: str | None = None

        rules = api_entry.arg_rules

        # Try to extract arguments by position or keyword name
        def get_arg(index_or_name: int | str | None) -> Any:
            if index_or_name is None:
                return None
            if isinstance(index_or_name, int):
                if index_or_name < len(node.args):
                    return self._eval_literal(node.args[index_or_name])
            elif isinstance(index_or_name, str):
                for kw in node.keywords:
                    if kw.arg == index_or_name:
                        return self._eval_literal(kw.value)
            return None

        if rules.key_size_arg is not None:
            val = get_arg(rules.key_size_arg)
            if isinstance(val, int):
                key_size = val
                raw_params["key_size"] = val

        if rules.mode_arg is not None:
            val = get_arg(rules.mode_arg)
            if val is not None:
                mode = str(val)
                raw_params["mode"] = mode

        if rules.curve_arg is not None:
            val = get_arg(rules.curve_arg)
            if val is not None:
                curve = str(val)
                raw_params["curve"] = curve

        if rules.algorithm_arg is not None:
            val = get_arg(rules.algorithm_arg)
            if val is not None:
                raw_params["algorithm_arg"] = str(val)

        return raw_params or None, key_size, mode, curve

    def _eval_literal(self, node: ast.expr) -> Any:
        """Safely evaluate a literal AST node to a Python value."""
        try:
            return ast.literal_eval(node)
        except (ValueError, TypeError):
            # Not a literal — may be a variable or complex expression
            if isinstance(node, ast.Attribute):
                return node.attr   # Return attribute name (e.g. "MODE_GCM")
            if isinstance(node, ast.Name):
                return node.id
            return None

    def _apply_patterns(self, file_path: Path, content: str) -> list[RawFinding]:
        """
        Apply regex patterns to source text for non-AST-detectable indicators
        (PEM blocks, cipher strings, algorithm identifiers in strings/configs).
        """
        findings: list[RawFinding] = []
        lines = content.splitlines()

        for pattern in ALL_PATTERNS:
            for match in pattern.pattern.finditer(content):
                # Determine the line number of this match
                line_idx = content[:match.start()].count("\n")
                line_text = lines[line_idx] if line_idx < len(lines) else ""

                in_comment = is_comment_line(line_text, "python")
                conf_score = (
                    pattern.comment_confidence if in_comment else pattern.base_confidence
                )

                # Skip very low confidence comment matches to reduce noise
                if in_comment and conf_score < 0.20:
                    continue

                snippet = self._truncate_snippet(
                    self._snippet(lines, line_idx)
                )

                try:
                    category = ArtifactCategory(pattern.category)
                except ValueError:
                    category = ArtifactCategory.UNKNOWN

                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=(
                        DiscoveryMethod.REGEX
                    ),
                    raw_symbol=match.group(0),
                    suspected_algorithm=pattern.algorithm,
                    artifact_category=category,
                    location=FileLocation(
                        file_path=str(file_path),
                        start_line=line_idx + 1,
                        snippet=snippet,
                    ),
                    confidence_score=conf_score,
                    confidence_rationale=(
                        f"{'Comment' if in_comment else 'Executable code'} regex match: "
                        f"pattern '{pattern.name}' | score={conf_score:.2f}"
                    ),
                ))

        return findings
