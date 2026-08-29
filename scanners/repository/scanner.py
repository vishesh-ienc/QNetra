"""
QNetra Repository Scanner — Main Entry Point

The RepositoryScanner is the primary cryptographic discovery engine for source code
repositories. It orchestrates the full discovery pipeline:

  1. Traversal: Walk the repository tree, classify files by language.
  2. Language Dispatch: Route each file to the appropriate language analyzer.
  3. Finding Collection: Aggregate RawFinding objects from all analyzers.
  4. Error Isolation: Handle per-file failures without aborting the entire scan.

Architecture notes:
  - Extends BaseScanner (implements _execute_scan).
  - Operates in read-only mode (RULE-008).
  - Does NOT normalize findings (that is core.normalization's responsibility).
  - Produces List[RawFinding] — the Discovery Layer output contract.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from scanners.framework.base_scanner import BaseScanner
from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
    ScanResult,
    ScanTarget,
    TargetType,
)
from scanners.repository.languages.base_analyzer import LanguageAnalyzer
from scanners.repository.languages.python_analyzer import PythonAnalyzer
from scanners.repository.languages.javascript_analyzer import JavaScriptAnalyzer
from scanners.repository.languages.java_analyzer import JavaAnalyzer
from scanners.repository.languages.cpp_analyzer import CppAnalyzer
from scanners.repository.traversal import RepositoryTraversal
from scanners.utils.file_traversal import safe_read_text
from scanners.utils.language_detector import Language, is_source_language

logger = logging.getLogger(__name__)


class RepositoryScanner(BaseScanner):
    """
    Cryptographic Discovery Scanner for Source Code Repositories.

    Scans a source code directory tree using AST analysis (Python),
    import detection, and regex pattern matching across Python, JavaScript,
    TypeScript, Java, C, and C++ source files.

    Target type: REPOSITORY
    Output: List[RawFinding] appended to ScanResult.findings
    """

    SCANNER_NAME = "RepositoryScanner"
    SCANNER_VERSION = "1.0.0"

    # Language -> Analyzer mapping (extensible for future languages)
    _ANALYZERS: dict[Language, type[LanguageAnalyzer]] = {
        Language.PYTHON: PythonAnalyzer,
        Language.JAVASCRIPT: JavaScriptAnalyzer,
        Language.TYPESCRIPT: JavaScriptAnalyzer,  # TS uses same analyzer as JS
        Language.JAVA: JavaAnalyzer,
        Language.C: CppAnalyzer,
        Language.CPP: CppAnalyzer,
    }

    def __init__(self) -> None:
        super().__init__()
        # Instantiate analyzers once per scanner instance
        self._analyzer_instances: dict[Language, LanguageAnalyzer] = {}
        for lang, analyzer_class in self._ANALYZERS.items():
            # Avoid creating duplicate instances for languages sharing an analyzer class
            instance_exists = any(
                isinstance(inst, analyzer_class)
                for inst in self._analyzer_instances.values()
            )
            if not instance_exists:
                self._analyzer_instances[lang] = analyzer_class()
            else:
                # Reuse existing instance
                self._analyzer_instances[lang] = next(
                    inst for inst in self._analyzer_instances.values()
                    if isinstance(inst, analyzer_class)
                )

    def _validate_target(self, target: ScanTarget) -> Optional[str]:
        """Validate that the target is a readable directory."""
        path = Path(target.path)
        if not path.exists():
            return f"Target path does not exist: {target.path}"
        if not path.is_dir():
            return (
                f"RepositoryScanner requires a directory target. "
                f"Got file: {target.path}. "
                f"Use BinaryScanner for individual files."
            )
        return None

    def _execute_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """
        Execute the full repository scanning pipeline.

        Steps:
          1. Traverse repository and classify files.
          2. Analyze each file with the appropriate language analyzer.
          3. Collect all findings and update statistics.
        """
        root = Path(target.path)
        traversal = RepositoryTraversal(target.options)

        # Step 1: Traverse and classify
        files_by_language = traversal.collect_files(root, result.statistics)

        if not files_by_language:
            result.warnings.append(
                f"No analyzable source files found in: {target.path}. "
                "Check that the path contains source code and exclusion patterns are appropriate."
            )
            return

        # Step 2: Analyze each language group
        total_files_scanned = 0
        findings_by_method: dict[str, int] = {}
        findings_by_category: dict[str, int] = {}

        for language, file_paths in files_by_language.items():
            analyzer = self._analyzer_instances.get(language)

            if analyzer is None:
                # Language detected but no analyzer available (e.g. Go, Rust in Phase 1)
                self._logger.debug(
                    "No analyzer for language %s — skipping %d files",
                    language.value, len(file_paths)
                )
                result.statistics.files_skipped += len(file_paths)
                continue

            self._logger.info(
                "Analyzing %d %s file(s)...", len(file_paths), language.value
            )

            for file_path in file_paths:
                try:
                    content, read_error = safe_read_text(
                        file_path,
                        max_bytes=target.options.max_file_size_bytes,
                    )

                    if read_error:
                        result.warnings.append(f"Could not read {file_path}: {read_error}")
                        result.statistics.files_errored += 1
                        continue

                    if not content or not content.strip():
                        result.statistics.files_skipped += 1
                        continue

                    # Analyze this file
                    file_findings = analyzer.analyze(file_path, content)

                    # Make path relative to scan root for cleaner reporting
                    for finding in file_findings:
                        rel_path = self._make_relative(file_path, root)
                        finding.location.file_path = rel_path

                        # Accumulate statistics
                        method_key = finding.discovery_method.value
                        findings_by_method[method_key] = findings_by_method.get(method_key, 0) + 1

                        cat_key = finding.artifact_category.value
                        findings_by_category[cat_key] = findings_by_category.get(cat_key, 0) + 1

                    result.findings.extend(file_findings)
                    total_files_scanned += 1

                except Exception as e:
                    # Per-file isolation: log and continue rather than crash
                    error_msg = f"Error analyzing {file_path}: {type(e).__name__}: {e}"
                    result.errors.append(error_msg)
                    self._logger.warning(error_msg)
                    result.statistics.files_errored += 1

        # Update statistics
        result.statistics.files_scanned = total_files_scanned
        result.statistics.findings_by_method = findings_by_method
        result.statistics.findings_by_category = findings_by_category

        self._logger.info(
            "Repository scan complete | files_scanned=%d | findings=%d",
            total_files_scanned,
            len(result.findings),
        )

    def _make_relative(self, file_path: Path, root: Path) -> str:
        """Make a file path relative to the scan root for cleaner finding locations."""
        try:
            return str(file_path.relative_to(root))
        except ValueError:
            return str(file_path)
