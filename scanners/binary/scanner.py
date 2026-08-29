"""
QNetra Binary Scanner — Main Entry Point

Inspects compiled binary files (ELF, PE) for cryptographic indicators
using a multi-stage pipeline:

  1. Format Detection: Identify binary format (ELF/PE/Mach-O/Unknown) from magic bytes.
  2. String Analysis: Extract printable strings and match crypto patterns.
  3. Symbol Inspection: Parse symbol tables for crypto library imports (requires lief).
  4. Correlation: Deduplicate, corroborate, and consolidate findings.

RULE-008: The binary scanner is PURELY PASSIVE — no code execution,
no ptrace, no memory mapping. lief parses binary structures statically.

Target type: BINARY
Output: List[RawFinding] appended to ScanResult.findings
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from scanners.framework.base_scanner import BaseScanner
from scanners.framework.models import (
    BinaryFormat,
    ScanResult,
    ScanTarget,
    TargetType,
)
from scanners.binary.format_detector import detect_format, get_format_description, is_parseable_with_lief
from scanners.binary.string_analyzer import analyze_strings
from scanners.binary.symbol_inspector import inspect_symbols, is_lief_available
from scanners.binary.correlation import correlate_findings

logger = logging.getLogger(__name__)


class BinaryScanner(BaseScanner):
    """
    Cryptographic Discovery Scanner for Compiled Binary Files.

    Analyzes ELF and PE binaries using static symbol table inspection (via lief)
    and string extraction with cryptographic pattern matching.

    Target type: BINARY
    Output: List[RawFinding] appended to ScanResult.findings
    """

    SCANNER_NAME = "BinaryScanner"
    SCANNER_VERSION = "1.0.0"

    def _validate_target(self, target: ScanTarget) -> Optional[str]:
        path = Path(target.path)
        if not path.exists():
            return f"Binary file does not exist: {target.path}"
        if path.is_dir():
            return (
                f"BinaryScanner requires a single binary file, not a directory: {target.path}. "
                f"Use RepositoryScanner or ContainerScanner for directories."
            )
        if not path.is_file():
            return f"Target is not a regular file: {target.path}"
        return None

    def _execute_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """Execute the binary scanning pipeline."""
        binary_path = Path(target.path)

        # Stage 1: Detect binary format
        binary_format = detect_format(binary_path)
        format_desc = get_format_description(binary_format)
        self._logger.info("Binary format detected: %s | file=%s", format_desc, binary_path.name)

        if binary_format == BinaryFormat.ARCHIVE:
            result.warnings.append(
                f"Static library archive detected: {binary_path.name}. "
                "Archive member inspection not implemented in Phase 1. "
                "String analysis only."
            )
        elif binary_format == BinaryFormat.MACHO:
            result.warnings.append(
                f"Mach-O binary detected: {binary_path.name}. "
                "Full Mach-O symbol inspection not implemented in Phase 1. "
                "String analysis only."
            )

        relative_path = binary_path.name  # Use filename as relative path for binary findings

        # Stage 2: String analysis
        string_findings: list = []
        try:
            string_findings = analyze_strings(
                file_path=binary_path,
                binary_format=binary_format,
                max_file_size=target.options.max_file_size_bytes,
            )
            # Update path to relative
            for f in string_findings:
                f.location.file_path = relative_path
            self._logger.info("String analysis: %d finding(s)", len(string_findings))
        except Exception as e:
            result.errors.append(f"String analysis failed: {type(e).__name__}: {e}")
            self._logger.exception("String analysis error for %s", binary_path)

        # Stage 3: Symbol table inspection (ELF/PE only, requires lief)
        symbol_findings: list = []
        if is_parseable_with_lief(binary_format):
            if is_lief_available():
                try:
                    symbol_findings = inspect_symbols(binary_path, binary_format)
                    for f in symbol_findings:
                        f.location.file_path = relative_path
                    self._logger.info("Symbol inspection: %d finding(s)", len(symbol_findings))
                except Exception as e:
                    result.errors.append(f"Symbol inspection failed: {type(e).__name__}: {e}")
                    self._logger.exception("Symbol inspection error for %s", binary_path)
            else:
                result.warnings.append(
                    "Symbol table inspection skipped: lief not installed. "
                    "Install with: pip install lief>=0.14.0"
                )
        else:
            self._logger.info(
                "Symbol inspection not available for format: %s", binary_format.value
            )

        # Stage 4: Correlation
        if string_findings or symbol_findings:
            try:
                correlated = correlate_findings(string_findings, symbol_findings, relative_path)
                result.findings.extend(correlated)
                self._logger.info(
                    "Correlation complete | before=%d | after=%d | removed=%d",
                    len(string_findings) + len(symbol_findings),
                    len(correlated),
                    (len(string_findings) + len(symbol_findings)) - len(correlated),
                )
            except Exception as e:
                # Correlation failure: fall back to raw findings
                result.errors.append(f"Correlation failed, using raw findings: {e}")
                result.findings.extend(string_findings)
                result.findings.extend(symbol_findings)
        else:
            result.warnings.append(
                f"No cryptographic indicators found in {binary_path.name} "
                f"({format_desc}). The binary may not use cryptographic libraries, "
                "or may use obfuscated/dynamic loading patterns."
            )

        result.statistics.files_scanned = 1
        self._logger.info(
            "Binary scan complete | format=%s | findings=%d",
            binary_format.value,
            len(result.findings),
        )
