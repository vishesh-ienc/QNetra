"""
QNetra Binary Scanner — Multi-Signal Finding Correlation

After collecting findings from string analysis and symbol inspection,
this module correlates and deduplicates findings to reduce noise:

1. Deduplication: Removes exact duplicate (same symbol, same file, same offset).
2. Algorithm corroboration: When string analysis and symbol inspection agree
   on the same algorithm at nearby locations, boost confidence of string finding.
3. Library consolidation: When multiple symbols from the same library are found,
   emit a single high-confidence library-level finding.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)

logger = logging.getLogger(__name__)


def correlate_findings(
    string_findings: list[RawFinding],
    symbol_findings: list[RawFinding],
    file_path_str: str,
) -> list[RawFinding]:
    """
    Correlate and deduplicate binary findings from multiple analysis passes.

    Strategy:
      1. Symbol findings are authoritative — always kept as-is.
      2. String findings that duplicate symbol findings are removed.
      3. String library version findings are kept if no symbol corroboration.
      4. General pattern string findings with confidence < 0.35 are dropped
         when we already have higher-quality evidence.

    Args:
        string_findings: Findings from string_analyzer.
        symbol_findings: Findings from symbol_inspector.
        file_path_str: Relative path for context.

    Returns:
        Correlated, deduplicated list of findings.
    """
    correlated: list[RawFinding] = []

    # Step 1: Collect all symbol-detected algorithms for corroboration
    symbol_algorithms: set[str] = set()
    symbol_libraries: set[str] = set()
    for sf in symbol_findings:
        if sf.suspected_algorithm:
            symbol_algorithms.add(sf.suspected_algorithm)
        if sf.library_hint:
            symbol_libraries.add(sf.library_hint)

    # Step 2: Keep all symbol findings (authoritative)
    correlated.extend(symbol_findings)

    # Step 3: Process string findings
    string_raw_symbols: set[str] = {sf.raw_symbol for sf in symbol_findings}

    for sf in string_findings:
        # Remove if the exact raw symbol already came from symbol table
        if sf.raw_symbol in string_raw_symbols:
            continue

        # Library version findings are valuable even if we have symbol evidence
        if sf.artifact_category == ArtifactCategory.LIBRARY and sf.confidence_score >= 0.80:
            correlated.append(sf)
            continue

        # Key material findings are always important
        if sf.artifact_category in (ArtifactCategory.KEY_MATERIAL, ArtifactCategory.CERTIFICATE):
            correlated.append(sf)
            continue

        # For algorithm pattern findings: boost confidence if symbols corroborate
        if sf.suspected_algorithm and sf.suspected_algorithm in symbol_algorithms:
            boosted = min(sf.confidence_score + 0.15, 0.65)
            updated_rationale = (
                sf.confidence_rationale +
                f" | Symbol table corroboration (+0.15) → {boosted:.2f}"
            )
            boosted_finding = sf.model_copy(update={
                "confidence_score": boosted,
                "confidence_rationale": updated_rationale,
            })
            correlated.append(boosted_finding)
        elif sf.confidence_score >= 0.35:
            # Keep medium+ confidence string findings without corroboration
            correlated.append(sf)
        else:
            logger.debug(
                "Dropping low-confidence string finding (%.2f): %s",
                sf.confidence_score, sf.raw_symbol[:50]
            )

    # Step 4: Emit library summary findings when multiple symbols from same lib found
    library_symbol_counts: dict[str, int] = defaultdict(int)
    for sf in symbol_findings:
        if sf.library_hint:
            library_symbol_counts[sf.library_hint] += 1

    for lib_name, count in library_symbol_counts.items():
        if count >= 3:  # Only emit summary if 3+ symbols from same library
            # Check if we already have a library-level finding from string analysis
            already_has_lib = any(
                f.artifact_category == ArtifactCategory.LIBRARY and f.library_hint == lib_name
                for f in correlated
            )
            if not already_has_lib:
                correlated.append(RawFinding(
                    scanner_name="BinaryScanner/Correlator",
                    discovery_method=DiscoveryMethod.SYMBOL_INSPECTION,
                    raw_symbol=f"{lib_name} ({count} crypto symbols found)",
                    artifact_category=ArtifactCategory.LIBRARY,
                    library_hint=lib_name,
                    location=FileLocation(
                        file_path=file_path_str,
                        snippet=f"{count} cryptographic symbols from {lib_name} detected in symbol table",
                    ),
                    confidence_score=0.95,
                    confidence_rationale=(
                        f"{count} {lib_name} symbols confirmed in binary symbol table | "
                        f"strong evidence of library linkage | confidence=0.95"
                    ),
                ))

    return correlated
