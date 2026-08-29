"""
QNetra Binary Scanner — Symbol Table Inspector

Extracts and analyzes import/export symbol tables from ELF and PE binaries
using the `lief` library. Symbol table inspection provides HIGH confidence
findings because confirmed function imports directly demonstrate the binary's
cryptographic capability.

Design: Requires `lief>=0.14` (see requirements.txt and DEC-007).
        Gracefully degrades to string analysis if lief is unavailable.

RULE-008 compliance: lief performs static binary parsing only.
No execution, no memory loading, no ptrace. Read-only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scanners.framework.models import (
    ArtifactCategory,
    BinaryFormat,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_symbols import find_symbol, find_symbol_by_prefix

logger = logging.getLogger(__name__)

_SCANNER_NAME = "BinaryScanner/SymbolInspector"

# Try to import lief — graceful degradation if not installed
try:
    import lief
    _LIEF_AVAILABLE = True
    logger.debug("lief library available for symbol table inspection")
except ImportError:
    lief = None  # type: ignore
    _LIEF_AVAILABLE = False
    logger.warning(
        "lief not available — symbol table inspection disabled. "
        "Install via: pip install lief>=0.14.0"
    )


def inspect_symbols(
    file_path: Path,
    binary_format: BinaryFormat,
) -> list[RawFinding]:
    """
    Extract and analyze import/export symbols from ELF or PE binary.

    Args:
        file_path: Path to the binary file.
        binary_format: Detected binary format (ELF or PE).

    Returns:
        List of RawFinding objects for recognized crypto symbols.
    """
    if not _LIEF_AVAILABLE:
        logger.warning(
            "Symbol inspection skipped for %s — lief not available", file_path
        )
        return []

    if binary_format == BinaryFormat.ELF:
        return _inspect_elf(file_path)
    elif binary_format == BinaryFormat.PE:
        return _inspect_pe(file_path)
    else:
        logger.debug("Symbol inspection not supported for format %s", binary_format.value)
        return []


def _inspect_elf(file_path: Path) -> list[RawFinding]:
    """Inspect ELF binary import/export symbols."""
    findings: list[RawFinding] = []

    try:
        binary = lief.parse(str(file_path))  # type: ignore
    except Exception as e:
        logger.warning("lief failed to parse ELF %s: %s", file_path, e)
        return []

    if binary is None:
        return []

    # Collect all dynamic symbols (imported functions)
    symbols_seen: set[str] = set()

    try:
        dynamic_symbols = getattr(binary, "dynamic_symbols", []) or []
        imported_functions = getattr(binary, "imported_functions", []) or []
        all_symbols = list(dynamic_symbols) + list(imported_functions)
    except Exception as e:
        logger.debug("Error accessing ELF symbols: %s", e)
        return []

    for sym in all_symbols:
        try:
            sym_name = _get_symbol_name(sym)
            if not sym_name or sym_name in symbols_seen:
                continue
            symbols_seen.add(sym_name)

            finding = _symbol_to_finding(sym_name, file_path, binary_format=BinaryFormat.ELF)
            if finding:
                findings.append(finding)
        except Exception:
            continue

    return findings


def _inspect_pe(file_path: Path) -> list[RawFinding]:
    """Inspect PE binary import table symbols."""
    findings: list[RawFinding] = []

    try:
        binary = lief.parse(str(file_path))  # type: ignore
    except Exception as e:
        logger.warning("lief failed to parse PE %s: %s", file_path, e)
        return []

    if binary is None:
        return []

    symbols_seen: set[str] = set()

    try:
        # PE imports are structured as DLL -> list of functions
        imports = getattr(binary, "imports", []) or []
        for dll_import in imports:
            try:
                dll_name = getattr(dll_import, "name", "") or ""
                entries = getattr(dll_import, "entries", []) or []
                for entry in entries:
                    sym_name = _get_symbol_name(entry)
                    if not sym_name or sym_name in symbols_seen:
                        continue
                    symbols_seen.add(sym_name)

                    finding = _symbol_to_finding(
                        sym_name, file_path,
                        binary_format=BinaryFormat.PE,
                        dll_hint=dll_name,
                    )
                    if finding:
                        findings.append(finding)
            except Exception:
                continue
    except Exception as e:
        logger.debug("Error accessing PE imports: %s", e)

    return findings


def _get_symbol_name(sym: Any) -> str:
    """Safely extract the name from a lief symbol object."""
    try:
        name = getattr(sym, "name", None)
        if name and isinstance(name, str) and len(name) > 0:
            return name
    except Exception:
        pass
    return ""


def _symbol_to_finding(
    sym_name: str,
    file_path: Path,
    binary_format: BinaryFormat,
    dll_hint: str = "",
) -> RawFinding | None:
    """
    Convert a binary symbol name to a RawFinding if it's recognized as cryptographic.

    Uses exact lookup first, then prefix matching for symbol families.
    """
    entry = find_symbol(sym_name) or find_symbol_by_prefix(sym_name)
    if not entry:
        return None

    try:
        cat = ArtifactCategory(entry.category)
    except ValueError:
        cat = ArtifactCategory.UNKNOWN

    return RawFinding(
        scanner_name=_SCANNER_NAME,
        discovery_method=DiscoveryMethod.SYMBOL_INSPECTION,
        raw_symbol=sym_name,
        suspected_algorithm=entry.algorithm,
        artifact_category=cat,
        library_hint=entry.library,
        binary_format=binary_format,
        symbol_name=sym_name,
        location=FileLocation(
            file_path=str(file_path),
            snippet=(
                f"Symbol: {sym_name} | Library: {entry.library}"
                + (f" | DLL: {dll_hint}" if dll_hint else "")
            ),
        ),
        confidence_score=entry.confidence,
        confidence_rationale=(
            f"Binary symbol '{sym_name}' matched in crypto symbol registry | "
            f"library={entry.library} | algo={entry.algorithm} | "
            f"confidence={entry.confidence:.2f}"
        ),
    )


def is_lief_available() -> bool:
    """Return True if the lief library is available for symbol inspection."""
    return _LIEF_AVAILABLE
