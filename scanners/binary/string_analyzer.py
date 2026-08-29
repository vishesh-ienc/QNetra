"""
QNetra Binary Scanner — String Extraction and Pattern Analysis

Extracts printable strings from binary files and applies cryptographic pattern
matching to identify algorithm names, library version strings, cipher suite
identifiers, and PEM certificate blocks embedded in binaries.

This provides LOW-MEDIUM confidence findings (0.30-0.55) — string matches are
heuristic and may include false positives from unrelated strings.
Higher-confidence evidence comes from symbol table inspection (symbol_inspector.py).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from scanners.framework.models import (
    ArtifactCategory,
    BinaryFormat,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_patterns import ALL_PATTERNS, KEY_MATERIAL_PATTERNS
from scanners.utils.string_extractor import extract_strings

logger = logging.getLogger(__name__)

_SCANNER_NAME = "BinaryScanner/StringAnalyzer"

# Minimum string length for binary extraction (longer = fewer false positives)
_MIN_STRING_LENGTH = 8

# Version string patterns for known crypto libraries
_LIBRARY_VERSION_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r'OpenSSL (\d+\.\d+[\.\d]*[a-z]?)', re.IGNORECASE), "OpenSSL", 0.90),
    (re.compile(r'LibreSSL (\d+\.\d+[\.\d]*)', re.IGNORECASE), "LibreSSL", 0.90),
    (re.compile(r'BoringSSL', re.IGNORECASE), "BoringSSL", 0.88),
    (re.compile(r'mbedTLS[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "mbedTLS", 0.88),
    (re.compile(r'libsodium[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "libsodium", 0.88),
    (re.compile(r'GnuTLS[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "GnuTLS", 0.85),
    (re.compile(r'NSS[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "NSS", 0.82),
    (re.compile(r'wolfSSL[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "wolfSSL", 0.85),
    (re.compile(r'Nettle[/ ](\d+\.\d+[\.\d]*)', re.IGNORECASE), "Nettle", 0.82),
    (re.compile(r'BouncyCastle', re.IGNORECASE), "BouncyCastle", 0.85),
]

# TLS cipher suite pattern — highly specific, high signal in binaries
_CIPHER_SUITE_PATTERN = re.compile(
    r'TLS_(?:RSA|DHE|ECDHE|PSK|ECDH)_(?:WITH|ANON)_[A-Z0-9_]+',
    re.IGNORECASE
)

# PEM header pattern in binary strings
_PEM_HEADER_IN_BINARY = re.compile(
    r'-----BEGIN\s+((?:RSA\s+)?PRIVATE\s+KEY|EC\s+PRIVATE\s+KEY|PUBLIC\s+KEY|CERTIFICATE)-----'
)


def analyze_strings(
    file_path: Path,
    binary_format: BinaryFormat,
    max_file_size: int = 50 * 1024 * 1024,
) -> list[RawFinding]:
    """
    Extract strings from a binary and apply cryptographic pattern matching.

    Args:
        file_path: Binary file path.
        binary_format: Detected binary format (for context in findings).
        max_file_size: Max bytes to read.

    Returns:
        List of RawFinding objects.
    """
    findings: list[RawFinding] = []
    relative_path = str(file_path)

    for extracted_string, byte_offset in extract_strings(
        file_path,
        min_length=_MIN_STRING_LENGTH,
        max_bytes=max_file_size,
    ):
        # Check library version strings (HIGH value — specific and reliable)
        for version_pattern, lib_name, confidence in _LIBRARY_VERSION_PATTERNS:
            match = version_pattern.search(extracted_string)
            if match:
                version = match.group(1) if match.lastindex else ""
                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.STRING_ANALYSIS,
                    raw_symbol=extracted_string[:100],
                    suspected_algorithm=None,  # Library, not algorithm
                    artifact_category=ArtifactCategory.LIBRARY,
                    library_hint=lib_name,
                    binary_format=binary_format,
                    symbol_name=None,
                    location=FileLocation(
                        file_path=relative_path,
                        byte_offset=byte_offset,
                        snippet=extracted_string[:120],
                    ),
                    confidence_score=confidence,
                    confidence_rationale=(
                        f"Library version string '{lib_name} {version}' found in binary strings "
                        f"at offset {byte_offset} | confidence={confidence:.2f}"
                    ),
                ))

        # Check TLS cipher suite strings
        for cs_match in _CIPHER_SUITE_PATTERN.finditer(extracted_string):
            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.STRING_ANALYSIS,
                raw_symbol=cs_match.group(0),
                suspected_algorithm="TLS",
                artifact_category=ArtifactCategory.PROTOCOL,
                binary_format=binary_format,
                location=FileLocation(
                    file_path=relative_path,
                    byte_offset=byte_offset,
                    snippet=extracted_string[:120],
                ),
                confidence_score=0.72,
                confidence_rationale=(
                    f"TLS cipher suite string '{cs_match.group(0)}' in binary | "
                    f"offset={byte_offset} | confidence=0.72"
                ),
            ))

        # Check PEM headers (key material embedded in binary)
        pem_match = _PEM_HEADER_IN_BINARY.search(extracted_string)
        if pem_match:
            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.STRING_ANALYSIS,
                raw_symbol=pem_match.group(0),
                artifact_category=ArtifactCategory.KEY_MATERIAL,
                binary_format=binary_format,
                location=FileLocation(
                    file_path=relative_path,
                    byte_offset=byte_offset,
                    snippet=pem_match.group(0),
                ),
                confidence_score=0.90,
                confidence_rationale=(
                    f"PEM header '{pem_match.group(1)}' found embedded in binary | "
                    f"HIGH confidence key material indicator | confidence=0.90"
                ),
            ))
            continue  # PEM found — skip general patterns for this string

        # Apply general crypto algorithm patterns (LOWER confidence for binary strings)
        for pattern in ALL_PATTERNS:
            match = pattern.pattern.search(extracted_string)
            if match:
                # De-rate confidence for binary string matches
                string_confidence = min(pattern.base_confidence * 0.55, 0.50)
                if string_confidence < 0.28:
                    continue  # Too noisy

                try:
                    cat = ArtifactCategory(pattern.category)
                except ValueError:
                    cat = ArtifactCategory.UNKNOWN

                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.STRING_ANALYSIS,
                    raw_symbol=match.group(0),
                    suspected_algorithm=pattern.algorithm,
                    artifact_category=cat,
                    binary_format=binary_format,
                    location=FileLocation(
                        file_path=relative_path,
                        byte_offset=byte_offset,
                        snippet=extracted_string[:120],
                    ),
                    confidence_score=string_confidence,
                    confidence_rationale=(
                        f"Pattern '{pattern.name}' matched in binary string | "
                        f"string='{extracted_string[:40]}' | confidence={string_confidence:.2f} "
                        f"(binary string de-rating applied)"
                    ),
                ))
                break  # One match per string to avoid duplicates

    return findings
