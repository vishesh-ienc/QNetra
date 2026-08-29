"""
QNetra Container Scanner — Filesystem Inspection

Inspects an extracted container filesystem for cryptographic indicators at the
filesystem layer: shared libraries (.so), header files, SSL/TLS config files,
certificate files, and known crypto library presence.

This module operates on a directory that represents an extracted container
filesystem (e.g., the result of 'docker export' or OCI layer extraction).
It does NOT pull images or interact with Docker daemon.

Target assumptions:
  - The container filesystem has been extracted to a local directory.
  - Standard Linux FHS paths are expected (/usr/lib, /usr/local/lib, etc.).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Generator

from scanners.framework.models import (
    ArtifactCategory,
    ContainerContext,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_libraries import find_library_by_shared_lib
from scanners.registry.crypto_patterns import ALL_PATTERNS, KEY_MATERIAL_PATTERNS
from scanners.utils.file_traversal import safe_read_text, traverse_directory, TraversalStats

logger = logging.getLogger(__name__)

_SCANNER_NAME = "ContainerScanner/FilesystemInspector"

# Shared library path locations in Linux container filesystems
_SHARED_LIB_PATHS = [
    "usr/lib",
    "usr/lib/x86_64-linux-gnu",
    "usr/lib/aarch64-linux-gnu",
    "usr/local/lib",
    "lib",
    "lib/x86_64-linux-gnu",
    "lib64",
    "usr/lib64",
]

# SSL/TLS configuration file locations to inspect
_TLS_CONFIG_PATHS = [
    "etc/ssl",
    "etc/openssl",
    "etc/tls",
    "etc/pki",
]

# File extensions for shared libraries
_SHARED_LIB_EXTENSIONS = {".so", ".so.1", ".so.2", ".so.3", ".dylib"}

# Config file extensions for crypto config scanning
_CONFIG_EXTENSIONS = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".pem",
                      ".crt", ".cer", ".key"}

# Known crypto-related shared library name fragments
_CRYPTO_LIB_FRAGMENTS = [
    "ssl", "crypto", "tls", "openssl", "mbedtls", "sodium", "gcrypt", "nss",
    "boringssl", "gnutls", "nettle", "wolfssl", "polarssl",
]

_CERT_PATTERN = re.compile(r'-----BEGIN\s+(CERTIFICATE|RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|PUBLIC KEY)\s*-----')
_VERSION_PATTERN = re.compile(r'(?:OpenSSL|libssl|mbedtls|libsodium)[/ ](\d+\.\d+[\.\d]*[a-z]?)', re.IGNORECASE)


def _is_shared_library(path: Path) -> bool:
    """Check if a file is a shared library based on name or extension."""
    name = path.name.lower()
    # Match .so, .so.N, .so.N.M etc.
    if ".so" in name:
        return True
    if any(name.endswith(ext) for ext in _SHARED_LIB_EXTENSIONS):
        return True
    return False


def _is_crypto_shared_lib(name: str) -> bool:
    """Check if a shared library name contains a known crypto library fragment."""
    name_lower = name.lower()
    return any(frag in name_lower for frag in _CRYPTO_LIB_FRAGMENTS)


def inspect_shared_libraries(
    fs_root: Path,
    container_ctx: ContainerContext | None,
    max_file_size: int,
) -> list[RawFinding]:
    """
    Scan standard shared library locations for known cryptographic libraries.

    Args:
        fs_root: Root of the extracted container filesystem.
        container_ctx: Container image context metadata.
        max_file_size: Maximum file size to inspect.

    Returns:
        List of RawFinding objects for discovered crypto libraries.
    """
    findings: list[RawFinding] = []

    for lib_path_str in _SHARED_LIB_PATHS:
        lib_dir = fs_root / lib_path_str
        if not lib_dir.exists() or not lib_dir.is_dir():
            continue

        try:
            entries = list(lib_dir.iterdir())
        except PermissionError:
            continue

        for entry in entries:
            if not entry.is_file():
                continue
            if not _is_shared_library(entry):
                continue
            if not _is_crypto_shared_lib(entry.name):
                continue

            # Check the library registry
            lib_entry = find_library_by_shared_lib(entry.name)
            relative_path = str(entry.relative_to(fs_root))

            if lib_entry:
                confidence = lib_entry.base_confidence + 0.10  # Higher for container detection
                confidence = min(confidence, 0.95)
                rationale = (
                    f"Known crypto shared library '{entry.name}' found at '{relative_path}' "
                    f"in container filesystem | confidence={confidence:.2f}"
                )
                for algo in lib_entry.primary_algorithms[:3]:  # Top 3 algorithms
                    findings.append(RawFinding(
                        scanner_name=_SCANNER_NAME,
                        discovery_method=DiscoveryMethod.LIBRARY_DETECTION,
                        raw_symbol=entry.name,
                        suspected_algorithm=algo,
                        artifact_category=ArtifactCategory.LIBRARY,
                        library_hint=lib_entry.canonical_name,
                        container_context=container_ctx,
                        location=FileLocation(
                            file_path=relative_path,
                            snippet=f"Shared library: {entry.name}",
                        ),
                        confidence_score=round(confidence, 4),
                        confidence_rationale=rationale,
                    ))
            else:
                # Unknown crypto library — still report it
                confidence = 0.55
                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.LIBRARY_DETECTION,
                    raw_symbol=entry.name,
                    artifact_category=ArtifactCategory.LIBRARY,
                    container_context=container_ctx,
                    location=FileLocation(
                        file_path=relative_path,
                        snippet=f"Unrecognized crypto-named shared library: {entry.name}",
                    ),
                    confidence_score=confidence,
                    confidence_rationale=(
                        f"Shared library '{entry.name}' name contains crypto keyword "
                        f"but is not in registry | confidence={confidence:.2f}"
                    ),
                ))

    return findings


def inspect_config_files(
    fs_root: Path,
    container_ctx: ContainerContext | None,
    exclude_patterns: list[str],
    max_file_size: int,
) -> list[RawFinding]:
    """
    Inspect SSL/TLS configuration files and certificate files in the container.

    Returns:
        List of RawFinding objects for cert material and crypto config.
    """
    findings: list[RawFinding] = []
    stats = TraversalStats()

    for config_path_str in _TLS_CONFIG_PATHS:
        config_dir = fs_root / config_path_str
        if not config_dir.exists():
            continue

        for file_path in traverse_directory(
            root=config_dir,
            exclude_patterns=exclude_patterns,
            max_file_size_bytes=max_file_size,
            stats=stats,
        ):
            if file_path.suffix.lower() not in _CONFIG_EXTENSIONS:
                continue

            content, err = safe_read_text(file_path, max_bytes=max_file_size)
            if err or not content:
                continue

            relative_path = str(file_path.relative_to(fs_root))

            # Check for certificate/key material
            for match in _CERT_PATTERN.finditer(content):
                line_idx = content[:match.start()].count("\n")
                findings.append(RawFinding(
                    scanner_name=_SCANNER_NAME,
                    discovery_method=DiscoveryMethod.STRING_ANALYSIS,
                    raw_symbol=match.group(0),
                    artifact_category=ArtifactCategory.CERTIFICATE,
                    container_context=container_ctx,
                    location=FileLocation(
                        file_path=relative_path,
                        start_line=line_idx + 1,
                        snippet=match.group(0)[:80],
                    ),
                    confidence_score=0.95,
                    confidence_rationale=f"PEM certificate/key block in container config | confidence=0.95",
                ))

            # General pattern scan on config files
            for pattern in KEY_MATERIAL_PATTERNS:
                for match in pattern.pattern.finditer(content):
                    line_idx = content[:match.start()].count("\n")
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
                        container_context=container_ctx,
                        location=FileLocation(
                            file_path=relative_path,
                            start_line=line_idx + 1,
                        ),
                        confidence_score=pattern.base_confidence,
                        confidence_rationale=f"Container config pattern match: '{pattern.name}' | {pattern.base_confidence:.2f}",
                    ))

    return findings
