"""
QNetra Container Scanner — Package Manager Metadata Inspector

Inspects package manager metadata files within an extracted container filesystem
to identify installed cryptographic libraries with high confidence.

Supported package managers:
  - dpkg (Debian/Ubuntu): /var/lib/dpkg/status
  - pip (Python): site-packages directories
  - npm: node_modules directories
  - rpm: /var/lib/rpm (basic detection)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from scanners.framework.models import (
    ArtifactCategory,
    ContainerContext,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
)
from scanners.registry.crypto_libraries import find_library_by_package
from scanners.utils.file_traversal import safe_read_text

logger = logging.getLogger(__name__)

_SCANNER_NAME = "ContainerScanner/PackageInspector"

# dpkg status file location
_DPKG_STATUS_PATHS = ["var/lib/dpkg/status", "var/lib/dpkg/info"]

# Python site-packages locations in containers
_PYTHON_SITE_PACKAGES = [
    "usr/lib/python3/dist-packages",
    "usr/local/lib/python3.10/dist-packages",
    "usr/local/lib/python3.11/site-packages",
    "usr/local/lib/python3.12/site-packages",
    "usr/lib/python3.10/site-packages",
    "usr/lib/python3.11/site-packages",
]

# npm node_modules locations
_NPM_LOCATIONS = ["usr/lib/node_modules", "usr/local/lib/node_modules"]

# dpkg package block parser: extracts Package: and Version: fields
_DPKG_PACKAGE = re.compile(r'^Package:\s*(.+)$', re.MULTILINE)
_DPKG_VERSION = re.compile(r'^Version:\s*(.+)$', re.MULTILINE)


def inspect_dpkg_packages(
    fs_root: Path,
    container_ctx: ContainerContext | None,
) -> list[RawFinding]:
    """Parse /var/lib/dpkg/status for installed crypto packages."""
    findings: list[RawFinding] = []

    for status_path_str in _DPKG_STATUS_PATHS:
        status_file = fs_root / status_path_str / "status" if "info" not in status_path_str else None
        if status_file is None:
            status_file = fs_root / status_path_str

        if not status_file.exists() or not status_file.is_file():
            # Try direct path
            status_file = fs_root / "var/lib/dpkg/status"
            if not status_file.exists():
                continue

        content, err = safe_read_text(status_file, max_bytes=20 * 1024 * 1024)
        if err or not content:
            continue

        # Split into package blocks
        blocks = content.split("\n\n")
        for block in blocks:
            pkg_match = _DPKG_PACKAGE.search(block)
            if not pkg_match:
                continue

            package_name = pkg_match.group(1).strip()
            lib_entry = find_library_by_package(package_name)
            if not lib_entry:
                continue

            version_match = _DPKG_VERSION.search(block)
            version = version_match.group(1).strip() if version_match else "unknown"

            confidence = lib_entry.base_confidence + 0.05
            confidence = min(confidence, 0.90)

            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.PACKAGE_INSPECTION,
                raw_symbol=f"{package_name}=={version}",
                suspected_algorithm=lib_entry.primary_algorithms[0] if lib_entry.primary_algorithms else None,
                artifact_category=ArtifactCategory.LIBRARY,
                library_hint=lib_entry.canonical_name,
                raw_parameters={"package": package_name, "version": version, "manager": "dpkg"},
                container_context=container_ctx,
                location=FileLocation(
                    file_path="var/lib/dpkg/status",
                    snippet=f"Package: {package_name}\nVersion: {version}",
                ),
                confidence_score=round(confidence, 4),
                confidence_rationale=(
                    f"dpkg package '{package_name}' v{version} found in container — "
                    f"known crypto library | confidence={confidence:.2f}"
                ),
            ))

    return findings


def inspect_python_packages(
    fs_root: Path,
    container_ctx: ContainerContext | None,
) -> list[RawFinding]:
    """Scan Python site-packages directories for installed crypto packages."""
    findings: list[RawFinding] = []

    for site_pkg_str in _PYTHON_SITE_PACKAGES:
        site_pkg_dir = fs_root / site_pkg_str
        if not site_pkg_dir.exists():
            continue

        # Each installed package may have a .dist-info or .egg-info directory
        try:
            entries = list(site_pkg_dir.iterdir())
        except PermissionError:
            continue

        for entry in entries:
            if not entry.is_dir():
                continue

            pkg_name = entry.name.split("-")[0].lower()  # Strip version from dir name
            lib_entry = find_library_by_package(pkg_name)
            if not lib_entry:
                continue

            # Try to get version from METADATA or PKG-INFO
            version = _read_package_version(entry)
            confidence = lib_entry.base_confidence + 0.05
            confidence = min(confidence, 0.90)

            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.PACKAGE_INSPECTION,
                raw_symbol=f"{pkg_name}=={version}",
                suspected_algorithm=lib_entry.primary_algorithms[0] if lib_entry.primary_algorithms else None,
                artifact_category=ArtifactCategory.LIBRARY,
                library_hint=lib_entry.canonical_name,
                raw_parameters={"package": pkg_name, "version": version, "manager": "pip"},
                container_context=container_ctx,
                location=FileLocation(
                    file_path=str(entry.relative_to(fs_root)),
                    snippet=f"Python package: {pkg_name} v{version}",
                ),
                confidence_score=round(confidence, 4),
                confidence_rationale=(
                    f"pip package '{pkg_name}' v{version} in container Python site-packages | "
                    f"confidence={confidence:.2f}"
                ),
            ))

    return findings


def inspect_npm_packages(
    fs_root: Path,
    container_ctx: ContainerContext | None,
) -> list[RawFinding]:
    """Scan node_modules for installed crypto npm packages."""
    findings: list[RawFinding] = []

    for nm_path_str in _NPM_LOCATIONS:
        nm_dir = fs_root / nm_path_str
        if not nm_dir.exists():
            continue

        try:
            entries = list(nm_dir.iterdir())
        except PermissionError:
            continue

        for entry in entries:
            if not entry.is_dir():
                continue

            pkg_name = entry.name.lower()
            lib_entry = find_library_by_package(pkg_name)
            if not lib_entry:
                continue

            # Read package.json for version
            pkg_json = entry / "package.json"
            version = "unknown"
            if pkg_json.exists():
                content, _ = safe_read_text(pkg_json, max_bytes=64 * 1024)
                if content:
                    try:
                        pkg_data = json.loads(content)
                        version = pkg_data.get("version", "unknown")
                    except json.JSONDecodeError:
                        pass

            confidence = lib_entry.base_confidence + 0.05
            confidence = min(confidence, 0.90)

            findings.append(RawFinding(
                scanner_name=_SCANNER_NAME,
                discovery_method=DiscoveryMethod.PACKAGE_INSPECTION,
                raw_symbol=f"{pkg_name}@{version}",
                suspected_algorithm=lib_entry.primary_algorithms[0] if lib_entry.primary_algorithms else None,
                artifact_category=ArtifactCategory.LIBRARY,
                library_hint=lib_entry.canonical_name,
                raw_parameters={"package": pkg_name, "version": version, "manager": "npm"},
                container_context=container_ctx,
                location=FileLocation(
                    file_path=str((nm_dir / pkg_name / "package.json").relative_to(fs_root)),
                    snippet=f"npm package: {pkg_name}@{version}",
                ),
                confidence_score=round(confidence, 4),
                confidence_rationale=(
                    f"npm package '{pkg_name}' v{version} in container node_modules | "
                    f"confidence={confidence:.2f}"
                ),
            ))

    return findings


def _read_package_version(pkg_dir: Path) -> str:
    """Try to read the version from a Python dist-info or egg-info directory."""
    for filename in ("METADATA", "PKG-INFO"):
        meta_file = pkg_dir / filename
        if meta_file.exists():
            content, _ = safe_read_text(meta_file, max_bytes=4096)
            if content:
                for line in content.splitlines():
                    if line.startswith("Version:"):
                        return line.split(":", 1)[1].strip()
    return "unknown"
