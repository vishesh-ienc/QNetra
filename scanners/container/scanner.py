"""
QNetra Container Scanner — Main Entry Point

Inspects an extracted container filesystem for cryptographic indicators
using a multi-stage pipeline:

  1. Shared Library Detection: Scan /usr/lib and similar paths for known
     cryptographic shared libraries (libssl, libcrypto, libsodium, etc.)
  2. Package Manager Inspection: Query dpkg, pip, and npm metadata for
     installed crypto library packages with version information.
  3. TLS/SSL Config Inspection: Scan /etc/ssl and similar paths for
     certificate material, TLS configuration, and hardcoded key material.

Target type: CONTAINER_FS
Requirement: The container filesystem must be pre-extracted to a local directory.
             QNetra does NOT pull images or start containers (RULE-008).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from scanners.framework.base_scanner import BaseScanner
from scanners.framework.models import (
    ContainerContext,
    ScanResult,
    ScanTarget,
    TargetType,
)
from scanners.container.filesystem import (
    inspect_config_files,
    inspect_shared_libraries,
)
from scanners.container.package_inspector import (
    inspect_dpkg_packages,
    inspect_npm_packages,
    inspect_python_packages,
)

logger = logging.getLogger(__name__)


class ContainerScanner(BaseScanner):
    """
    Cryptographic Discovery Scanner for Extracted Container Filesystems.

    Analyzes an extracted container filesystem directory for installed
    cryptographic libraries, TLS configurations, and certificate material.

    This scanner operates purely on filesystem contents — no Docker daemon
    interaction, no container startup, no network calls (RULE-008).

    Target type: CONTAINER_FS
    Output: List[RawFinding] appended to ScanResult.findings
    """

    SCANNER_NAME = "ContainerScanner"
    SCANNER_VERSION = "1.0.0"

    def _validate_target(self, target: ScanTarget) -> Optional[str]:
        path = Path(target.path)
        if not path.exists():
            return f"Container filesystem path does not exist: {target.path}"
        if not path.is_dir():
            return f"ContainerScanner requires an extracted filesystem directory, not a file: {target.path}"
        # A valid container filesystem should have at least one recognizable path
        # This is a soft check — we proceed regardless and just may find nothing
        return None

    def _execute_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """Execute all container filesystem inspection stages."""
        fs_root = Path(target.path)

        # Build container context metadata for all findings
        container_ctx = ContainerContext(
            image_reference=target.metadata.get("image_reference"),
            layer_id=target.metadata.get("layer_id"),
            filesystem_path=str(fs_root),
        )

        total_findings = 0

        # Stage 1: Shared library detection
        self._logger.info("Stage 1: Scanning shared library directories...")
        try:
            lib_findings = inspect_shared_libraries(
                fs_root=fs_root,
                container_ctx=container_ctx,
                max_file_size=target.options.max_file_size_bytes,
            )
            result.findings.extend(lib_findings)
            total_findings += len(lib_findings)
            self._logger.info("Shared library inspection: %d finding(s)", len(lib_findings))
        except Exception as e:
            result.errors.append(f"Shared library inspection failed: {type(e).__name__}: {e}")
            self._logger.exception("Error during shared library inspection")

        # Stage 2: Package manager inspection
        self._logger.info("Stage 2: Inspecting package manager metadata...")
        for inspector_name, inspector_fn in [
            ("dpkg", inspect_dpkg_packages),
            ("pip", inspect_python_packages),
            ("npm", inspect_npm_packages),
        ]:
            try:
                pkg_findings = inspector_fn(fs_root, container_ctx)
                result.findings.extend(pkg_findings)
                total_findings += len(pkg_findings)
                self._logger.info(
                    "%s package inspection: %d finding(s)", inspector_name, len(pkg_findings)
                )
            except Exception as e:
                result.warnings.append(
                    f"{inspector_name} package inspection failed: {type(e).__name__}: {e}"
                )

        # Stage 3: TLS/SSL config file inspection
        self._logger.info("Stage 3: Scanning TLS/SSL configuration files...")
        try:
            config_findings = inspect_config_files(
                fs_root=fs_root,
                container_ctx=container_ctx,
                exclude_patterns=target.options.exclude_patterns,
                max_file_size=target.options.max_file_size_bytes,
            )
            result.findings.extend(config_findings)
            total_findings += len(config_findings)
            self._logger.info("Config file inspection: %d finding(s)", len(config_findings))
        except Exception as e:
            result.errors.append(f"Config file inspection failed: {type(e).__name__}: {e}")

        result.statistics.files_scanned = total_findings  # Approximate for container
        self._logger.info("Container scan complete | total_findings=%d", total_findings)
