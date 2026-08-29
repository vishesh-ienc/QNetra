"""
QNetra Discovery Framework — Scanner Router

The ScannerRouter is responsible for:
  1. Receiving a ScanTarget
  2. Determining the target type (auto-detection or explicit)
  3. Validating that a compatible scanner is registered
  4. Dispatching execution to the appropriate scanner
  5. Returning the ScanResult

Design principles:
  - Router logic is SEPARATE from scanner internals (architecture invariant RULE-004).
  - Auto-detection uses file-system heuristics, not magic.
  - Explicit target_type overrides auto-detection.
  - Routing is deterministic — same input always routes to same scanner.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from scanners.framework.base_scanner import BaseScanner
from scanners.framework.models import (
    BinaryFormat,
    ScanResult,
    ScanStatus,
    ScanTarget,
    TargetType,
)

logger = logging.getLogger(__name__)

# Binary file magic bytes for format detection
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACHO_MAGIC_LE = b"\xcf\xfa\xed\xfe"
_MACHO_MAGIC_BE = b"\xce\xfa\xed\xfe"


def _detect_binary_format(path: Path) -> BinaryFormat:
    """Read the first 4 bytes of a file to identify its binary format."""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
        if magic[:4] == _ELF_MAGIC:
            return BinaryFormat.ELF
        if magic[:2] == _PE_MAGIC:
            return BinaryFormat.PE
        if magic[:4] in (_MACHO_MAGIC_LE, _MACHO_MAGIC_BE):
            return BinaryFormat.MACHO
    except (OSError, PermissionError):
        pass
    return BinaryFormat.UNKNOWN


def _auto_detect_target_type(target_path: Path) -> TargetType:
    """
    Heuristically determine what kind of target this path represents.

    Detection order:
      1. If it is a directory → REPOSITORY (may contain extracted container FS)
      2. If it is a recognized binary format (ELF/PE) → BINARY
      3. Falls back to REPOSITORY for unknown single files.

    Note: CONTAINER_FS requires explicit target_type because an extracted container
    filesystem is indistinguishable from a regular directory via heuristics alone.
    """
    if not target_path.exists():
        logger.warning("Target path does not exist: %s", target_path)
        return TargetType.REPOSITORY  # Will fail during scanner validation

    if target_path.is_dir():
        return TargetType.REPOSITORY

    if target_path.is_file():
        fmt = _detect_binary_format(target_path)
        if fmt in (BinaryFormat.ELF, BinaryFormat.PE, BinaryFormat.MACHO):
            return TargetType.BINARY
        # Non-binary files (e.g. tarballs, zip archives) fall back to BINARY scanner
        # for string/symbol extraction attempts
        return TargetType.BINARY

    return TargetType.REPOSITORY


class ScannerRouter:
    """
    Routes ScanTarget instances to the appropriate registered scanner.

    Usage:
        router = ScannerRouter()
        router.register(TargetType.REPOSITORY, RepositoryScanner())
        router.register(TargetType.CONTAINER_FS, ContainerScanner())
        router.register(TargetType.BINARY, BinaryScanner())
        result = router.route(target)
    """

    def __init__(self) -> None:
        self._scanners: dict[TargetType, BaseScanner] = {}
        self._logger = logging.getLogger(self.__class__.__name__)

    def register(self, target_type: TargetType, scanner: BaseScanner) -> None:
        """
        Register a scanner for a specific target type.

        Only one scanner per TargetType is allowed. Registering a second scanner
        for the same type overwrites the first (last-write-wins).

        Args:
            target_type: The TargetType this scanner handles.
            scanner: A concrete BaseScanner implementation.
        """
        if target_type == TargetType.AUTO:
            raise ValueError(
                "Cannot register a scanner for TargetType.AUTO. "
                "AUTO is a routing hint, not a scanner designation."
            )
        self._scanners[target_type] = scanner
        self._logger.debug(
            "Registered scanner %r for target type %s", scanner.name, target_type.value
        )

    def route(self, target: ScanTarget) -> ScanResult:
        """
        Resolve the target type and dispatch to the appropriate scanner.

        Steps:
          1. If target_type is AUTO, run auto-detection heuristics.
          2. Verify a scanner is registered for the resolved type.
          3. Delegate to scanner.scan(target).

        Args:
            target: The ScanTarget to scan.

        Returns:
            ScanResult from the dispatched scanner.
        """
        target_path = Path(target.path)

        # Step 1: Resolve target type
        if target.target_type == TargetType.AUTO:
            resolved_type = _auto_detect_target_type(target_path)
            self._logger.info(
                "Auto-detected target type: %s for path: %s",
                resolved_type.value,
                target.path,
            )
            # Create a new target with resolved type (immutable pattern — no mutation)
            target = target.model_copy(update={"target_type": resolved_type})
        else:
            resolved_type = target.target_type
            self._logger.info(
                "Explicit target type: %s for path: %s",
                resolved_type.value,
                target.path,
            )

        # Step 2: Verify scanner registration
        scanner = self._scanners.get(resolved_type)
        if scanner is None:
            available = [t.value for t in self._scanners]
            error_msg = (
                f"No scanner registered for target type '{resolved_type.value}'. "
                f"Available types: {available}"
            )
            self._logger.error(error_msg)
            # Return a FAILED ScanResult rather than raising — callers can inspect errors
            return ScanResult(
                target=target,
                scanner_name="ScannerRouter",
                status=ScanStatus.FAILED,
                errors=[error_msg],
            )

        # Step 3: Dispatch
        self._logger.info(
            "Routing to scanner: %s", scanner.name
        )
        return scanner.scan(target)

    def registered_types(self) -> list[TargetType]:
        """Return all currently registered TargetTypes."""
        return list(self._scanners.keys())

    @classmethod
    def create_default(cls) -> "ScannerRouter":
        """
        Factory method that creates a ScannerRouter pre-configured with all
        three Phase 1 scanners.

        Import is done locally to avoid circular imports since scanner modules
        import from framework.models.
        """
        from scanners.repository.scanner import RepositoryScanner
        from scanners.container.scanner import ContainerScanner
        from scanners.binary.scanner import BinaryScanner

        router = cls()
        router.register(TargetType.REPOSITORY, RepositoryScanner())
        router.register(TargetType.CONTAINER_FS, ContainerScanner())
        router.register(TargetType.BINARY, BinaryScanner())
        return router
