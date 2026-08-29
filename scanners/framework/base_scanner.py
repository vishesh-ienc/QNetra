"""
QNetra Discovery Framework — Base Scanner Abstract Contract

Defines the BaseScanner abstract class that all scanner implementations must extend.
This contract enforces:
  - Consistent scan() interface
  - Standard ScanResult construction
  - Mandatory scan lifecycle management (start/end timestamps, status tracking)
  - Common error handling behavior

Architecture invariant: Scanners MUST remain stateless across separate scan() calls.
Each call to scan() should operate independently and return a fresh ScanResult.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

from scanners.framework.models import (
    ScanResult,
    ScanStatus,
    ScanTarget,
    ScanStatistics,
)

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for all QNetra scanner implementations.

    Every concrete scanner (RepositoryScanner, ContainerScanner, BinaryScanner,
    and future scanners) must extend this class and implement _execute_scan().

    The scan() method handles lifecycle management. Subclasses focus only on
    the actual discovery logic in _execute_scan().

    Supported scanner hierarchy:
        BaseScanner
        ├── RepositoryScanner    (scanners.repository.scanner)
        ├── ContainerScanner     (scanners.container.scanner)
        ├── BinaryScanner        (scanners.binary.scanner)
        ├── DependencyScanner    (future)
        ├── CertificateScanner   (future)
        └── ConfigurationScanner (future)
    """

    #: Scanner name — override in subclass with a descriptive identifier.
    SCANNER_NAME: str = "BaseScanner"
    SCANNER_VERSION: str = "1.0.0"

    def __init__(self) -> None:
        self._logger = logging.getLogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )

    def scan(self, target: ScanTarget) -> ScanResult:
        """
        Execute a scan against the given target.

        This method manages the scan lifecycle:
          1. Validates that the target type is supported by this scanner.
          2. Records start timestamp.
          3. Delegates to _execute_scan() for actual discovery work.
          4. Records completion timestamp and final status.
          5. Returns a fully populated ScanResult.

        Subclasses must NOT override this method. Override _execute_scan() instead.

        Args:
            target: The ScanTarget representing what to scan.

        Returns:
            ScanResult with findings, statistics, warnings, and errors.
        """
        result = ScanResult(
            target=target,
            scanner_name=self.SCANNER_NAME,
            scanner_version=self.SCANNER_VERSION,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )

        self._logger.info(
            "Starting scan | scanner=%s | target=%s | type=%s",
            self.SCANNER_NAME,
            target.path,
            target.target_type.value,
        )

        try:
            # Pre-scan target validation
            validation_error = self._validate_target(target)
            if validation_error:
                result.status = ScanStatus.FAILED
                result.errors.append(f"Target validation failed: {validation_error}")
                result.completed_at = datetime.now(timezone.utc)
                self._logger.error("Scan failed validation: %s", validation_error)
                return result

            # Execute scanner-specific discovery
            self._execute_scan(target, result)

            # Determine final status
            if result.errors:
                result.status = ScanStatus.PARTIAL
            else:
                result.status = ScanStatus.COMPLETED

        except Exception as exc:
            result.status = ScanStatus.FAILED
            result.errors.append(f"Unhandled scanner error: {type(exc).__name__}: {exc}")
            self._logger.exception("Unhandled error during scan of %s", target.path)

        finally:
            result.completed_at = datetime.now(timezone.utc)
            duration = result.duration_seconds
            result.statistics.findings_count = len(result.findings)
            result.statistics.scan_duration_seconds = duration or 0.0

        self._logger.info(
            "Scan complete | scanner=%s | status=%s | findings=%d | duration=%.2fs",
            self.SCANNER_NAME,
            result.status.value,
            len(result.findings),
            result.statistics.scan_duration_seconds,
        )

        return result

    @abstractmethod
    def _execute_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """
        Subclass-specific discovery logic.

        Implementations should:
          - Traverse/inspect the target
          - Append RawFinding objects to result.findings
          - Update result.statistics
          - Append non-fatal issues to result.warnings
          - Append recoverable errors to result.errors (do NOT raise for recoverable errors)
          - Raise only for truly unrecoverable conditions

        Args:
            target: The ScanTarget to scan.
            result: The ScanResult to populate (mutate in place).
        """

    def _validate_target(self, target: ScanTarget) -> Optional[str]:
        """
        Validate that the target is compatible with this scanner.

        Returns None if valid, or an error message string if invalid.
        Subclasses may override to add scanner-specific validation.
        """
        return None  # Default: accept any target (router handles type-matching)

    @property
    def name(self) -> str:
        return self.SCANNER_NAME

    @property
    def version(self) -> str:
        return self.SCANNER_VERSION

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.SCANNER_NAME!r}, version={self.SCANNER_VERSION!r})"
