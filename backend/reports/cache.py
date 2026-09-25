"""
In-Memory Report Cache & Pre-Warming Subsystem.

Caches generated reports (PDF, CSV, JSON) for completed scans to deliver
sub-millisecond downloads. Pre-warms common reports (Executive PDF, Migration Plan)
upon scan completion.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from backend.store import ScanRecord

logger = logging.getLogger(__name__)


class ReportCache:
    """Thread-safe LRU-style cache for compiled report artifacts."""

    def __init__(self, max_entries: int = 256):
        self._cache: dict[tuple[str, str, str], tuple[bytes | str, str, str]] = {}
        self._keys_order: list[tuple[str, str, str]] = []
        self._lock = threading.Lock()
        self._max = max_entries

    def get(self, scan_id: str, report_type: str, format_type: str) -> Optional[tuple[bytes | str, str, str]]:
        key = (scan_id, report_type, format_type)
        with self._lock:
            if key in self._cache:
                # Move to end for LRU
                self._keys_order.remove(key)
                self._keys_order.append(key)
                return self._cache[key]
        return None

    def set(
        self,
        scan_id: str,
        report_type: str,
        format_type: str,
        content: bytes | str,
        media_type: str,
        filename: str,
    ) -> None:
        key = (scan_id, report_type, format_type)
        with self._lock:
            if key in self._cache:
                self._keys_order.remove(key)
            elif len(self._keys_order) >= self._max:
                oldest = self._keys_order.pop(0)
                self._cache.pop(oldest, None)

            self._cache[key] = (content, media_type, filename)
            self._keys_order.append(key)

    def invalidate_scan(self, scan_id: str) -> None:
        with self._lock:
            keys_to_remove = [k for k in self._keys_order if k[0] == scan_id]
            for k in keys_to_remove:
                self._keys_order.remove(k)
                self._cache.pop(k, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._keys_order.clear()


    def prewarm(self, scan: ScanRecord) -> None:
        """Pre-computes the most common reports in the background so downloads are instantaneous."""
        if scan.status not in ("COMPLETED", "PARTIAL"):
            return

        try:
            from backend.reports.data import extract_report_data
            from backend.reports.pdf import build_executive_pdf, build_migration_pdf
            from backend.reports.csv_builder import build_migration_csv

            # Fast extract without findings (not needed for executive or migration)
            data = extract_report_data(scan, include_findings=False)

            # Executive PDF
            if not self.get(scan.scan_id, "executive", "pdf"):
                exec_pdf = build_executive_pdf(data)
                self.set(
                    scan.scan_id,
                    "executive",
                    "pdf",
                    exec_pdf,
                    "application/pdf",
                    f"qnetra-executive-assessment-{data.safe_target}.pdf",
                )

            # Migration PDF
            if not self.get(scan.scan_id, "migration", "pdf"):
                mig_pdf = build_migration_pdf(data)
                self.set(
                    scan.scan_id,
                    "migration",
                    "pdf",
                    mig_pdf,
                    "application/pdf",
                    f"qnetra-pqc-migration-plan-{data.safe_target}.pdf",
                )

            # Migration CSV
            if not self.get(scan.scan_id, "migration", "csv"):
                mig_csv = build_migration_csv(data)
                self.set(
                    scan.scan_id,
                    "migration",
                    "csv",
                    mig_csv,
                    "text/csv",
                    f"qnetra-pqc-migration-plan-{data.safe_target}.csv",
                )

            logger.info("Pre-warmed reports for scan %s successfully", scan.scan_id)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to pre-warm reports for scan %s: %s", scan.scan_id, e)


# Global singleton
report_cache = ReportCache()


def prewarm_reports_async(scan: ScanRecord) -> None:
    """Dispatches report pre-warming on a background daemon thread."""
    thread = threading.Thread(target=report_cache.prewarm, args=(scan,), daemon=True)
    thread.start()
