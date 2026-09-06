"""
In-memory persistence for artifacts and scans.

There is no database in this phase — the contract's async lifecycle (POST
returns immediately, client polls) is honored with in-process state guarded
by a lock, since the pipeline runs in a background thread per scan. This is
storage plumbing, not analysis: it holds exactly what the engines produced.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from core.mosca_engine.models import MoscaAssessment, MoscaAssessmentReport
from core.recommendation_engine.models import PQCRecommendation, PQCRecommendationReport
from core.risk_engine.models import RiskAssessment, RiskAssessmentReport
from scanners.framework.models import RawFinding
from core.models import CryptoAsset

ARTIFACT_RETENTION = timedelta(days=7)


@dataclass
class ArtifactRecord:
    artifact_id: str
    name: Optional[str]
    artifact_type: Optional[str]
    filename: str
    file_size_bytes: int
    status: str  # UPLOADING | PROCESSING | READY | FAILED | EXPIRED
    path: Path  # extracted directory (zip) or the single saved file
    uploaded_at: datetime
    expires_at: datetime

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "description": None,
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "file_count": None,
            "status": self.status,
            "uploaded_at": self.uploaded_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
        }


STAGE_ORDER = [
    "DISCOVERY",
    "NORMALIZATION",
    "CLASSIFICATION",
    "CBOM",
    "RISK_ANALYSIS",
    "MOSCA_ANALYSIS",
    "PQC_ANALYSIS",
]


@dataclass
class ScanRecord:
    """
    Everything genuinely computed for one scan.

    `status`/`current_stage` are mutated by backend.pipeline as the real
    pipeline advances through each engine — they are not simulated for effect.
    """

    scan_id: str
    name: Optional[str]
    artifact_id: Optional[str]
    target_path: str
    target_type: str
    target_name: Optional[str]
    status: str = "QUEUED"  # QUEUED | RUNNING | COMPLETED | PARTIAL | FAILED | CANCELLED
    current_stage: str = "QUEUED"
    stage_status: dict[str, str] = field(
        default_factory=lambda: {name: "WAITING" for name in STAGE_ORDER}
    )
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Discovery
    directories_visited: int = 0
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_errored: int = 0
    findings: list[RawFinding] = field(default_factory=list)
    findings_by_method: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)

    # Normalization + classification
    assets: list[CryptoAsset] = field(default_factory=list)
    normalization_stats: Optional[dict[str, Any]] = None

    # Downstream engine output
    risk_assessments: list[RiskAssessment] = field(default_factory=list)
    risk_report: Optional[RiskAssessmentReport] = None
    mosca_assessments: list[MoscaAssessment] = field(default_factory=list)
    mosca_report: Optional[MoscaAssessmentReport] = None
    mosca_params: dict[str, Any] = field(default_factory=dict)
    recommendations: list[PQCRecommendation] = field(default_factory=list)
    recommendation_report: Optional[PQCRecommendationReport] = None
    cbom_assets_signature: Optional[str] = None  # unused placeholder for future caching

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class Store:
    """Process-wide state. One instance, imported by every route module."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.artifacts: dict[str, ArtifactRecord] = {}
        self.scans: dict[str, ScanRecord] = {}

    def put_artifact(self, record: ArtifactRecord) -> None:
        with self._lock:
            self.artifacts[record.artifact_id] = record

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactRecord]:
        with self._lock:
            return self.artifacts.get(artifact_id)

    def put_scan(self, record: ScanRecord) -> None:
        with self._lock:
            self.scans[record.scan_id] = record

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        with self._lock:
            return self.scans.get(scan_id)

    def list_scans(self) -> list[ScanRecord]:
        with self._lock:
            return sorted(self.scans.values(), key=lambda s: s.created_at, reverse=True)


def new_id() -> str:
    return str(uuid.uuid4())


store = Store()
