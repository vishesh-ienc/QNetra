"""
Artifact upload handling.

Accepts an uploaded file, stores it under a per-artifact temp workspace, and —
for zip archives — extracts it with zip-slip protection (every extracted path
is confirmed to stay inside the workspace before it is written). This is
standard safe file handling for untrusted uploads (RULE-008: passive,
non-destructive), not cryptographic analysis.
"""

from __future__ import annotations

import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import UploadFile

from backend.store import ARTIFACT_RETENTION, ArtifactRecord, new_id, store

_WORKSPACE_ROOT = Path(tempfile.gettempdir()) / "qnetra-artifacts"
_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)


class InvalidArtifactError(ValueError):
    """Raised for malformed or unsafe uploads (e.g. zip-slip attempts)."""


def _safe_extract(zip_path: Path, dest: Path) -> None:
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            member_path = (dest / member.filename).resolve()
            if member_path == dest_resolved or dest_resolved not in member_path.parents:
                raise InvalidArtifactError(
                    f"Archive entry '{member.filename}' resolves outside the "
                    "extraction workspace and was rejected."
                )
        archive.extractall(dest)


async def save_upload(file: UploadFile, name: Optional[str]) -> ArtifactRecord:
    artifact_id = new_id()
    workspace = _WORKSPACE_ROOT / artifact_id
    workspace.mkdir(parents=True, exist_ok=True)

    filename = file.filename or "upload"
    raw_path = workspace / "_raw" / filename
    raw_path.parent.mkdir(parents=True, exist_ok=True)

    size = 0
    with open(raw_path, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
            size += len(chunk)

    if filename.lower().endswith(".zip"):
        extracted = workspace / "content"
        extracted.mkdir(parents=True, exist_ok=True)
        try:
            _safe_extract(raw_path, extracted)
        except zipfile.BadZipFile as exc:
            raise InvalidArtifactError(f"'{filename}' is not a valid zip archive.") from exc
        target_path = extracted
        artifact_type = "SOURCE_REPOSITORY"
    else:
        target_path = raw_path
        artifact_type = "BINARY"

    now = datetime.now(timezone.utc)
    record = ArtifactRecord(
        artifact_id=artifact_id,
        name=name or filename,
        artifact_type=artifact_type,
        filename=filename,
        file_size_bytes=size,
        status="READY",
        path=target_path,
        uploaded_at=now,
        expires_at=now + ARTIFACT_RETENTION,
    )
    store.put_artifact(record)
    return record
