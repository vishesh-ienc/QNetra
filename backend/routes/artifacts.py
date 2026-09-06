from __future__ import annotations

from fastapi import APIRouter, Form, UploadFile
from fastapi import File as FastAPIFile

from backend.artifacts import InvalidArtifactError, save_upload
from backend.errors import artifact_not_found, validation_error
from backend.store import store

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.post("/upload", status_code=201)
async def upload_artifact(
    file: UploadFile = FastAPIFile(...),
    name: str | None = Form(None),
    artifact_type: str | None = Form(None),
):
    try:
        record = await save_upload(file, name)
    except InvalidArtifactError as exc:
        raise validation_error(str(exc)) from exc
    return record.to_api_dict()


@router.get("/{artifact_id}")
def get_artifact(artifact_id: str):
    record = store.get_artifact(artifact_id)
    if record is None:
        raise artifact_not_found(artifact_id)
    return record.to_api_dict()
