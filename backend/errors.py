"""Error envelope matching docs/10_API_CONTRACT.md §17."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException


class ApiError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str, details: Optional[Any] = None):
        super().__init__(
            status_code=status_code,
            detail={"error": {"code": code, "message": message, "details": details}},
        )


def scan_not_found(scan_id: str) -> ApiError:
    return ApiError(404, "SCAN_NOT_FOUND", f"Scan {scan_id} does not exist.")


def artifact_not_found(artifact_id: str) -> ApiError:
    return ApiError(404, "ARTIFACT_NOT_FOUND", f"Artifact {artifact_id} does not exist.")


def finding_not_found(finding_id: str) -> ApiError:
    return ApiError(404, "FINDING_NOT_FOUND", f"Finding {finding_id} does not exist.")


def asset_not_found(asset_id: str) -> ApiError:
    return ApiError(404, "ASSET_NOT_FOUND", f"Asset {asset_id} does not exist.")


def validation_error(message: str, details: Optional[Any] = None) -> ApiError:
    return ApiError(422, "VALIDATION_ERROR", message, details)


def scan_not_ready(scan_id: str, status: str) -> ApiError:
    return ApiError(
        409,
        "SCAN_NOT_READY",
        f"Scan {scan_id} has not completed (status: {status}). Results are not yet available.",
    )
