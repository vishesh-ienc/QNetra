"""
QNetra API Gateway — Phase 4 FastAPI entry point.

    uvicorn backend.main:app --reload --port 8000

Every route delegates to scanners/ and core/ unchanged. See backend/__init__.py
for the layering rule this file enforces.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.errors import ApiError
from backend.routes import artifacts, assets, cbom, exports, findings, mosca, recommendations, risk, scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(
    title="QNetra API",
    version="1.0.0",
    description="Enterprise Cryptographic Discovery & Analysis Tool — API Gateway",
)

# Dev-time CORS: the Vite dev server proxies /api by default, so this is a
# safety net for direct-origin requests (e.g. VITE_API_BASE_URL overridden to
# an absolute URL, or `vite preview`). Not a production security boundary.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
app.include_router(artifacts.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(assets.router, prefix=API_PREFIX)
app.include_router(risk.router, prefix=API_PREFIX)
app.include_router(mosca.router, prefix=API_PREFIX)
app.include_router(recommendations.router, prefix=API_PREFIX)
app.include_router(cbom.router, prefix=API_PREFIX)
app.include_router(exports.router, prefix=API_PREFIX)


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
