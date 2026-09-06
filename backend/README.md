# QNetra Backend — API Gateway

The Phase 4 FastAPI layer. Orchestrates the existing, unmodified pipeline
(`scanners/` → `core/normalization` → `core/classification` →
`core/risk_engine` → `core/mosca_engine` → `core/recommendation_engine` →
`core/cbom_generator`) and exposes it as the JSON API `docs/10_API_CONTRACT.md`
describes. It contains no cryptographic, risk, or classification logic —
see `PROJECT_RULES.md` RULE-004.

## Run it

```bash
pip install -r requirements.txt -r backend/requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Interactive docs at `http://localhost:8000/docs`.

## Test it

```bash
pip install pytest
python -m pytest backend/tests -v
```

27 tests, all running the real engines against `samples/repository_samples/`
end to end (upload → scan → poll → results), not against mocked data.

## Layout

```
backend/
├── main.py         FastAPI app, CORS, router registration
├── pipeline.py      Orchestration: calls each engine in order, updates
│                    ScanRecord as each real stage completes
├── store.py         In-memory ScanRecord / ArtifactRecord state (no DB yet)
├── serializers.py   Shapes engine output into the API's JSON contract
├── artifacts.py     Upload handling — zip extraction with zip-slip protection
├── filtering.py     Generic search/filter/sort/paginate for list endpoints
├── errors.py        docs/10 §17 error envelope
├── routes/          One module per resource (scans, findings, assets,
│                    risk, mosca, recommendations, cbom, exports, artifacts)
└── tests/           pytest suite (see above)
```

## Known limitations

- **In-memory only.** A restart loses every scan and artifact. No persistence
  layer exists yet — this is infrastructure, not analysis, and is genuinely
  out of scope for the current phase.
- **No auth, permissive CORS.** Fine for local development; not for
  production exposure.
- Container and binary scanning are wired into the router (`ScannerRouter`
  already dispatches `CONTAINER_FS` / `BINARY` targets to the existing
  scanners) but have no end-to-end test through the API — only the
  repository target type is exercised by `backend/tests/`.

See `frontend/API_GAPS.md` for the full reconciliation between
`docs/10_API_CONTRACT.md`, the implemented engines, and this gateway.
