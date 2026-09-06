# Frontend ↔ Backend Gap Register

> **Purpose:** Where `docs/10_API_CONTRACT.md`, the implemented `core/` engines, and the `backend/`
> API gateway disagree or where something genuinely isn't implemented — and why.
>
> **Rule this document exists to enforce:** the frontend never invents security intelligence, and
> the backend never invents pipeline output. Every gap below is either a naming/shape reconciliation
> or an honest "not implemented," never a workaround that fabricates data.

---

## 1. Status: the API gateway now exists

`backend/` was empty at the start of this work (only `.gitkeep`). It now contains a working FastAPI
gateway (`backend/main.py`) that orchestrates the real pipeline —

```
scanners.* -> core.normalization -> core.classification -> core.risk_engine
           -> core.mosca_engine -> core.recommendation_engine -> core.cbom_generator
```

— for every request, with no cryptographic, scoring, or classification logic of its own
(`backend/pipeline.py`, `backend/serializers.py`). It is exercised by 27 tests in `backend/tests/`,
all running the real engines against `samples/repository_samples/`, and by a full browser-driven
run (upload → scan → poll → dashboard) confirming the numbers rendered match the numbers the
engines produced.

Run it: `uvicorn backend.main:app --reload --port 8000`. The frontend defaults to
`VITE_API_MODE=live` and talks to it through the Vite dev proxy; `VITE_API_MODE=mock` still serves
the offline fixture dataset (`frontend/tools/generate_fixtures.py`) for UI work without a backend.

---

## 2. Endpoints implemented

| Endpoint | Notes |
| :--- | :--- |
| `POST /artifacts/upload` | Zip archives are extracted with zip-slip protection; other files are saved as-is. |
| `GET /artifacts/{id}` | |
| `POST /scans` | Runs the full pipeline on a background thread; accepts optional `mosca_params`. |
| `GET /scans`, `GET /scans/{id}`, `GET /scans/{id}/progress` | Stage-by-stage status reflects the real pipeline's actual progress, not a simulated timer. |
| `GET /scans/{id}/findings`, `.../findings/{id}` | Search (`q`), filter, sort, paginate — server-side. |
| `GET /scans/{id}/assets`, `.../assets/{id}` | Same list contract as findings, plus `quantum_threat_type` and `severity` filters. |
| `GET /scans/{id}/risk` | |
| `GET /scans/{id}/mosca` (GET + POST) | **Live recomputation.** Any X/Y/Z is re-evaluated by `core.mosca_engine` on the spot — GET with query params computes without persisting, POST persists as the scan's new baseline. |
| `GET /scans/{id}/recommendations` | |
| `GET /scans/{id}/cbom`, `.../cbom/export?format=json\|xml` | XML export uses `CBOMSerializer.to_xml()`, which already existed and was unused. |
| `GET /scans/{id}/export?format=json\|csv` | Added beyond the original scope of "just wire the existing pages" because the data was already fully computed in `ScanRecord` — assembling it into one document (json) or one CSV is composition, not analysis. `format=pdf` returns `501 NOT_IMPLEMENTED` honestly (see §4). |

---

## 3. Contract vs. engine reconciliation

`docs/10_API_CONTRACT.md` was frozen before Phase 3 completed, so a few response shapes diverge
from what the engines actually produce. The backend and frontend types both follow the **engines**
(verified against real `.to_dict()` / `.to_api_dict()` output), because that is the actual data
available to serve — not a hypothetical the contract described earlier.

- **Mosca (`§12`)** — the contract describes one repository-level verdict (`is_vulnerable`,
  `deadline_year`, `hndl_alert: bool`). The engine produces a `MoscaAssessment` **per asset** (Y
  differs by primitive type) with `MoscaUrgency` (`IMMEDIATE`/`URGENT`/`PLANNED`/`MONITOR`/
  `NOT_REQUIRED`/`UNKNOWN`) and `HNDLExposure` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`/`UNKNOWN`)
  tiers, aggregated into `MoscaAssessmentReport.urgency_distribution` /`hndl_distribution`. The
  per-asset model is correct and the contract should be updated to match.
- **Recommendations (`§13`)** — field names differ (`primary_pqc_replacement` →
  `recommended_algorithm`, `migration_strategy` → `recommendation_type`, `rationale` is a list, not
  a string), and `CLASSICAL_UPGRADE` — added in the Phase 3.3 corrective pass specifically so a
  classical hardening is never mislabeled `DIRECT_PQC` — isn't in the contract's example.
- **Risk (`§9`)** — `total_assets` → `total_assets_discovered`, `top_risk_assets` → `asset_scores`
  (all assets, not a top-N slice; the API's `sort=risk_score` query param is how a client gets a
  top-N view).

**Recommendation:** update `docs/10_API_CONTRACT.md §9/§12/§13` to the engine's actual shape now
that a real implementation exists to verify it against.

---

## 4. Genuinely not implemented, and why

- **`quantum_readiness_score` / a dedicated `/quantum` endpoint.** No `core.quantum_analysis`
  module exists. Quantum classification lives on each `CryptoAsset`
  (`quantum_threat_type`, `quantum_security_status`, `effective_*_security_bits`) and is aggregated
  in the risk report; the Quantum page composes its view from `/risk` + `/assets` rather than a
  route that doesn't exist behind real logic. No composite "readiness score" is invented.
- **`/migration` roadmap endpoint / `IMMEDIATE`-`SHORT_TERM`-`MEDIUM_TERM`-`PLANNED` buckets.** No
  `core.migration_planner` exists — nothing computes a timeframe or a deadline. The PQC Migration
  page (and the Command Center's migration section) groups assets by the `MoscaUrgency` the Mosca
  engine already assigned, or by `recommendation_type`. Both are real backend classifications; no
  date, sprint, or deadline is attached by the frontend.
- **`format=pdf` on `/export`.** No engine produces report prose or page layout. The route returns
  a structured `501 NOT_IMPLEMENTED` rather than a client-rendered document the pipeline never
  authored.

---

## 5. What the frontend adds beyond raw display

All presentation-layer only, per RULE-004 — filtering, sorting, search, pagination, and grouping by
data the backend already returns:

- Free-text search (`q`) and the extra filters above are implemented server-side (see §2), removing
  the need for any client-side re-filtering of an already-paginated list.
- The Command Center's "Where risk concentrates" section groups assets by the top-level path
  segment of `location.file_path` — the only system/component boundary genuinely present in the
  data. QNetra does not infer service or system names.
- The Reports page's CSV/JSON exports of already-fetched query data (risk, Mosca, recommendations,
  CBOM) are saved client-side with no server round-trip, since the data is already in memory; the
  asset-inventory CSV and the combined envelope now come from the real `/export` endpoint instead
  (§2), removing what used to be ~60 lines of duplicate flattening logic in the frontend.

---

## 6. Known limitations (honest accounting)

- **In-memory state.** Scans and artifacts live in process memory (`backend/store.py`) — a backend
  restart loses all history. Acceptable for local/dev use; a real deployment needs persistence,
  which is out of scope here (not analysis logic, but a real piece of follow-up work).
- **No auth.** Nothing in the contract calls for it yet; CORS is wide open for local development.
- **Backend test suite is targeted, not exhaustive** — 27 tests covering the upload → scan →
  results lifecycle, filtering/sorting/pagination, validation errors, 404s, and the export formats.
  It does not cover concurrent scans, very large uploads, or container/binary target types (the
  scanners for those exist and are wired into the router, but no sample fixture exercises them end
  to end from the API the way `samples/repository_samples/` does).
- **No accessibility audit was performed** beyond what the existing component library already does
  (semantic HTML, focus states, keyboard-operable drawers and tables).
