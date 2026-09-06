# Frontend ↔ Backend Gap Register

> **Purpose:** Every place where the frontend needs something the backend does not provide today,
> or where `docs/10_API_CONTRACT.md` and the implemented engines in `core/` disagree.
>
> **Rule this document exists to enforce:** the frontend never invents security intelligence.
> Where a gap exists, the UI shows an explicit unavailable state and this register records why.
>
> **Status as of this build:** the frontend implements no backend change and requests none. Each
> entry states what the interface does today and what it would consume if the gap were closed.

---

## 1. The API gateway does not exist yet

`backend/` contains only a placeholder. There is no running `/api/v1`, so nothing in
`docs/10_API_CONTRACT.md` is reachable.

**What the frontend does:** every call goes through `src/api/client.ts`, which has two transports.
`live` speaks the contract to a real server. `mock` (the default) answers the *same* request
contract from JSON fixtures in `src/mocks/fixtures/`.

**Where the fixtures come from:** `frontend/tools/generate_fixtures.py` runs the real pipeline —
`scanners.repository`, `core.normalization`, `core.classification`, `core.risk_engine`,
`core.mosca_engine`, `core.recommendation_engine`, `core.cbom_generator` — over
`samples/repository_samples/` and serialises the engines' own output. No value in the dataset is
hand-written. Regenerate with:

```bash
python frontend/tools/generate_fixtures.py
```

**To switch to the real API:** set `VITE_API_MODE=live` (and `VITE_API_BASE_URL` if it is not
`/api/v1`). No component changes — the transport is the only thing that differs.

---

## 2. Contract vs. implemented engines

`docs/10_API_CONTRACT.md` was frozen before Phase 3 completed. The engines now emit shapes the
contract does not describe. The frontend types (`src/api/types.ts`) follow the **engines**, because
that is what a thin FastAPI layer over `core/` will actually serve.

### 2.1 Mosca (`§12`)

| Contract says | Engine produces |
| :--- | :--- |
| One repository-level result: `x_plus_y`, `is_vulnerable`, `exposure_gap_years`, `deadline_year`, `hndl_alert` | A `MoscaAssessment` **per asset**, plus a `MoscaAssessmentReport` with `urgency_distribution` and `hndl_distribution` |
| `urgency_rating`: `CRITICAL_IMMEDIATE` / `HIGH_PLANNED` / `MODERATE` | `MoscaUrgency`: `IMMEDIATE` / `URGENT` / `PLANNED` / `MONITOR` / `NOT_REQUIRED` / `UNKNOWN` |
| `hndl_alert`: boolean | `HNDLExposure`: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE` / `UNKNOWN` |
| `deadline_year`: absolute year | `migration_deadline_years_from_now`: years from `assessment_date` |
| Y supplied by the caller | Y derived per `primitive_type` unless explicitly overridden |

The per-asset model is the more accurate one: Y depends on what is being migrated, so a single
repository-wide verdict would flatten real differences. The Mosca page therefore reports
"*n* of *m* applicable assets fail the inequality" rather than one boolean.

**Recommendation:** update `docs/10_API_CONTRACT.md §12` to the engine's shape.

### 2.2 Recommendations (`§13`)

The contract's field names differ from `PQCRecommendation.to_dict()`:
`primary_pqc_replacement` → `recommended_algorithm`, `recommended_hybrid_scheme` →
`hybrid_recommendation`, `migration_strategy` → `recommendation_type`, and `rationale` is a
**list** of strings, not one string. `priority` does not exist on the recommendation — urgency
comes from the Mosca engine.

The engine also emits `CLASSICAL_UPGRADE`, added in the Phase 3.3 corrective pass, which the
contract's `§13` example does not mention. The UI treats it as a first-class category and never
presents it as post-quantum cryptography.

### 2.3 Risk (`§9`)

Field names differ: `total_assets` → `total_assets_discovered`, `vulnerable_assets` →
`vulnerable_assets_count`, and the quantum counts are top-level rather than nested under
`quantum_exposure`. `top_risk_assets` is `asset_scores` (all assets, not a top-N slice), and the
full `assessments` list carries the per-factor breakdown the investigation drawer displays.

---

## 3. Endpoints with no engine behind them

### 3.1 `GET /scans/{id}/quantum` (`§11`)

There is no `core.quantum_analysis` module. Quantum classification lives in `core.classification`
and is already carried on each `CryptoAsset` (`quantum_threat_type`, `quantum_security_status`,
`effective_classical_security_bits`, `effective_quantum_security_bits`), with the aggregate counts
in the risk report.

**What the frontend does:** the Quantum page consumes `/risk` and `/assets`. It does not call
`/quantum`, so a redundant endpoint is not required.

**`quantum_readiness_score` is not implemented anywhere.** The page says so explicitly rather than
computing a composite. If a readiness score is wanted, it belongs in `core/`, with a documented
formula in `docs/05_ALGORITHMS.md`.

### 3.2 `GET /scans/{id}/migration` (`§14`)

There is no `core.migration_planner`. The `IMMEDIATE` / `SHORT_TERM` / `MEDIUM_TERM` / `PLANNED`
buckets and their timeframe guidance have no engine behind them.

**What the frontend does:** the PQC Migration page groups assets by the `MoscaUrgency` the Mosca
engine assigned, or by the `recommendation_type` the recommendation engine assigned. Both are
backend classifications. The UI attaches no dates, sprints or deadlines of its own.

### 3.3 `GET /scans/{id}/export` and `/cbom/export` (`§10`, `§15`)

Not reachable without the API. The Reports page downloads the exact JSON documents the endpoints
returned (CBOM, risk, Mosca, recommendations) and builds one CSV by flattening those documents —
every CSV column is a value an engine produced. PDF and XML are listed as unavailable, because
generating either in the browser would produce a document the engines never authored.

### 3.4 `POST /artifacts/upload`, `POST /scans` (`§5`, `§6`)

The Scan page implements the real two-step flow (upload, then create). Without the API it surfaces
the failure with an explanation instead of simulating a scan.

---

## 4. Additions the frontend asks the contract to consider

| Request | Why |
| :--- | :--- |
| `q` free-text search parameter on `/findings` and `/assets` | The tables offer search across symbol, path, algorithm and library. The mock transport implements it; a live backend currently would not. Without it, search has to be client-side and therefore limited to the current page. |
| `quantum_threat_type` filter on `/assets` | `§8` defines `quantum_vulnerable` (boolean). The Quantum page filters by threat class, which is a finer and more useful cut of the same field. |
| Facet counts on the scan resource | `ScanStatistics.findings_by_method` / `findings_by_category` and `NormalizationStatistics.assets_by_*` populate the filter menus with real counts without fetching the whole list. These already exist in the models; they just need to be on the scan response. The fixture exposes them as `scan.discovery` and `scan.normalization`. |
| `POST /scans/{id}/mosca` accepting a partial body | The Mosca page sends only the parameters the user changed, letting the engine keep its own defaults for the rest. |

---

## 5. Known limitation of the offline dataset

Mosca recomputation is engine work. Without the API, the interface cannot evaluate `X + Y > Z`
itself and will not try. `generate_fixtures.py` therefore pre-computes a grid of **real engine
runs** for X ∈ {1, 3, 5, 10, 15, 20, 25} and Z ∈ {5, 10, 15}, and the Mosca sliders snap to those
values with a note explaining why. In `live` mode the controls are continuous and every value is
recomputed by `core.mosca_engine`.
