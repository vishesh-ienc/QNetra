# Current Prompt Update — Public GitHub Repository Scanning Implementation

**Date:** 2026-09-15  
**Scope:** Public GitHub Repository Scan capability in New Scan page, acquisition layer, secure workspace management, real-time stage progress, and Scan History (RULE-012 compliant)

---

## 1. Summary of Actions Taken

1. **Repository Acquisition Layer (`backend/github.py`):**
   - Implemented `normalize_github_url(raw_url)` to enforce strict format `https://github.com/<owner>/<repo>`, handle variations (with/without `.git`, with/without `https://`, trailing slashes), and reject dangerous shell characters, credentials, or path traversals (`..`).
   - Implemented `verify_public_repo(normalized_url)` for non-blocking pre-flight checks using `git ls-remote --exit-code -h` with `GIT_TERMINAL_PROMPT=0` and `GIT_ASKPASS=echo`. Rejects private or non-existent repositories with HTTP 400 (`GITHUB_REPO_INACCESSIBLE`) and aligned error messages ("This GitHub repository could not be found or is not publicly accessible", "QNetra could not reach GitHub. Check the repository URL and try again.").
   - Implemented `acquire_github_repository(url, scan_id)` performing shallow clone (`--depth 1 --single-branch --no-tags`) into a temporary workspace, followed by safe `.git` folder removal with Windows read-only attribute handling.

2. **Pipeline Stage & Workspace Cleanup (`backend/pipeline.py`, `backend/store.py`):**
   - Updated `backend/store.py` with `GITHUB_STAGE_ORDER` prepending `ACQUISITION` as stage 1, and added `source_type` ("UPLOAD" | "GITHUB") and `source_url` to `ScanRecord`.
   - Updated `backend/serializers.py` to serialize `source_type`, `source_url`, and dynamic stages according to `source_type`.
   - Updated `backend/routes/scans.py` `CreateScanRequest` to accept `source_type` and `repository_url`, validating public accessibility before dispatching the background worker.
   - Updated `backend/pipeline.py` to run the `ACQUISITION` stage prior to `DISCOVERY` when `source_type == "GITHUB"`, assigning the cloned folder to `scan.target_path` and passing it to the exact same cryptographic analysis pipeline (`RepositoryScanner` -> `Normalizer` -> `ClassificationEngine` -> `CBOMSerializer` -> `RiskEngine` -> `MoscaEngine` -> `RecommendationEngine`).
   - Added automatic cleanup of the cloned repository folder in `finally:` block of `run_pipeline`, preventing temporary disk leaks.

3. **Frontend UI & Experience (`frontend/src/`):**
   - Updated `pages/ScanPage.tsx` with prompt-specified layout:
     - Header: "New Scan"
     - Subheader label: "Choose scan source"
     - Segmented buttons: `[ Upload Files ]` | `[ GitHub Repository ]`
     - Clean subtle divider.
     - GitHub section: Header "GitHub Repository", Subtitle "Scan a publicly accessible GitHub repository for cryptographic usage and quantum exposure.", Input label "Repository URL", placeholder `https://github.com/organization/repository`, helper "Only public GitHub repositories are supported.", Action button `[ Scan Repository ]`.
     - Instant client-side URL validation (`parseGitHubUrl`) ensuring valid syntax before submission.
     - Live scanning takeover view with Section 10 technical metadata grid (`Repository`, `Source`, `Status`, `Current stage`), real-time counters, and contextual transition text ("Acquiring repository from GitHub…", "Repository acquired. Starting cryptographic discovery…", "Discovering cryptographic usage…").
   - Updated `pages/ScanHistoryPage.tsx` and `ScanHistoryPage.module.css` to distinguish scan sources (`GitHub Repository`, `Uploaded Repository`, `Binary`, `Container`) and display clean repository identities (`github.com/owner/repo`).
   - Updated `lib/labels.ts` to define stage labels, user-facing activity descriptions, and outcome summaries for `ACQUISITION` and `DISCOVERY`.
   - Updated `pages/shared/ScanGate.tsx` and `components/layout/SideNav.tsx` to integrate `ACQUISITION` in pipeline ordering.

4. **Automated Testing:**
   - Authored `backend/tests/test_github_acquisition.py` with 14 comprehensive unit and integration tests covering URL normalization, mock accessibility checks, private/not-found/network error handling, clone failure and timeouts, workspace cleanup, and full end-to-end scan pipeline execution.
   - Executed full test suite: 567 passed, 1 skipped (0 failures, 100% active pass rate).
   - Executed frontend production build: `tsc -b && vite build` succeeded with 0 errors.

5. **Living Documentation Updates:**
   - Recorded ADR `DEC-017` in `docs/08_DECISIONS_AND_LOG.md`.
   - Updated `docs/06_API_AND_DATA_CONTRACTS.md` (Section 4.1).
   - Updated `docs/10_API_CONTRACT.md` (Section 6).
   - Updated `docs/04_MODULES.md` (`MOD-015`).
   - Updated `docs/07_PROGRESS.md`, `current_status.md`, and `PROJECT_CONTEXT.md`.

---

## 2. Files Touched

* `backend/github.py`
* `backend/errors.py`
* `backend/store.py`
* `backend/serializers.py`
* `backend/routes/scans.py`
* `backend/pipeline.py`
* `backend/tests/test_github_acquisition.py`
* `frontend/src/api/types.ts`
* `frontend/src/api/endpoints.ts`
* `frontend/src/lib/labels.ts`
* `frontend/src/pages/shared/ScanGate.tsx`
* `frontend/src/components/layout/SideNav.tsx`
* `frontend/src/pages/ScanPage.tsx`
* `frontend/src/pages/ScanPage.module.css`
* `frontend/src/pages/ScanHistoryPage.tsx`
* `frontend/src/pages/ScanHistoryPage.module.css`
* `docs/08_DECISIONS_AND_LOG.md`
* `docs/06_API_AND_DATA_CONTRACTS.md`
* `docs/10_API_CONTRACT.md`
* `docs/04_MODULES.md`
* `docs/07_PROGRESS.md`
* `current_status.md`
* `PROJECT_CONTEXT.md`
* `current_prompt_update.md`

---

## 3. Verification Results

* `pytest tests/ backend/tests/`: 567 passed, 1 skipped in 11.84s
* `npm run build`: `tsc -b && vite build` built in 4.63s with 0 errors
