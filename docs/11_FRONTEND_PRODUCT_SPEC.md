# 11 — Frontend Product Specification

> **DOCUMENT PURPOSE:** Authoritative specification for the QNetra frontend product.
> Written for the frontend developer and their AI coding agent.
> Contains the complete product philosophy, user flow, screen-by-screen specification,
> component guidance, and visual direction.
>
> **CONTRACT:** The frontend must consume `docs/10_API_CONTRACT.md` exclusively.
> It must not implement security logic, risk calculations, Mosca, PQC recommendations,
> CBOM generation, or quantum classification.

---

## 1. QNetra in One Sentence

> The user gives QNetra cryptographic artifacts; QNetra discovers and proves what cryptography exists,
> turns the evidence into a canonical inventory, evaluates risk and quantum exposure, and guides
> the user toward a prioritized post-quantum migration plan.

---

## 2. Product Philosophy

QNetra is a **single enterprise cryptographic security dashboard** — not a collection of separate tools.

The user should experience one continuous analysis journey:

```
"What cryptography do I have?"
        ↓
"Where exactly is it?"
        ↓
"How confident is QNetra?"
        ↓
"How dangerous is it?"
        ↓
"Is it quantum vulnerable?"
        ↓
"What should I migrate?"
        ↓
"How urgently should I migrate it?"
        ↓
"What should my migration plan look like?"
```

Every screen answers a specific question. Every technical result must answer:

| Question | Design Responsibility |
| :--- | :--- |
| **WHAT?** | What was found? | Evidence clearly named |
| **WHERE?** | Where was it found? | File, line, location shown |
| **WHY?** | Why is QNetra confident? | Rationale text displayed |
| **HOW CONFIDENT?** | Confidence score visible | 0–100% or VERY_HIGH/HIGH/etc. |
| **HOW BAD?** | Risk severity prominent | CRITICAL/HIGH/MEDIUM/LOW with color |
| **QUANTUM?** | Quantum threat named | SHOR/GROVER/CLASSICALLY_BROKEN/SAFE |
| **WHAT NEXT?** | Actionable output | Recommendation or migration item |

---

## 3. The "Why" Behind Each Dashboard Section

Understanding why each section exists is essential. Each screen corresponds to one stage of a systematic security analysis:

```
Discovery
"What cryptography exists in my codebase?"
        ↓
Evidence
"Where exactly was it found and how was it detected?"
        ↓
Normalization
"What unique cryptographic assets do we actually have?"
        ↓
Classification
"What type of cryptography is this, and what quantum threat applies?"
        ↓
Risk
"Which assets matter most and which require immediate attention?"
        ↓
CBOM
"What is the complete, exportable cryptographic inventory?"
        ↓
Mosca / HNDL
"How urgent is migration given our data confidentiality requirements?"
        ↓
PQC Recommendations
"What standardized algorithms should replace the vulnerable ones?"
        ↓
Migration Planning
"What should we migrate first, and what should the roadmap look like?"
```

---

## 4. Navigation Structure

QNetra is a **single-application shell** with persistent top-level navigation.
Views are not separate applications — they are different lenses on the same scan.

```
QNetra
│
├── Overview          "How bad is my situation?"
├── Scan              "Start a new analysis"
├── Findings          "What scanner evidence exists?"
├── Crypto Assets     "What canonical cryptographic assets were discovered?"
├── Risk              "Which assets are most dangerous?"
├── CBOM              "Full cryptographic bill of materials"
├── Quantum Readiness "What is my quantum exposure?"
├── Mosca             "How urgent is migration?"
├── PQC Migration     "What should I migrate and in what order?"
└── Reports / Exports "Download audit artifacts"
```

All navigation items are disabled/empty until a scan completes. The dashboard should show
informative empty states rather than hiding navigation entirely.

---

## 5. End-to-End QNetra User Flow

### Visual Flow Diagram

```
User opens QNetra
       │
       ▼
┌─────────────────────────────────┐
│  EMPTY STATE / LANDING          │
│  No active scan                 │
│  "Scan your environment"        │
│  [Drop Zone / File Picker]      │
└──────────────┬──────────────────┘
               │ User drops files/folder
               ▼
┌─────────────────────────────────┐
│  ARTIFACT SELECTION             │
│  Show selected files summary    │
│  Validate + show metadata       │
│  [START SCAN]                   │
└──────────────┬──────────────────┘
               │ POST /artifacts/upload
               │ POST /scans
               ▼
┌─────────────────────────────────┐
│  SCAN PROGRESS                  │
│  Pipeline stage tracker         │
│  Live counts (files, findings)  │
│  GET /scans/{id}/progress       │
└──────────────┬──────────────────┘
               │ Poll until COMPLETED
               ▼
┌─────────────────────────────────┐
│  OVERVIEW DASHBOARD             │
│  Risk summary, top findings     │
│  Quantum exposure summary       │
│  Recommended next actions       │
└──────────────┬──────────────────┘
               │
       ┌───────┼──────────────────────────┐
       ▼       ▼                          ▼
  Findings  Crypto Assets              Risk View
  (Evidence) (Inventory)             (Priority)
       │       │
       ▼       ▼
  Single     Single Asset Detail
  Finding    (evidence + risk + quantum + PQC)
  Detail
               │
     ┌─────────┼──────────┐
     ▼         ▼          ▼
   CBOM    Quantum    Mosca
   View    Readiness  Assessment
                          │
                          ▼
                    PQC Migration
                    View + Roadmap
                          │
                          ▼
                  Reports / Export
```

---

### Stage-by-Stage Flow Documentation

---

#### Stage 1 — User Opens QNetra

**User Action:** Opens browser, navigates to QNetra URL.

**Frontend:**
- Show empty state landing screen.
- Primary headline: "Scan your cryptographic environment."
- Large, prominent drop zone: "Drag & drop files or folders here."
- Secondary buttons: `[ Select Files ]` and `[ Select Folder ]`.
- Supported types displayed: Repositories · Source Files · Binaries · Container Filesystems.
- Recent scans list (empty on first visit).

**API:** No API call yet.

**QNetra Processing:** None.

**Output:** Empty state UI displayed.

**Next UX:** User drags files or clicks file picker.

---

#### Stage 2 — Artifact Selection and Upload

**User Action:** Drags a folder (e.g. `my-payment-service/`) onto the drop zone,
or clicks "Select Folder" to browse. May also select individual binary files or source files.

**Frontend:**
- Show selected artifact summary:
  - Artifact name (folder/file name)
  - Artifact type (auto-detected or user-selectable)
  - Estimated file count (if known)
  - Size
- Optional: Allow user to set a scan name.
- Optional: Allow user to configure Mosca X/Y/Z parameters (with sensible defaults).
- Button: `[ START SCAN ]`
- Validation errors displayed inline if type is unsupported or size exceeds limits.

**API:**
- `POST /artifacts/upload` — uploads the file/archive.
- Poll `GET /artifacts/{artifact_id}` until `status == "READY"`.

**QNetra Processing:** Server receives and extracts the artifact into an isolated workspace.

**Output:** `artifact_id` ready for scan creation.

**Next UX:** User clicks `[ START SCAN ]`.

---

#### Stage 3 — Scan Creation and Queuing

**User Action:** Clicks `[ START SCAN ]`.

**Frontend:**
- Immediately transition to the Scan Progress screen.
- Show "Queued — waiting for worker."

**API:**
- `POST /scans` — returns `scan_id` immediately with `status: "QUEUED"`.

**QNetra Processing:** Scan job added to the background worker queue.

**Output:** `scan_id` retained for all subsequent API calls.

**Next UX:** Progress screen polls for status updates.

---

#### Stage 4 — Scan Progress

**User Action:** Watches progress. Can navigate away and return.

**Frontend:**
- Show named pipeline stages with status indicators:

```
Discovery               ✅ Completed    (4,281 files, 289 findings)
Normalization           ⏳ Running...
Classification          ⏸ Waiting
CBOM                    ⏸ Waiting
Risk Analysis           ⏸ Waiting
Quantum Analysis        ⏸ Waiting
Mosca Assessment        ⏸ Waiting
PQC Recommendations     ⏸ Waiting
Migration Planning      ⏸ Waiting
```

- Live counters (update via polling):
  - Files discovered: 4,281
  - Files scanned: 4,102
  - Raw findings: 289
  - Crypto assets: 0 (updates as normalization runs)

- Warning banner if non-fatal warnings present (e.g. "lief not installed — symbol inspection skipped").
- `[ Cancel Scan ]` button.
- Do NOT use a meaningless spinner. Every stage must have a label.

**API:** Poll `GET /scans/{scan_id}/progress` every 2–5 seconds until `status` is `COMPLETED`, `PARTIAL`, or `FAILED`.

**QNetra Processing:**
- DISCOVERY: `ScannerRouter` routes to `RepositoryScanner` / `ContainerScanner` / `BinaryScanner`.
- Subsequent stages: Core engines (Phase 2/3) run sequentially.

**Output:** `ScanResult` with `status: "COMPLETED"`.

**Next UX:** Auto-navigate to Overview Dashboard.

---

#### Stage 5 — Overview Dashboard

**User Action:** Views the high-level summary of their cryptographic posture.

**Frontend — Overview screen sections:**

**Section A: Critical Metrics Row**
```
Total Findings    289    |   Crypto Assets    83   |   Critical    12   |   Quantum Vulnerable    57
```

**Section B: Overall Risk Score**
- Large number: `88.5 / 100`
- Severity badge: `CRITICAL`
- Brief explanation: "Your environment contains multiple Shor-vulnerable asymmetric cryptographic assets."

**Section C: Severity Distribution**
- Four counts in descending severity: Critical | High | Medium | Low
- Optional: simple bar visualization (no heavy charting libraries required).

**Section D: Quantum Exposure Summary**
```
Shor-Vulnerable (asymmetric)    28 assets
Grover-Impacted (symmetric)     21 assets
Classically Broken              9 assets
Quantum-Resistant               25 assets
```

**Section E: Top 5 Critical Findings**
- Table: Algorithm | File | Line | Risk | Confidence
- Click row → opens Finding Detail.

**Section F: Mosca Status Banner** (if configured)
```
⚠ HNDL ALERT: X + Y (13 years) > Z (8 years)
Migration urgency: CRITICAL_IMMEDIATE
Deadline year: 2034
[View Full Mosca Assessment]
```

**Section G: Recommended Next Actions**
```
1. Migrate RSA-1024 in src/legacy/old_auth.py → ML-KEM-768 [CRITICAL]
2. Review AES-128-CBC usage in encryption_service.py → upgrade to AES-256-GCM [HIGH]
3. Replace SHA-1 checksums in deployment/verify.sh → SHA-256 [HIGH]
```

**API:**
- `GET /scans/{scan_id}/risk` — for risk summary.
- `GET /scans/{scan_id}/quantum` — for quantum exposure.
- `GET /scans/{scan_id}/findings?sort=confidence_score&order=desc&page_size=5` — for top findings.
- `GET /scans/{scan_id}/mosca/latest` — for Mosca banner.
- `GET /scans/{scan_id}/recommendations?severity=CRITICAL&page_size=3` — for next actions.

**QNetra Processing:** Data already computed by core engines during pipeline.

**Next UX:** User clicks into Findings, Assets, Risk, CBOM, Mosca, PQC tabs.

---

#### Stage 6 — Findings View

**User Action:** Navigates to "Findings" tab to investigate raw scanner evidence.

**Frontend:**
- Filterable, sortable table:

```
Algorithm | Category | Confidence | Scanner | Method | File | Line
```

- Filter bar: Algorithm · Category · Scanner · Method · Min Confidence
- Sort: Confidence (desc default) | Algorithm | Category | Line
- Pagination controls.

Each row is clickable → opens Finding Detail.

**API:** `GET /scans/{scan_id}/findings?...filters...`

---

#### Stage 7 — Finding Detail (Source Evidence View)

**User Action:** Clicks a finding row.

**Frontend — Finding Detail panel/drawer:**

```
src/auth/crypto_manager.py

  Line 31
  ─────────────────────────────────────────
  29  │ # Generate RSA keypair for auth
  30  │
  31  │ key = RSA.generate(2048, e=65537)   ◄── highlighted
  32  │
  33  │ cipher = AES.new(key[:16], AES.MODE_CBC)
  ─────────────────────────────────────────

  Detection                 RSA
  Algorithm Family          RSA (Asymmetric Public Key)
  Key Size                  2048 bits
  Library                   pycryptodome
  Scanner                   RepositoryScanner/PythonAnalyzer
  Discovery Method          AST (Abstract Syntax Tree)
  Confidence Score          0.95 (VERY HIGH)
  Confidence Rationale      AST-confirmed cryptographic API call (0.90) |
                            Library import corroborated (+0.05) |
                            Registry match (+0.02)

  Quantum Threat            SHOR_POLYNOMIAL_BREAK
  Risk Severity             CRITICAL (Score: 91)

  [View Crypto Asset →]     [View Recommendation →]
```

> [!IMPORTANT]
> The source evidence code viewer uses `location.snippet`, `location.start_line`, and `location.file_path`
> from the API. The frontend does NOT parse source files or implement detection logic.

**API:** `GET /scans/{scan_id}/findings/{finding_id}`

---

#### Stage 8 — Crypto Assets View

**User Action:** Navigates to "Crypto Assets" tab.

**Frontend:**
- This is the **normalized inventory** — each row represents a deduplicated canonical cryptographic asset.
- Table columns:

```
Algorithm | Primitive Type | Key Size | Library | Quantum | Risk Score | Severity | Location
```

- Filters: Algorithm · Primitive Type · Quantum Vulnerable · Severity · Library
- Sort: Risk Score (desc default) | Algorithm | Key Size
- Pagination.

Click → Asset Detail.

**API:** `GET /scans/{scan_id}/assets?...`

---

#### Stage 9 — Asset Detail (Full Context)

**User Action:** Clicks an asset row.

**Frontend — Asset Detail panel/drawer combining all related information:**

```
RSA-2048
Asymmetric Encryption · pycryptodome
src/auth/crypto_manager.py : Line 31

Identity
  Algorithm Family:    RSA
  Primitive Type:      ASYMMETRIC_ENCRYPTION
  Key Length:          2048 bits
  Mode:                —
  Curve:               —
  Library:             pycryptodome

Evidence (1 supporting finding)
  [AST] RSA.generate(2048)
  crypto_manager.py:31 · 0.95 confidence
  [View full evidence →]

Quantum Status
  ⚠ VULNERABLE — SHOR_POLYNOMIAL_BREAK
  Effective classical security: 112 bits
  Effective quantum security:   0 bits
  "Shor's algorithm factors the RSA modulus in O((log N)^3)
   polynomial time, recovering the private key unconditionally."

Risk
  Score:    91 / 100
  Severity: CRITICAL
  "RSA-2048 completely broken by Shor. Classical security of
   ~112 bits falls to 0 post-CRQC."

Mosca Relevance
  This asset contributes to your HNDL exposure.

PQC Recommendation
  Current:              RSA-2048
  Quantum problem:      Shor's algorithm (polynomial time break)
  Recommended:          ML-KEM-768 (NIST FIPS 203)
  Hybrid strategy:      X25519 + ML-KEM-768
  Migration complexity: MEDIUM
  Priority:             CRITICAL

  Steps:
  1. Abstract key encapsulation behind a CryptoService interface.
  2. Deploy hybrid X25519 + ML-KEM-768 for backward compatibility.
  3. Upgrade clients for larger ML-KEM ciphertexts (~1.1 KB).
  4. Remove RSA after all clients upgraded.

Migration Priority
  Bucket:     IMMEDIATE
  Timeframe:  Begin within current sprint/quarter
```

**API:** `GET /scans/{scan_id}/assets/{asset_id}` (returns all inline data above in one response).

---

#### Stage 10 — Risk View

**User Action:** Navigates to "Risk" tab.

**Frontend:**

**Section A: Overall Risk**
```
Risk Score: 88.5 / 100    CRITICAL
```

**Section B: Severity Distribution**
```
Critical    12
High        37
Medium      24
Low         10
```

**Section C: Quantum Exposure Breakdown**
```
Shor-vulnerable (asymmetric broken by quantum):    28
Grover-impacted (symmetric/hash halved):           21
Classically broken (broken today):                 9
Quantum-resistant / PQC-ready:                     25
```

**Section D: Ranked Asset List**
```
#   Algorithm    Key   File                      Risk   Severity
─────────────────────────────────────────────────────────────────
1   RSA-1024    1024   src/legacy/old_auth.py    100    CRITICAL
2   RSA-2048    2048   src/auth/crypto_manager.py 91    CRITICAL
3   ECDSA P-256  256   src/api/signing.py         87    CRITICAL
4   AES-128-CBC  128   src/enc/encservice.py      70    HIGH
5   SHA-1         —    deploy/verify.sh           65    HIGH
...
```

Click row → Asset Detail.

**API:** `GET /scans/{scan_id}/risk` + `GET /scans/{scan_id}/assets?sort=risk_score&order=desc`

---

#### Stage 11 — CBOM View

**User Action:** Navigates to "CBOM" tab.

**Frontend:**

**Header:** "Cryptographic Bill of Materials — CycloneDX 1.6"

**Summary row:**
```
Total Components: 83 | Quantum Vulnerable: 57 | Quantum-Resistant: 25
RSA: 14  ECC: 12  AES: 22  SHA: 18  KDF: 8  Other: 9
```

**Table (searchable, filterable, sortable):**
```
Name        Algorithm  Type          Key Size  Library         Quantum       Risk    Recommendation
RSA-2048    RSA        Asym Encrypt  2048 bit  pycryptodome    VULNERABLE    CRITICAL ML-KEM-768
AES-256-GCM AES        Sym Cipher    256 bit   PyCryptodome    RESISTANT     LOW      No change needed
SHA-1       SHA        Hash          —         hashlib         BROKEN        HIGH     SHA-256 / SHA-384
...
```

**Export buttons:**
```
[ Export CycloneDX JSON ]   [ Export CycloneDX XML ]   [ Export CSV ]
```

**API:** `GET /scans/{scan_id}/cbom` (dashboard) and `GET /scans/{scan_id}/cbom/export?format=json|xml`

---

#### Stage 12 — Quantum Readiness View

**User Action:** Navigates to "Quantum Readiness" tab.

**Frontend:**

**Quantum Readiness Score:**
```
31 / 100
LOW QUANTUM READINESS
```

**Section: Vulnerability Breakdown**

Displayed as four labeled count blocks with brief explanations (no jargon-only labels):

```
Shor-Vulnerable          28
Asymmetric cryptography completely broken by Shor's algorithm.
RSA, ECC, ECDSA, DH. A CRQC recovers private keys in polynomial time.

Grover-Impacted          21
Symmetric/hash algorithms with reduced quantum security.
AES-128 provides only 64-bit quantum security. Upgrade to AES-256.

Classically Broken        9
Already broken by classical attacks. MD5, SHA-1, DES.
Migrate immediately regardless of quantum concerns.

Quantum-Resistant        25
AES-256, SHA-512, and NIST-approved PQC algorithms.
No migration required for these assets.
```

**Section: Most Urgent Assets**
- Table sorted by quantum threat severity.

**API:** `GET /scans/{scan_id}/quantum`

---

#### Stage 13 — Mosca Assessment

**User Action:** Navigates to "Mosca" tab. Configures X, Y, Z sliders.

**Frontend:**

**Interactive panel:**

```
Data Shelf Life (X)         [ 10 ] years
  How long must your data remain confidential?

Migration Time (Y)          [  3 ] years
  How long will your enterprise migration take?

Quantum Threat Horizon (Z)  [  8 ] years
  When is a CRQC expected? (consensus: 2030–2035)

                    X + Y = 13 years
                    Z     =  8 years
                    ─────────────────
                    Gap   =  5 years   ⚠ VULNERABLE

Assessment Result:    CRITICAL_IMMEDIATE
HNDL Alert:           ACTIVE ⚠

"X + Y (13 years) exceeds Z (8 years) by 5 years.
 Adversaries harvesting encrypted traffic today will be able to decrypt
 it before your data loses confidentiality value.
 Migration must start immediately."

Deadline Year: 2034
```

**Harvest Now, Decrypt Later explanation always visible when `hndl_alert = true`.**

**API:**
- User adjusts sliders → `POST /scans/{scan_id}/mosca` on change (debounced 500ms).
- Initial load: `GET /scans/{scan_id}/mosca/latest`.

**QNetra Processing:** `core.mosca_engine` evaluates X + Y > Z. The frontend must not calculate this.

---

#### Stage 14 — PQC Migration View

**User Action:** Navigates to "PQC Migration" tab.

**Frontend:**

**Header section:**
```
57 assets require migration
12 CRITICAL — 21 HIGH — 16 MEDIUM — 8 LOW
```

**Roadmap timeline view:**

```
IMMEDIATE (12 assets)
Begin within current sprint/quarter
─────────────────────────────────────────────────────────────────
Asset                    Current    Recommended      Complexity
src/legacy/old_auth.py   RSA-1024   ML-KEM-768       HIGH
src/api/signing.py       ECDSA      ML-DSA-65        MEDIUM
...

NEXT 30 DAYS (21 assets)
Plan and initiate within 30 days
─────────────────────────────────────────────────────────────────
...

NEXT 90 DAYS (16 assets)
Schedule within 90 days
─────────────────────────────────────────────────────────────────
...

PLANNED (8 assets)
Include in next annual review
─────────────────────────────────────────────────────────────────
...
```

Click asset → opens Asset Detail with full PQC recommendation and migration steps.

**API:** `GET /scans/{scan_id}/migration`

---

#### Stage 15 — Reports and Exports

**User Action:** Navigates to "Reports / Exports" tab.

**Frontend:**

```
Export Options

[ Download Full Report (JSON)      ]   — Complete scan data envelope
[ Download Asset Inventory (CSV)   ]   — One row per crypto asset
[ Download CycloneDX CBOM (JSON)   ]   — Standards-compliant CBOM
[ Download CycloneDX CBOM (XML)    ]   — CycloneDX XML format
[ Download Executive Report (PDF)  ]   — Risk overview + roadmap
```

**API:** `GET /scans/{scan_id}/export?format=...` and `GET /scans/{scan_id}/cbom/export?format=...`

---

## 6. System Architecture Data Flow

```
Files / Repository / Binary / Container FS
                │
                ▼
        ScannerRouter
        (scanners/framework/router.py)
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
Repository  Container  Binary
Scanner     Scanner    Scanner
(Phase 1:  (Phase 1:  (Phase 1:
IMPLEMENTED IMPLEMENTED IMPLEMENTED)
       │        │        │
       └────────┴────────┘
                │
                ▼
         RawFinding v1.1.0
         (scanners/framework/models.py)

══════════════════════════════════════
  ↑ CURRENTLY IMPLEMENTED (Phase 1) ↑
══════════════════════════════════════
  ↓ PLANNED — Future Phases         ↓
══════════════════════════════════════

                ▼
      core.normalization         (Phase 2)
      RawFinding → CryptoAsset
                │
                ▼
      core.classification        (Phase 2)
      Primitive + Quantum Threat
                │
                ▼
      core.cbom_generator        (Phase 2)
      CycloneDX 1.6 CBOM
                │
                ▼
      core.risk_engine           (Phase 3)
      Deterministic Risk Scores
                │
                ▼
      core.quantum_analysis      (Phase 3)
      Shor / Grover / Classical
                │
                ▼
      core.mosca_engine          (Phase 3)
      X + Y > Z Urgency
                │
                ▼
      core.recommendation_engine (Phase 3)
      NIST PQC Replacements
                │
                ▼
      core.migration_planner     (Phase 3)
      Prioritized Roadmap
                │
                ▼
           FastAPI                (Phase 4)
        /api/v1/* endpoints
                │
                ▼
           Frontend               (Phase 4)
        React/Vue/etc application
```

---

## 7. Conceptual Example User Session

> [!NOTE]
> This is a **conceptual example** only — not hard-coded values.
> The purpose is to make the intended product experience immediately understandable.

**User uploads:** `my-payment-service/` (a Python + Java microservice)

**QNetra discovers:**
- `RSA.generate(2048)` in `src/auth/keys.py:42`
- `AES.new(key, AES.MODE_GCM)` in `src/encryption/service.py:78`
- `hashlib.sha256(...)` in multiple files
- `Signature.getInstance("SHA256withRSA")` in `PaymentService.java:31`
- `ECDSA on secp256r1` in `src/api/signing.py:19`

**User opens Findings tab:**
- Sees 289 raw findings from across the codebase.
- Filters to `algorithm=RSA` — sees 14 RSA-related findings.
- Clicks the `RSA.generate(2048)` at `src/auth/keys.py:42`.

**Finding Detail shows:**
```
src/auth/keys.py

  40  │ # Generate keypair for auth service
  41  │
  42  │ key = RSA.generate(2048, e=65537)   ◄── highlighted
  43  │
  44  │ return key

  Algorithm:     RSA
  Key Size:      2048 bits
  Confidence:    0.95 (VERY HIGH)
  Method:        AST (Abstract Syntax Tree parse)
  Reason:        Confirmed API call: RSA.generate(2048)
```

**User clicks "View Crypto Asset":**
- Asset detail for RSA-2048 opens.
- Risk Score: 91/100 — CRITICAL.
- Quantum: SHOR_POLYNOMIAL_BREAK — "A CRQC will recover the private key unconditionally."
- Recommendation: Replace with ML-KEM-768 (NIST FIPS 203). Hybrid: X25519 + ML-KEM-768.
- Migration priority: IMMEDIATE.

**User opens Mosca tab:**
- Sets X=10, Y=3, Z=8.
- Result: X+Y=13 > Z=8. HNDL alert active. Deadline year: 2034.

**User opens Migration tab:**
- `RSA.generate(2048)` at `src/auth/keys.py:42` appears in the IMMEDIATE bucket.
- Steps shown: abstract behind CryptoService → deploy hybrid → upgrade clients.

**User exports PDF report** for CISO review.

---

## 8. Frontend States and Error Handling

The UI must clearly handle every application state:

| State | UI Behaviour |
| :--- | :--- |
| **No scans** | Empty state landing with prominent drop zone |
| **Uploading** | Upload progress indicator |
| **Upload failure** | Inline error with retry option |
| **Queued** | "Waiting for worker" with cancel option |
| **Scanning** | Stage tracker with live counters |
| **Partial completion** | Warning banner, results valid, errors listed |
| **Completed** | Full dashboard available |
| **Scan failed** | Error message, error log, retry option |
| **No findings** | Explicit message: "No cryptographic artifacts detected" |
| **Analysis pending** | Each section shows "Analysis running..." skeleton |
| **API failure** | Structured error message, not a generic crash |
| **Empty dataset** | Empty state per section, never a blank white screen |

> [!IMPORTANT]
> **Never conflate these states:**
> - "No findings" (scan ran, found nothing) ≠ "Scan failed" ≠ "Analysis still running"
> Each must have its own distinct UI message.

---

## 9. Implementation Boundary (CRITICAL)

```
╔══════════════════════════════════════════════════════════╗
║  FRONTEND                                                ║
║  Presentation · Interaction · Filtering · Sorting        ║
║  Navigation · Visualization · API consumption           ║
╠══════════════════════════════════════════════════════════╣
║  BACKEND (FastAPI)                                       ║
║  API routes · Request validation                        ║
║  Scan orchestration · Job management                    ║
║  Calling core engines · File persistence               ║
╠══════════════════════════════════════════════════════════╣
║  CORE                                                    ║
║  Discovery · Normalization · Classification             ║
║  CBOM · Risk · Quantum analysis                        ║
║  Mosca · PQC recommendations · Migration intelligence  ║
╚══════════════════════════════════════════════════════════╝
```

**The frontend MUST NOT implement:**
- Risk score calculation
- Mosca inequality evaluation (X + Y > Z)
- Quantum threat classification (Shor / Grover)
- PQC algorithm selection
- CBOM generation
- Confidence score calculation
- Any scanner or core engine logic

All of the above are provided by the API (see `docs/10_API_CONTRACT.md`).

---

## 10. Frontend Architecture Guidance

### Technology Direction

- **Framework:** Modern JavaScript SPA (React, Vue, or Svelte — team's choice).
- **Type Safety:** TypeScript strongly recommended. Define API response types from `docs/10_API_CONTRACT.md`.
- **HTTP Client:** Dedicated API client module. All API calls go through this module. No ad-hoc fetch calls scattered through components.
- **State Management:** Centralize scan state. The current `scan_id` and scan status are global application state.

### Component Organization

```
src/
├── api/
│   ├── client.ts           # Base HTTP client + auth headers
│   ├── artifacts.ts        # /artifacts/* calls
│   ├── scans.ts            # /scans/* calls
│   ├── findings.ts         # /findings/* calls
│   ├── assets.ts           # /assets/* calls
│   ├── risk.ts             # /risk calls
│   ├── cbom.ts             # /cbom/* calls
│   ├── quantum.ts          # /quantum calls
│   ├── mosca.ts            # /mosca/* calls
│   ├── recommendations.ts  # /recommendations calls
│   └── migration.ts        # /migration calls
│
├── components/
│   ├── upload/             # Drop zone, file picker, artifact summary
│   ├── scan/               # Progress tracker, stage list
│   ├── findings/           # Findings table, finding detail, evidence viewer
│   ├── assets/             # Asset table, asset detail drawer
│   ├── risk/               # Risk overview, severity bars, asset ranking
│   ├── cbom/               # CBOM table, export buttons
│   ├── quantum/            # Quantum readiness, exposure breakdown
│   ├── mosca/              # Mosca sliders, X+Y>Z result panel
│   ├── migration/          # Roadmap timeline, migration items
│   ├── shared/             # Tables, badges, skeletons, error states
│   └── layout/             # App shell, navigation, sidebar
│
└── pages/
    ├── Overview.tsx
    ├── Scan.tsx
    ├── Findings.tsx
    ├── Assets.tsx
    ├── Risk.tsx
    ├── CBOM.tsx
    ├── QuantumReadiness.tsx
    ├── Mosca.tsx
    ├── PQCMigration.tsx
    └── Reports.tsx
```

### Reusable Components

- **`DataTable`** — generic sortable, filterable, paginated table consumed by all views.
- **`AssetDetailDrawer`** — slides in from right; shows full asset context including evidence, risk, recommendation.
- **`EvidenceViewer`** — renders `location.snippet` with the relevant line highlighted. Uses `start_line` and `file_path` from API.
- **`SeverityBadge`** — CRITICAL / HIGH / MEDIUM / LOW with consistent color scheme.
- **`ConfidenceMeter`** — displays `confidence_score` as a percentage with `confidence_level` label.
- **`QuantumStatusIndicator`** — SHOR_POLYNOMIAL_BREAK / GROVER_BIT_HALVING / RESISTANT / BROKEN with icon and label.
- **`ScanProgressTracker`** — stage list with per-stage status icons and live counters.
- **`ErrorState`** — structured error display: code + message + optional retry.
- **`EmptyState`** — per-section empty state with icon, label, and optional action.
- **`SkeletonRow`** — table row loading skeleton used while API data loads.

### Scan State Pattern

```typescript
interface ScanState {
  scanId: string | null;
  status: ScanStatus;
  currentStage: PipelineStage;
  progress: ScanProgress | null;
  error: string | null;
}
```

All pages that reference scan data read from this global state rather than fetching independently.

### Polling Strategy

- Poll `GET /scans/{scan_id}/progress` every 3 seconds while `status == "RUNNING"`.
- Stop polling on `COMPLETED`, `PARTIAL`, `FAILED`, or `CANCELLED`.
- Implement exponential backoff on API errors during polling (3s → 6s → 12s → stop).

---

## 11. Visual Direction

### Aesthetic

Enterprise cybersecurity — not a consumer app, not a toy dashboard.

**Character:**
- Technical and professional
- Information-dense but organized
- Evidence-driven
- Action-oriented and outcome-focused
- Trustworthy and serious

**Avoid:**
- Excessive gradients or neon cyberpunk styling
- Giant decorative hero cards
- Heavy animations that obscure data
- Meaningless placeholder charts
- Excessive rounded containers that waste space

**Prioritize:**
- Typography hierarchy (clear H1 → H2 → body → caption)
- Dense tabular data with clear column headers
- Color-coded severity consistently applied throughout
- Evidence visibility (code snippets presented cleanly)
- Actionable recommendation panels

### Color System (Guidance — confirm with design system)

- **Critical:** Red / high-urgency hue
- **High:** Orange
- **Medium:** Amber / yellow
- **Low:** Green / safe hue
- **Quantum Resistant:** Blue-green / calm hue
- **Background:** Dark neutral (near-black or dark grey preferred for security tooling)
- **Text:** High contrast on dark background
- **Accent:** Single brand color for interactive elements

> The project does not yet define exact hex values. The frontend should establish a design system
> early and apply it consistently. Record the chosen palette as a design decision.

### Typography

- Use a modern system font or a clean sans-serif (Inter, IBM Plex Sans, or Geist are suitable).
- Code snippets use a monospace font (Fira Code, JetBrains Mono, or Geist Mono).
- Avoid mixing more than two font families.

### Responsive Behaviour

- Primary target: Desktop / large screen (1280px+). Enterprise security tools are primarily desktop experiences.
- Secondary: 1024px support (laptop screens).
- Mobile is not a priority for the initial version but should not break catastrophically.
- Tables should support horizontal scroll on smaller screens.

---

## 12. Documentation Reference

The frontend developer must read these documents before implementation:

| Document | Purpose |
| :--- | :--- |
| `docs/10_API_CONTRACT.md` | Every API endpoint, request, response, and error shape |
| `docs/06_API_AND_DATA_CONTRACTS.md` | Internal RawFinding and CryptoAsset schemas for type reference |
| `docs/05_ALGORITHMS.md` | Understanding risk scoring, Mosca, and PQC logic (for rendering, not reimplementing) |
| `docs/09_KNOWLEDGE_BASE.md` | Domain knowledge: Shor, Grover, HNDL, Mosca, NIST PQC standards |
| `raw_findings.md` | Real scanner output demonstrating what RawFinding data looks like |
