# 10 — API Contract Specification

> **DOCUMENT PURPOSE:** The authoritative API design contract for the QNetra FastAPI backend and
> its consuming frontend. Defines every endpoint, request/response shape, error convention, and
> design principle that governs the interface between `core/`, `backend/`, and `frontend/`.
>
> **CONTRACT STATUS:** Frozen — Implementation Pending (Phase 4)
>
> **GOVERNANCE RULE:** This contract must remain consistent with `docs/06_API_AND_DATA_CONTRACTS.md`
> (internal schemas), `docs/02_SYSTEM_ARCHITECTURE.md` (layer boundaries), and `PROJECT_RULES.md`.
> No developer may silently alter these contracts without following Section 18 governance protocol.

---

## 1. API Design Principles

| # | Principle |
| :--- | :--- |
| **P-01** | The frontend communicates exclusively through this API. It must never import `core/`, `scanners/`, or any Python module directly. |
| **P-02** | FastAPI routes must remain thin: validate → invoke service → return response. All cryptographic intelligence lives in `core/`. |
| **P-03** | The API layer must not implement any analysis logic. Backend orchestration calls core engines. |
| **P-04** | API responses expose stable, versioned contracts — never internal implementation details. |
| **P-05** | `RawFinding` (scanner evidence) and `CryptoAsset` (normalized asset) are distinct concepts and must remain distinguishable in every API response. |
| **P-06** | All list APIs support pagination and filtering. No API returns an unlimited unfiltered list. |
| **P-07** | Long-running scans are asynchronous. Client receives `scan_id` immediately; polls for status. |
| **P-08** | All errors are structured and predictable (see Section 16). HTTP codes follow REST conventions. |
| **P-09** | API versioning is applied from the start via the URL prefix `/api/v1/`. |
| **P-10** | Evidence fields (`snippet`, `byte_offset`, `rationale`) must allow the frontend to display evidence without parsing scanner internals. |
| **P-11** | The contract accommodates enterprise-scale scans (thousands of files, hundreds of assets). |
| **P-12** | Timestamps: ISO-8601 UTC. IDs: UUID strings. Enums: UPPERCASE strings. Nulls: explicit `null`. |

---

## 2. Base URL and Versioning

```
Base URL:    /api/v1
Full prefix: http://{host}:{port}/api/v1
```

All endpoints in this document are relative to `/api/v1`.

---

## 3. User Journey — API Flow Map

```
Stage 1   Upload artifacts
           POST /artifacts/upload
           GET  /artifacts/{artifact_id}
          ↓
Stage 2   Create scan
           POST /scans  →  scan_id
          ↓
Stage 3   Monitor scan progress
           GET  /scans/{scan_id}
           GET  /scans/{scan_id}/progress
          ↓
Stage 4   Raw findings (scanner evidence)
           GET  /scans/{scan_id}/findings
           GET  /scans/{scan_id}/findings/{finding_id}
          ↓
Stage 5   Normalized crypto assets
           GET  /scans/{scan_id}/assets
           GET  /scans/{scan_id}/assets/{asset_id}
          ↓
Stage 6   Risk analysis
           GET  /scans/{scan_id}/risk
          ↓
Stage 7   CBOM
           GET  /scans/{scan_id}/cbom
           GET  /scans/{scan_id}/cbom/export?format=json|xml
          ↓
Stage 8   Quantum analysis
           GET  /scans/{scan_id}/quantum
          ↓
Stage 9   Mosca assessment (interactive X/Y/Z)
           POST /scans/{scan_id}/mosca
           GET  /scans/{scan_id}/mosca/latest
          ↓
Stage 10  PQC recommendations
           GET  /scans/{scan_id}/recommendations
          ↓
Stage 11  Migration roadmap
           GET  /scans/{scan_id}/migration
          ↓
Stage 12  Exports
           GET  /scans/{scan_id}/export?format=json|csv|pdf
```

---

## 4. Core Concepts: Artifact, Target, Scan

Three separate concepts govern how QNetra receives input. They must not be merged into one object.

| Concept | Definition |
| :--- | :--- |
| **Artifact** | A single uploaded file or directory archive. Has its own identity, metadata, and lifecycle. |
| **Target** | A logical entity being analysed (e.g. "my-payment-service"). References one or more Artifacts and carries a `target_type`. |
| **Scan** | A specific execution of the analysis pipeline against one Target with specific scan options. |

> [!IMPORTANT]
> A Target may be reused across multiple Scans. An Artifact has a retention lifecycle independent of Scans.

---

## 5. Artifacts API

### `POST /artifacts/upload`

Upload a file or folder archive for scanning.

**Request:** `multipart/form-data`

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `file` | file | Yes | The uploaded file. Folders must be submitted as a ZIP archive. |
| `name` | string | No | Human-readable name |
| `artifact_type` | enum | No | `SOURCE_REPOSITORY`, `BINARY`, `CONTAINER_FS`, `MANIFEST`, `ARCHIVE` |
| `description` | string | No | Optional description |

**Response: `201 Created`**

```json
{
  "artifact_id": "a1f93bc1-1234-4c28-98e3-a4c3e21199a0",
  "name": "my-payment-service",
  "artifact_type": "SOURCE_REPOSITORY",
  "description": null,
  "filename": "my-payment-service.zip",
  "file_size_bytes": 2457600,
  "file_count": null,
  "status": "READY",
  "uploaded_at": "2026-09-02T10:00:00Z",
  "expires_at": "2026-09-09T10:00:00Z"
}
```

**Artifact Status Enum:** `UPLOADING` | `PROCESSING` | `READY` | `FAILED` | `EXPIRED`

**Validation:**
- Maximum file size: 500 MB recommended (configurable).
- Supported archive: `.zip`. Directories are received as zips.
- Server extracts into an isolated temporary workspace.
- Default retention: 7 days before automatic deletion.

### `GET /artifacts/{artifact_id}`

Returns artifact metadata and status. Same response shape as POST above.

### `DELETE /artifacts/{artifact_id}`

Delete artifact and extracted filesystem. **Response: `204 No Content`**

---

## 6. Scans API — Async Pipeline

### `POST /scans`

Initiate a new cryptographic analysis scan.

**Request Body:**

```json
{
  "name": "Payment Service Audit Q4 2026",
  "artifact_id": "a1f93bc1-1234-4c28-98e3-a4c3e21199a0",
  "target_type": "REPOSITORY",
  "options": {
    "enable_ast": true,
    "enable_regex": true,
    "enable_import_analysis": true,
    "exclude_patterns": ["node_modules", ".git", "dist", "build"],
    "max_file_size_bytes": 10485760
  },
  "mosca_params": {
    "data_shelf_life_years_x": 10.0,
    "migration_time_years_y": 3.0,
    "quantum_threat_horizon_years_z": 8.0
  }
}
```

**Response: `202 Accepted`**

```json
{
  "scan_id": "b2d93bc1-5678-4c28-98e3-b4c3e21199b0",
  "name": "Payment Service Audit Q4 2026",
  "artifact_id": "a1f93bc1-1234-4c28-98e3-a4c3e21199a0",
  "status": "QUEUED",
  "created_at": "2026-09-02T10:01:00Z",
  "started_at": null,
  "completed_at": null,
  "current_stage": "QUEUED",
  "progress": null
}
```

### `GET /scans/{scan_id}`

Full scan status, stage progress, and counts.

**Response: `200 OK`**

```json
{
  "scan_id": "b2d93bc1-5678-4c28-98e3-b4c3e21199b0",
  "status": "COMPLETED",
  "current_stage": "COMPLETED",
  "duration_seconds": 43.1,
  "progress": {
    "stages": [
      {"name": "DISCOVERY",          "status": "COMPLETED"},
      {"name": "NORMALIZATION",      "status": "COMPLETED"},
      {"name": "CLASSIFICATION",     "status": "COMPLETED"},
      {"name": "CBOM",               "status": "COMPLETED"},
      {"name": "RISK_ANALYSIS",      "status": "COMPLETED"},
      {"name": "QUANTUM_ANALYSIS",   "status": "COMPLETED"},
      {"name": "MOSCA_ANALYSIS",     "status": "COMPLETED"},
      {"name": "PQC_ANALYSIS",       "status": "COMPLETED"},
      {"name": "MIGRATION_PLANNING", "status": "COMPLETED"}
    ],
    "files_discovered": 4281,
    "files_scanned": 4102,
    "raw_findings_count": 289,
    "assets_count": 83
  },
  "errors": [],
  "warnings": ["Symbol table inspection skipped: lief not installed."]
}
```

**Scan Status Enum:**

| Value | Description |
| :--- | :--- |
| `QUEUED` | Waiting for worker slot |
| `RUNNING` | Pipeline actively processing |
| `COMPLETED` | All stages complete |
| `PARTIAL` | Completed with non-fatal errors |
| `FAILED` | Fatal failure — results unreliable |
| `CANCELLED` | Cancelled by user |

**Pipeline Stage Enum and their Core Modules:**

| Stage | Core Module | Phase |
| :--- | :--- | :--- |
| `DISCOVERY` | `scanners.*` | **Phase 1 — Implemented** |
| `NORMALIZATION` | `core.normalization` | Phase 2 — Planned |
| `CLASSIFICATION` | `core.classification` | Phase 2 — Planned |
| `CBOM` | `core.cbom_generator` | Phase 2 — Planned |
| `RISK_ANALYSIS` | `core.risk_engine` | Phase 3 — Planned |
| `QUANTUM_ANALYSIS` | `core.quantum_analysis` | Phase 3 — Planned |
| `MOSCA_ANALYSIS` | `core.mosca_engine` | Phase 3 — Planned |
| `PQC_ANALYSIS` | `core.recommendation_engine` | Phase 3 — Planned |
| `MIGRATION_PLANNING` | `core.migration_planner` | Phase 3 — Planned |

### `GET /scans/{scan_id}/progress`

Lightweight poll-only endpoint returning stage and counts.

```json
{
  "scan_id": "b2d93bc1-5678-4c28-98e3-b4c3e21199b0",
  "status": "RUNNING",
  "current_stage": "NORMALIZATION",
  "files_scanned": 3812,
  "raw_findings_count": 267,
  "assets_count": 0
}
```

### `GET /scans` — List Scans

Query parameters: `page`, `page_size`, `status`

### `POST /scans/{scan_id}/cancel`

Request cancellation. **Response: `202 Accepted`** or `409 Conflict` if already complete.

---

## 7. Raw Findings API

Raw Findings are the direct output of the scanner — unprocessed cryptographic evidence.
They correspond to `RawFinding v1.1.0` defined in `docs/06_API_AND_DATA_CONTRACTS.md`.

> [!IMPORTANT]
> `RawFinding` (scanner evidence) and `CryptoAsset` (normalized entity) are DIFFERENT concepts.
> They must be kept distinguishable in all API responses and never merged into a single flat object.

### `GET /scans/{scan_id}/findings`

**Query Parameters:**

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `page`, `page_size` | int | Pagination (default 50, max 200) |
| `sort` | string | `confidence_score`, `artifact_category`, `suspected_algorithm` |
| `order` | string | `asc` or `desc` |
| `algorithm` | string | Filter by `suspected_algorithm` (e.g. `RSA`) |
| `category` | string | Filter by `artifact_category` |
| `scanner` | string | Filter by `scanner_name` |
| `method` | string | Filter by `discovery_method` |
| `min_confidence` | float | Minimum confidence score (0.0–1.0) |

**Response: `200 OK`**

```json
{
  "data": [
    {
      "finding_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "scanner_name": "RepositoryScanner/PythonAnalyzer",
      "scanner_version": "1.0.0",
      "discovery_method": "AST",
      "raw_symbol": "RSA.generate(2048)",
      "suspected_algorithm": "RSA",
      "artifact_category": "ASYMMETRIC_PKC",
      "library_hint": "pycryptodome",
      "key_size_hint": 2048,
      "mode_hint": null,
      "curve_hint": null,
      "location": {
        "file_path": "src/auth/crypto_manager.py",
        "start_line": 31,
        "end_line": 31,
        "byte_offset": null,
        "snippet": "key = RSA.generate(2048, e=65537)"
      },
      "confidence_score": 0.95,
      "confidence_level": "VERY_HIGH",
      "confidence_rationale": "AST-confirmed cryptographic API call (0.90) | Library import corroborated (+0.05) | Registry match (+0.02)",
      "binary_format": null,
      "symbol_name": null,
      "container_context": null,
      "discovered_at": "2026-09-02T10:01:08Z",
      "asset_id": null
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_items": 289,
    "total_pages": 6
  }
}
```

**Source evidence structure** — used by the frontend to render the evidence viewer:

```
location.file_path    → relative file path to display
location.start_line   → line number to highlight
location.snippet      → code excerpt for inline display
confidence_rationale  → human-readable detection reason
```

> [!NOTE]
> **Planned enhancement:** Phase 2 normalization will enrich `location.snippet` with a ±3 line
> context window around the detected line, enabling richer source evidence display.

### `GET /scans/{scan_id}/findings/{finding_id}`

Returns one raw finding with full evidence. Same schema as list item above.

---

## 8. Crypto Assets API

Normalized assets are canonical cryptographic entities derived from raw findings by `core.normalization`.
They correspond to `CryptoAsset` defined in `docs/06_API_AND_DATA_CONTRACTS.md`.

> **Implementation note:** Available only after Phase 2 normalization is implemented.
> The contract is defined now for frontend build stability.

### `GET /scans/{scan_id}/assets`

**Query Parameters:**

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `page`, `page_size` | int | Pagination |
| `sort` | string | `risk_score`, `confidence_score`, `algorithm`, `key_length_bits` |
| `order` | string | `asc` or `desc` |
| `algorithm` | string | Filter by algorithm |
| `primitive_type` | string | Filter by functional type |
| `quantum_vulnerable` | bool | Filter for vulnerable / safe |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `library` | string | Filter by implementation library |

**Response: `200 OK`**

```json
{
  "data": [
    {
      "asset_id": "c1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "primitive_type": "ASYMMETRIC_ENCRYPTION",
      "key_length_bits": 2048,
      "curve": null,
      "mode": null,
      "padding": null,
      "implementation_library": "pycryptodome",
      "location": {
        "file_path": "src/auth/crypto_manager.py",
        "start_line": 31,
        "end_line": 31,
        "snippet": "key = RSA.generate(2048, e=65537)"
      },
      "quantum_vulnerable": true,
      "quantum_threat_type": "SHOR_POLYNOMIAL_BREAK",
      "confidence_score": 0.95,
      "confidence_level": "VERY_HIGH",
      "risk_score": 91,
      "risk_severity": "CRITICAL",
      "supporting_finding_ids": ["f81d4fae-7dec-11d0-a765-00a0c91e6bf6"],
      "recommendation_id": "r1a93e3d-3b1a-4c28-98e3-a4c3e21199a0"
    }
  ],
  "pagination": {"page": 1, "page_size": 50, "total_items": 83, "total_pages": 2}
}
```

### `GET /scans/{scan_id}/assets/{asset_id}`

Full asset detail including inline supporting finding evidence and recommendation summary.

```json
{
  "asset_id": "c1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
  "algorithm": "RSA",
  "primitive_type": "ASYMMETRIC_ENCRYPTION",
  "key_length_bits": 2048,
  "quantum_vulnerable": true,
  "quantum_threat_type": "SHOR_POLYNOMIAL_BREAK",
  "risk_score": 91,
  "risk_severity": "CRITICAL",
  "risk_rationale": "RSA-2048 is completely vulnerable to Shor's algorithm. Classical security of ~112 bits falls to 0 post-CRQC.",
  "supporting_findings": [
    {
      "finding_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "discovery_method": "AST",
      "raw_symbol": "RSA.generate(2048)",
      "location": {"file_path": "src/auth/crypto_manager.py", "start_line": 31, "snippet": "key = RSA.generate(2048, e=65537)"},
      "confidence_score": 0.95,
      "confidence_rationale": "AST-confirmed cryptographic API call..."
    }
  ],
  "quantum_analysis": {
    "threat_classification": "SHOR_POLYNOMIAL_BREAK",
    "effective_classical_bits": 112,
    "effective_quantum_bits": 0,
    "grover_impact": false,
    "shor_impact": true,
    "explanation": "Shor's algorithm factors the RSA modulus in O((log N)^3) polynomial time, recovering the private key unconditionally. No key-size mitigation exists."
  },
  "recommendation": {
    "recommendation_id": "r1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
    "primary_pqc_replacement": "ML-KEM-768",
    "pqc_standard": "NIST FIPS 203",
    "hybrid_scheme": "X25519 + ML-KEM-768",
    "migration_complexity": "MEDIUM",
    "priority": "CRITICAL"
  }
}
```

---

## 9. Risk API

Risk scores are computed deterministically by `core.risk_engine` (Phase 3). The frontend must not replicate the calculation.

### `GET /scans/{scan_id}/risk`

```json
{
  "scan_id": "b2d93bc1-5678-4c28-98e3-b4c3e21199b0",
  "overall_risk_score": 88.5,
  "overall_severity": "CRITICAL",
  "total_assets": 83,
  "vulnerable_assets": 67,
  "severity_distribution": {
    "CRITICAL": 12, "HIGH": 37, "MEDIUM": 24, "LOW": 10
  },
  "quantum_exposure": {
    "shor_vulnerable_count": 28,
    "grover_impacted_count": 21,
    "classically_broken_count": 9,
    "quantum_resistant_count": 25
  },
  "top_risk_assets": [
    {
      "asset_id": "c1a93e3d-...",
      "algorithm": "RSA",
      "key_length_bits": 1024,
      "risk_score": 100,
      "risk_severity": "CRITICAL",
      "risk_rationale": "RSA-1024 is below NIST minimum and broken by Shor's algorithm.",
      "location": {"file_path": "src/legacy/old_auth.py", "start_line": 88}
    }
  ],
  "calculated_at": "2026-09-02T10:01:25Z"
}
```

**Risk Scoring Formula (from `docs/05_ALGORITHMS.md`):**

| Algorithm Class | Base Score |
| :--- | :--- |
| Shor-vulnerable (RSA, ECC, DH, ECDSA) | 90 |
| Grover-impacted symmetric < 256 bits | 60 |
| Classically broken (MD5, SHA-1, DES) | 100 |
| Quantum-resistant classical (AES-256, SHA-512) | 20 |
| NIST-approved PQC | 0 |

**Severity Tiers:** Critical (80–100) | High (60–79) | Medium (30–59) | Low (0–29)

---

## 10. CBOM API

### `GET /scans/{scan_id}/cbom`

Dashboard-friendly paginated inventory. Suitable for the CBOM table view.

**Query Parameters:** `page`, `page_size`, `algorithm`, `quantum_status`, `severity`

```json
{
  "cbom_version": "CycloneDX-1.6",
  "generated_at": "2026-09-02T10:01:20Z",
  "summary": {
    "total_components": 83,
    "quantum_vulnerable": 57,
    "quantum_resistant": 25,
    "unknown": 1,
    "algorithm_families": {"RSA": 14, "ECC": 12, "AES": 22, "SHA": 18, "KDF": 8, "OTHER": 9}
  },
  "data": [
    {
      "bom_ref": "crypto-asset-001",
      "asset_id": "c1a93e3d-...",
      "name": "RSA-2048",
      "algorithm": "RSA",
      "algorithm_family": "RSA",
      "primitive_type": "ASYMMETRIC_ENCRYPTION",
      "key_size_bits": 2048,
      "mode": null, "curve": null,
      "implementation_library": "pycryptodome",
      "location": {"file_path": "src/auth/crypto_manager.py", "start_line": 31},
      "quantum_status": "VULNERABLE",
      "quantum_threat": "SHOR_POLYNOMIAL_BREAK",
      "risk_score": 91,
      "risk_severity": "CRITICAL",
      "pqc_recommendation": "ML-KEM-768 (NIST FIPS 203)"
    }
  ],
  "pagination": {"page": 1, "page_size": 50, "total_items": 83, "total_pages": 2}
}
```

### `GET /scans/{scan_id}/cbom/export?format=json`
### `GET /scans/{scan_id}/cbom/export?format=xml`

Downloads the full CycloneDX 1.6-compliant CBOM document. Response is a file stream.
JSON format follows the schema in `docs/06_API_AND_DATA_CONTRACTS.md § 3`.

---

## 11. Quantum Analysis API

### `GET /scans/{scan_id}/quantum`

```json
{
  "quantum_readiness_score": 31,
  "summary": {
    "total_assets": 83, "shor_vulnerable": 28,
    "grover_impacted": 21, "classically_broken": 9, "quantum_resistant": 25
  },
  "assets": [
    {
      "asset_id": "c1a93e3d-...",
      "algorithm": "RSA",
      "key_length_bits": 2048,
      "quantum_vulnerable": true,
      "quantum_threat_type": "SHOR_POLYNOMIAL_BREAK",
      "effective_classical_bits": 112,
      "effective_quantum_bits": 0,
      "shor_impact": true,
      "grover_impact": false,
      "explanation": "Shor's algorithm factors RSA moduli in O((log N)^3). A CRQC recovers the private key unconditionally."
    }
  ]
}
```

**`quantum_threat_type` Values:**

| Value | Description |
| :--- | :--- |
| `SHOR_POLYNOMIAL_BREAK` | Asymmetric algorithm completely broken by Shor |
| `GROVER_BIT_HALVING` | Symmetric/hash security halved by Grover |
| `CLASSICALLY_BROKEN` | Broken by classical cryptanalysis |
| `QUANTUM_RESISTANT` | PQC or sufficiently large symmetric key |

---

## 12. Mosca API

The Mosca API evaluates X + Y > Z. All calculations are performed by `core.mosca_engine`.
**The frontend must not implement Mosca calculations.**

### `POST /scans/{scan_id}/mosca`

Submit configurable X, Y, Z and receive the assessment.

**Request:**
```json
{"data_shelf_life_years_x": 10.0, "migration_time_years_y": 3.0, "quantum_threat_horizon_years_z": 8.0}
```

**Response: `200 OK`**
```json
{
  "parameters": {"data_shelf_life_years_x": 10.0, "migration_time_years_y": 3.0, "quantum_threat_horizon_years_z": 8.0},
  "result": {
    "x_plus_y": 13.0,
    "is_vulnerable": true,
    "exposure_gap_years": 5.0,
    "deadline_year": 2034,
    "urgency_rating": "CRITICAL_IMMEDIATE",
    "hndl_alert": true
  },
  "explanation": {
    "summary": "X + Y (13.0 years) exceeds Z (8.0 years) by 5.0 years. Migration must start now.",
    "x_explanation": "Data requires 10 years of confidentiality. Harvested traffic will be retained this long.",
    "y_explanation": "Enterprise migration is estimated to take 3 years.",
    "z_explanation": "CRQC projected within 8 years (consensus estimate).",
    "hndl_note": "Active Harvest Now, Decrypt Later exposure. Adversaries may already be archiving traffic."
  },
  "assessed_at": "2026-09-02T10:31:00Z"
}
```

### `GET /scans/{scan_id}/mosca/latest`

Returns the most recently computed Mosca assessment for this scan.

**`urgency_rating` Values:** `CRITICAL_IMMEDIATE` | `HIGH_PLANNED` | `MODERATE`

---

## 13. PQC Recommendations API

### `GET /scans/{scan_id}/recommendations`

**Query Parameters:** `page`, `page_size`, `severity`, `asset_id`

```json
{
  "data": [
    {
      "recommendation_id": "r1a93e3d-...",
      "asset_id": "c1a93e3d-...",
      "current_primitive": "RSA-2048",
      "current_usage_context": "ASYMMETRIC_ENCRYPTION",
      "quantum_threat": "SHOR_POLYNOMIAL_BREAK",
      "threat_explanation": "RSA is completely broken by Shor's algorithm. CRQC recovers the private key unconditionally.",
      "primary_pqc_replacement": "ML-KEM-768",
      "pqc_standard": "NIST FIPS 203",
      "secondary_pqc_alternative": "ML-KEM-1024",
      "recommended_hybrid_scheme": "X25519 + ML-KEM-768",
      "migration_strategy": "HYBRID_TRANSITION",
      "migration_complexity": "MEDIUM",
      "priority": "CRITICAL",
      "guidance_steps": [
        "Abstract key encapsulation behind a CryptoService interface.",
        "Deploy hybrid X25519 + ML-KEM-768 for backward compatibility.",
        "Upgrade clients for larger ML-KEM ciphertext payloads (~1.1 KB).",
        "Remove RSA after all clients upgraded."
      ],
      "rationale": "ML-KEM-768 provides NIST FIPS 203 post-quantum key encapsulation with ~128-bit quantum security."
    }
  ],
  "pagination": {"page": 1, "page_size": 50, "total_items": 57, "total_pages": 2}
}
```

**PQC Mapping Matrix (from `docs/05_ALGORITHMS.md`):**

| Classical | Primary Replacement | Standard | Hybrid Scheme |
| :--- | :--- | :--- | :--- |
| RSA Key Exchange | ML-KEM-768 | FIPS 203 | X25519 + ML-KEM-768 |
| ECDH / X25519 | ML-KEM-768 | FIPS 203 | ECDH + ML-KEM-768 |
| RSA Signature | ML-DSA-65 | FIPS 204 | RSA + ML-DSA-65 |
| ECDSA | ML-DSA-44/65 | FIPS 204 | ECDSA + ML-DSA-65 |
| AES-128 | AES-256-GCM | — | Increase key length |
| SHA-1/SHA-224 | SHA-384/SHA-512 | — | Migrate to SHA-2/3 |

---

## 14. Migration Roadmap API

### `GET /scans/{scan_id}/migration`

```json
{
  "generated_at": "2026-09-02T10:01:45Z",
  "summary": {"total_items": 57, "immediate_count": 12, "short_term_count": 21, "medium_term_count": 16, "planned_count": 8},
  "roadmap": {
    "IMMEDIATE": {
      "label": "Immediate",
      "description": "Critical quantum-vulnerable assets requiring migration without delay.",
      "timeframe_guidance": "Begin within current sprint/quarter",
      "items": [
        {
          "migration_id": "m1a93e3d-0001",
          "asset_id": "c1a93e3d-...",
          "current_algorithm": "RSA-1024",
          "recommended_algorithm": "ML-KEM-768",
          "hybrid_scheme": "X25519 + ML-KEM-768",
          "priority": "CRITICAL",
          "risk_score": 100,
          "location": {"file_path": "src/legacy/old_auth.py", "start_line": 88},
          "risk_reduction_estimate": "Eliminates Shor vulnerability. Eliminates HNDL risk.",
          "migration_complexity": "HIGH",
          "dependencies": [],
          "reason": "RSA-1024 below NIST minimum threshold, fully broken by Shor's algorithm."
        }
      ]
    },
    "SHORT_TERM": {"label": "Next 30 Days", "items": []},
    "MEDIUM_TERM": {"label": "Next 90 Days", "items": []},
    "PLANNED":    {"label": "Planned",       "items": []}
  }
}
```

> [!NOTE]
> Timeframe buckets are recommendation outputs from `core.migration_planner`. They are guidance,
> not legally binding deadlines. The API must not imply contractual timelines.

---

## 15. Export API

### `GET /scans/{scan_id}/export?format={json|csv|pdf}`

| Format | MIME Type | Content |
| :--- | :--- | :--- |
| `json` | `application/json` | Complete scan envelope: findings + assets + risk + CBOM + recommendations |
| `csv` | `text/csv` | Asset inventory + risk scores, one row per asset |
| `pdf` | `application/pdf` | Executive summary: risk overview + CBOM + migration roadmap |

**Response:** File stream with `Content-Disposition: attachment; filename="qnetra-report-{scan_id}.{format}"`

---

## 16. Pagination Convention

All list endpoints:

```json
{
  "data": [...],
  "pagination": {"page": 1, "page_size": 50, "total_items": 289, "total_pages": 6}
}
```

Defaults: `page=1`, `page_size=50`. Maximum `page_size`: 200.

---

## 17. Error Response Convention

```json
{
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "Scan b2d93bc1-... does not exist.",
    "details": null
  }
}
```

Validation error (422):

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request body failed validation.",
    "details": [
      {"field": "mosca_params.data_shelf_life_years_x", "error": "must be > 0"},
      {"field": "artifact_id", "error": "not a valid UUID"}
    ]
  }
}
```

**HTTP Status Codes:**

| Status | Condition |
| :--- | :--- |
| `200 OK` | Successful retrieval |
| `201 Created` | Resource created |
| `202 Accepted` | Async operation accepted |
| `204 No Content` | Successful deletion |
| `400 Bad Request` | Invalid parameters |
| `404 Not Found` | Resource not found |
| `409 Conflict` | State conflict |
| `413 Payload Too Large` | Artifact exceeds size limit |
| `422 Unprocessable Entity` | Pydantic validation failure |
| `500 Internal Server Error` | Unexpected server error |
| `503 Service Unavailable` | Worker / analysis engine unavailable |

---

## 18. Complete Endpoint Map

```
ARTIFACTS
  POST   /artifacts/upload
  GET    /artifacts/{artifact_id}
  DELETE /artifacts/{artifact_id}

SCANS
  POST   /scans
  GET    /scans
  GET    /scans/{scan_id}
  GET    /scans/{scan_id}/progress
  POST   /scans/{scan_id}/cancel

FINDINGS
  GET    /scans/{scan_id}/findings
  GET    /scans/{scan_id}/findings/{finding_id}

ASSETS
  GET    /scans/{scan_id}/assets
  GET    /scans/{scan_id}/assets/{asset_id}

RISK
  GET    /scans/{scan_id}/risk

CBOM
  GET    /scans/{scan_id}/cbom
  GET    /scans/{scan_id}/cbom/export?format=json|xml

QUANTUM
  GET    /scans/{scan_id}/quantum

MOSCA
  POST   /scans/{scan_id}/mosca
  GET    /scans/{scan_id}/mosca/latest

PQC
  GET    /scans/{scan_id}/recommendations

MIGRATION
  GET    /scans/{scan_id}/migration

EXPORTS
  GET    /scans/{scan_id}/export?format=json|csv|pdf
```

---

## 19. Implementation Status Table

| Endpoint Group | Status | Phase Requirement |
| :--- | :--- | :--- |
| `/artifacts/*` | Planned | Phase 4 |
| `/scans` create/status/list | Planned | Phase 4 |
| `/scans/{id}/findings` | Planned (Phase 1 data ready) | Phase 4 |
| `/scans/{id}/assets` | Planned | Phase 2 + Phase 4 |
| `/scans/{id}/risk` | Planned | Phase 3 + Phase 4 |
| `/scans/{id}/cbom` | Planned | Phase 2 + Phase 4 |
| `/scans/{id}/quantum` | Planned | Phase 3 + Phase 4 |
| `/scans/{id}/mosca` | Planned | Phase 3 + Phase 4 |
| `/scans/{id}/recommendations` | Planned | Phase 3 + Phase 4 |
| `/scans/{id}/migration` | Planned | Phase 3 + Phase 4 |
| `/scans/{id}/export` | Planned | Phase 4 |

> The Phase 1 scanner produces `RawFinding v1.1.0` data that is directly consumable by the
> `/findings` endpoint once Phase 4 persistence and API are implemented.

---

## 20. API Contract Governance Protocol

1. **Impact Analysis:** Identify all affected frontend components, backend routes, core consumers.
2. **Document Update:** Propose change with version annotation in this file.
3. **ADR:** Record decision in `docs/08_DECISIONS_AND_LOG.md`.
4. **Synchronized Implementation:** API, core, and frontend update in the same release.
5. **Backward Compatibility:** Existing consumers must not break without a migration path.
