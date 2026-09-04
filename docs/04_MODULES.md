# 04 — System Modules Specification

> **DOCUMENT PURPOSE:** Catalogs all technical modules in **QNetra**, detailing their responsibilities, inputs, outputs, dependencies, lifecycle status, and MVP priority.

---

## Module Catalog Summary

| Module Name | Path / Package | Status | MVP Priority | Primary Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **Discovery Framework** | `scanners.framework` | **Implemented** | High (P0) | Core contracts (`ScanTarget`, `ScanResult`, `RawFinding`), BaseScanner ABC, ScannerRouter |
| **Crypto Knowledge Registry** | `scanners.registry` | **Implemented** | High (P0) | Curated registries for algorithms, libraries, API mappings, regex patterns, binary symbols |
| **Shared Scanner Utils** | `scanners.utils` | **Implemented** | High (P0) | Robust directory traversal, language classification, binary string extraction |
| **Repository Scanner** | `scanners.repository` | **Implemented** | High (P0) | Multi-language source code scanner (Python AST, JS, Java, C/C++ analyzers) |
| **Container Scanner** | `scanners.container` | **Implemented** | High (P0) | Extracted container filesystem, shared lib, package metadata (dpkg, npm, pip), & TLS config scanner |
| **Binary Scanner** | `scanners.binary` | **Implemented** | High (P0) | Static ELF/PE binary scanner (lief symbol tables, string patterns, multi-signal correlation) |
| **Normalization Layer** | `core.normalization` | **Implemented** | High (P0) | Translating raw findings into canonical `CryptoAsset` models (UUIDv5 identity, confidence aggregation) |
| **Classification Engine** | `core.classification` | **Implemented** | High (P0) | Deterministic classical + quantum threat classification of `CryptoAsset` objects |
| **CBOM Generator** | `core.cbom_generator` | **Implemented** | High (P0) | Generating CycloneDX 1.6+ JSON/XML CBOM artifacts from `CryptoAsset` list |
| **Quantum Risk Engine** | `core.risk_engine` | **Implemented** | High (P0) | Computing deterministic quantum vulnerability risk scores (0–100) and severity ratings |
| **Mosca Assessment Engine** | `core.mosca_engine` | **Implemented** | High (P0) | Evaluating $X+Y > Z$ Mosca inequality, HNDL exposure, migration urgency, and deadline calculation |
| **PQC Recommendation Engine**| `core.recommendation_engine`| **Implemented** | High (P0) | Mapping vulnerable assets to NIST PQC/Hybrid replacements (FIPS 203/204/205) |
| **Backend API Gateway** | `backend.api` | Planned | High (P0) | REST API endpoints for scans, data retrieval, and export |
| **Storage Manager** | `backend.storage` | Planned | Medium (P1) | Session cache & lightweight historical scan persistence |
| **Web Dashboard UI** | `frontend` | Planned | High (P0) | Interactive visualization, charts, and report exploration |
| **Report Export Engine** | `backend.export_service` | Planned | Medium (P1) | Generating downloadable PDF, CSV, and CBOM packages |

---

## Detailed Module Specifications

### 1. Discovery Framework & Router
* **Module Identifier:** `MOD-001`
* **Path:** `scanners/framework`
* **Purpose:** Provides base interfaces, router dispatching, and canonical discovery contracts.
* **Responsibility:**
  * Define `BaseScanner` abstract lifecycle (`scan()`, `_execute_scan()`, `_validate_target()`).
  * Route targets via `ScannerRouter` using explicit `target_type` or magic byte & directory heuristics.
  * Define canonical models: `ScanTarget`, `ScanResult`, `RawFinding` (v1.1.0), `ScanOptions`, `ScanStatistics`.
* **Inputs:** `ScanTarget`.
* **Outputs:** `ScanResult` containing `List[RawFinding]`.
* **Dependencies:** Standard library `pathlib`, `uuid`, `logging`, `pydantic`.
* **Related Data Contracts:** `ScanTarget`, `ScanResult`, `RawFinding` ([docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md)).
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_framework/test_models.py`, `tests/test_framework/test_router.py`.

---

### 2. Cryptographic Knowledge Registry
* **Module Identifier:** `MOD-002`
* **Path:** `scanners/registry`
* **Purpose:** Single source of truth for cryptographic domain knowledge across all scanners.
* **Responsibility:**
  * Centralize known crypto algorithms, NIST quantum threat levels, and key sizes (`crypto_algorithms.py`).
  * Map package names, import aliases, and shared library names to canonical libraries (`crypto_libraries.py`).
  * Map library API calls to algorithms and parameter extraction rules (`crypto_api_map.py`).
  * Curate compiled regex patterns for algorithms, key material, protocols, and PQC (`crypto_patterns.py`).
  * Curate binary symbol definitions for OpenSSL, libsodium, mbedTLS, and Windows CNG (`crypto_symbols.py`).
* **Inputs:** Algorithm/library/symbol queries.
* **Outputs:** `AlgorithmEntry`, `LibraryEntry`, `APIEntry`, `CryptoPattern`, `SymbolEntry`.
* **Dependencies:** Standard library `re`, `dataclasses`.
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** Integrated throughout scanner unit and integration tests.

---

### 3. Repository Scanner
* **Module Identifier:** `MOD-003`
* **Path:** `scanners/repository`
* **Purpose:** Discovers cryptographic assets across source code repositories in multiple languages.
* **Responsibility:**
  * Perform language-aware repository directory traversal with exclusion filters (`traversal.py`).
  * Python AST analysis (Alg-01): imports, function calls, literal key size & mode extraction (`python_analyzer.py`).
  * JavaScript/TypeScript analysis: require/import detection, crypto API matching (`javascript_analyzer.py`).
  * Java analysis: JCA/JCE `getInstance()` factory detection, imports, key material (`java_analyzer.py`).
  * C/C++ analysis: OpenSSL/mbedTLS/libsodium `#include` and EVP API call parsing (`cpp_analyzer.py`).
  * Calculate deterministic multi-signal confidence scores (`confidence.py`).
* **Inputs:** `ScanTarget` (directory path).
* **Outputs:** `ScanResult` with `List[RawFinding]`.
* **Dependencies:** Python stdlib `ast`, `re`, `pathlib`.
* **Related Data Contracts:** `RawFinding` ([docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md)).
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_repository/` (Python, JS, Java, C++ analyzers).

---

### 4. Container Scanner
* **Module Identifier:** `MOD-004`
* **Path:** `scanners/container`
* **Purpose:** Inspects extracted container filesystem directories for installed crypto libraries and certificates.
* **Responsibility:**
  * Inspect Linux shared library locations (`/usr/lib`, `/usr/local/lib`, `/lib64`) for known crypto `.so` files (`filesystem.py`).
  * Inspect package manager metadata: dpkg (`/var/lib/dpkg/status`), pip (`site-packages`), npm (`node_modules`) (`package_inspector.py`).
  * Inspect SSL/TLS configuration paths (`/etc/ssl`, `/etc/pki`) for certificates and keys (`filesystem.py`).
  * Populate `container_context` on all generated findings.
* **Inputs:** `ScanTarget` (extracted container directory path).
* **Outputs:** `ScanResult` with `List[RawFinding]`.
* **Dependencies:** Standard library `pathlib`, `json`, `re`.
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_container/test_container_scanner.py`.

---

### 5. Binary Scanner
* **Module Identifier:** `MOD-005`
* **Path:** `scanners/binary`
* **Purpose:** Static inspection of compiled binary files (ELF, PE) for cryptographic symbols and strings.
* **Responsibility:**
  * Detect binary format via magic bytes (ELF, PE, Mach-O, Archive) (`format_detector.py`).
  * Extract ASCII strings and match crypto version strings, TLS cipher suites, and PEM headers (`string_analyzer.py`).
  * Static symbol table parsing via `lief` for imported crypto functions (`symbol_inspector.py`).
  * Multi-signal correlation, deduplication, and library summary generation (`correlation.py`).
* **Inputs:** `ScanTarget` (binary file path).
* **Outputs:** `ScanResult` with `List[RawFinding]`.
* **Dependencies:** `lief` (optional, graceful fallback to string analysis), standard library `struct`, `re`.
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_binary/test_binary_scanner.py`.

---

### 5. Normalization Layer
* **Module Identifier:** `MOD-005`
* **Path:** `core/normalization`
* **Purpose:** Converts varied scanner outputs into the standard canonical `CryptoAsset` schema.
* **Responsibility:**
  * Normalize algorithm naming variants (e.g. `AES_256_GCM`, `AES/GCM/NoPadding` -> canonical `AES-256-GCM`).
  * Group and deduplicate findings across multi-pass scanners and source locations (`deduplicator.py`).
  * Deterministically compute RFC 4122 UUIDv5 canonical asset IDs using the `asset.qnetra.io` namespace.
  * Formulate multi-signal aggregated confidence scores with transparent rationales (`confidence_aggregator.py`).
  * Preserve complete audit traceability to all supporting raw findings (`supporting_finding_ids`, `supporting_findings`).
* **Inputs:** `List[RawFinding]`.
* **Outputs:** `List[CryptoAsset]`.
* **Dependencies:** Standard library `uuid`, `re`, `pydantic`.
* **Related Data Contracts:** `RawFinding`, `CryptoAsset` ([docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md)).
* **Status:** Implemented (`v1.0.0`)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_normalization.py` (19 tests, 82% coverage).

---

### 6. CBOM Generator
* **Module Identifier:** `MOD-006`
* **Path:** `core/cbom_generator`
* **Purpose:** Generates standards-compliant Cryptographic Bill of Materials artifacts.
* **Responsibility:**
  * Format normalized `CryptoAsset` records into CycloneDX 1.6+ Cryptography Extension JSON.
  * Attach cryptographic properties (algorithm, key length, mode, padding, quantum security level).
* **Inputs:** `List[CryptoAsset]`, project metadata.
* **Outputs:** CycloneDX 1.6 CBOM JSON object and exportable file.
* **Dependencies:** JSON serializer, CycloneDX schema validator.
* **Related Data Contracts:** `CycloneDX_CBOM_JSON`.
* **Status:** Implemented (`v1.0.0` — Milestone 2.3)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_cbom_generator.py` (116 tests, 92% coverage).

---

### 7. Classification Engine
* **Module Identifier:** `MOD-007`
* **Path:** `core/classification`
* **Purpose:** Categorizes discovered cryptographic primitives and analyzes key parameters.
* **Responsibility:**
  * Classify assets into functional categories: Asymmetric PKC, Symmetric Cipher, Hash Function, KDF, MAC, Digital Signature, Protocol/TLS.
  * Tag quantum threat mechanism: Shor-vulnerable (polynomial break) vs. Grover-impacted (effective bit halving).
* **Inputs:** `List[CryptoAsset]`.
* **Outputs:** Classified `CryptoAsset` records enriched with quantum threat tags.
* **Dependencies:** Cryptographic Knowledge Base.
* **Related Data Contracts:** `CryptoAsset`.
* **Status:** Implemented (`v1.0.0` — Milestone 2.2)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_classification.py` (54 tests, 85% core coverage).

---

### 8. Quantum Risk Engine
* **Module Identifier:** `MOD-008`
* **Path:** `core/risk_engine`
* **Purpose:** Computes deterministic, auditable quantum vulnerability risk scores.
* **Responsibility:**
  * Evaluate algorithm family, key size, and deprecation status.
  * Calculate numerical risk scores (0–100) and severity ratings (Critical, High, Medium, Low).
  * Generate itemized risk justifications.
* **Inputs:** Classified `List[CryptoAsset]`.
* **Outputs:** `RiskAssessmentReport` (aggregate score, asset risk ratings, high-priority vulnerabilities).
* **Dependencies:** Pure mathematical scoring logic ([docs/05_ALGORITHMS.md](docs/05_ALGORITHMS.md)).
* **Related Data Contracts:** `RiskAssessmentReport`.
* **Status:** Implemented (`v1.0.0` — Milestone 3.1)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_risk_engine.py` (41 tests, 98% coverage).

---

### 9. Mosca Assessment Engine
* **Module Identifier:** `MOD-009`
* **Path:** `core/mosca_engine`
* **Purpose:** Implements Michele Mosca's $X+Y > Z$ migration urgency and HNDL analysis engine.
* **Responsibility:**
  * Evaluate Mosca inequality: Data Shelf Life ($X$) + Migration Time ($Y$) > Quantum Threat Horizon ($Z$).
  * Calculate exposure gap $(X+Y) - Z$ and migration deadline (years from assessment date).
  * Classify Harvest Now, Decrypt Later (HNDL) exposure tiers (CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN).
  * Derive migration urgency (IMMEDIATE/URGENT/PLANNED/MONITOR/NOT_REQUIRED/UNKNOWN).
  * Handle NOT_APPLICABLE assets (Library, Random) and NIST-approved PQC (ML-KEM, ML-DSA, SLH-DSA).
  * Reject invalid duration inputs (negative, NaN, infinite).
  * Enforce no-fabrication: protected lifetime (X) has no silent default — returns UNKNOWN without it.
* **Inputs:** Classified `CryptoAsset`, optional `MoscaInput` (X, Y, Z overrides, HNDL flag, assessment date).
* **Outputs:** `MoscaAssessment` (per-asset), `MoscaAssessmentReport` (repository aggregate).
* **Dependencies:** `core.models` (CryptoAsset, PrimitiveType).
* **Related Data Contracts:** `MoscaAssessmentReport` (docs/06 §2.4), `MoscaAssessment`.
* **Status:** Implemented (`v1.0.0` — Milestone 3.2)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_mosca_engine.py` (95 tests: inequality boundary, HNDL, urgency, determinism, no-mutation, full pipeline).

---

### 10. PQC & Hybrid Recommendation Engine
* **Module Identifier:** `MOD-010`
* **Path:** `core/recommendation_engine`
* **Purpose:** Delivers deterministic, explainable NIST PQC and Hybrid migration recommendations for each classified CryptoAsset.
* **Responsibility:**
  * Map Shor-vulnerable public-key assets to standardized NIST PQC algorithms:
    * Key exchange/KEM (ECDH, DH, RSA-KEM) → ML-KEM (NIST FIPS 203) via Hybrid X25519+ML-KEM-768.
    * Digital signatures (ECDSA, DSA, Ed25519, RSA-sign) → ML-DSA (NIST FIPS 204); ECDSA/Ed25519 → Hybrid Ed25519+ML-DSA-65.
    * Certificates → ML-DSA Hybrid with CA infrastructure guidance.
  * Recommend hash family upgrades for Grover-impacted hash functions (SHA-256 → SHA-384) as CLASSICAL_UPGRADE (not DIRECT_PQC).
  * Recommend symmetric key-length upgrades for Grover-impacted ciphers (AES-128 → AES-256) and broken ciphers (DES/3DES → AES-256-GCM) as CLASSICAL_UPGRADE (not DIRECT_PQC).
  * Explicitly distinguish post-quantum migration (DIRECT_PQC, HYBRID) from classical cryptographic strengthening (CLASSICAL_UPGRADE).
  * Detect already-PQC assets (ML-KEM, ML-DSA, SLH-DSA) and return ALREADY_PQC (no unnecessary replacement).
  * Return NO_MIGRATION_REQUIRED for non-applicable assets (Library, Random, Protocol).
  * Return UNKNOWN for unrecognized algorithms without fabricating recommendations.
  * Apply deterministic parameter selection policy (ML-KEM-768 default; ML-KEM-1024 for high-security RSA≥3072/ECC≥384).
  * Maintain strict Risk Score and Mosca Urgency independence (recommendation routing never uses risk_score).
  * Enforce no-fabrication: unknown algorithms receive UNKNOWN status, not fabricated recommendations.
  * Batch results sorted deterministically by asset_id.
* **Inputs:** Classified `CryptoAsset` list (with primitive_type, algorithm, key_length_bits, curve populated).
* **Outputs:** `PQCRecommendation` (per-asset), `PQCRecommendationReport` (repository aggregate).
* **Dependencies:** `core.models` (CryptoAsset, PrimitiveType).
* **Related Data Contracts:** `PQCRecommendationReport` (docs/06 §2.5), `PQCRecommendation`.
* **Key Files:**
  * `core/recommendation_engine/models.py` — `PQCRecommendationType` (6 outcomes including `CLASSICAL_UPGRADE`), `MigrationComplexity`, `PQCRecommendation`, `AssetRecommendationDetail`, `PQCRecommendationReport` dataclasses.
  * `core/recommendation_engine/knowledge.py` — PQC algorithm definitions, mapping tables, parameter selection policy, hybrid constructions, rationale templates.
  * `core/recommendation_engine/mapper.py` — Pure stateless `map_asset_to_recommendation()` routing function.
  * `core/recommendation_engine/engine.py` — `RecommendationEngine`: `recommend()`, `recommend_all()`, `generate_report()` (pure functional, no mutation).
  * `core/recommendation_engine/__init__.py` — Public API exports.
* **Architecture Invariants:**
  * `recommend()` and `recommend_all()` are PURELY FUNCTIONAL — never mutate input CryptoAsset.
  * Recommendation routing is independent of `risk_score` and Mosca urgency fields.
  * Classical strengthening (hashes, symmetric ciphers) is strictly classified as `CLASSICAL_UPGRADE`, never `DIRECT_PQC`.
  * Only finalized NIST PQC standards used as primary recommendations: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).
  * Hybrid constructions: only X25519+ML-KEM-768 and Ed25519+ML-DSA-65 explicitly supported.
  * No datetime.now(), no non-deterministic logic.
* **Status:** Implemented (`v1.1.0` — Milestone 3.3 Corrective Pass)
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_core/test_recommendation_engine.py` (118 tests: algorithm mapping, classical upgrade distinction, regression test, PQC detection, hybrid constructions, parameter selection, explainability, independence, determinism, no-mutation, serialization, batch, full pipeline 289→147→147→147→147→147).

---

### 11. Backend API Gateway
* **Module Identifier:** `MOD-011`
* **Path:** `backend/api`
* **Purpose:** Provides RESTful API endpoints for target management, scan initiation, and result retrieval.
* **Responsibility:**
  * Handle HTTP requests (`/api/scan`, `/api/cbom`, `/api/mosca`, `/api/export`).
  * Orchestrate background scan tasks.
* **Inputs:** HTTP Requests.
* **Outputs:** JSON API Responses conforming to [docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md).
* **Dependencies:** FastAPI / Pydantic.
* **Status:** Planned
* **MVP Priority:** High (P0)
* **Tests:** `tests/test_api.py`.

---

### 12. Storage Manager
* **Module Identifier:** `MOD-012`
* **Path:** `backend/storage`
* **Purpose:** Manages scan result persistence and audit history.
* **Responsibility:**
  * In-memory caching for active scan sessions.
  * Local file/SQLite persistence for historical scan comparisons.
* **Inputs:** Scan records and CBOMs.
* **Outputs:** Retrieved scan histories and diffs.
* **Dependencies:** SQLite / File I/O.
* **Status:** Planned
* **MVP Priority:** Medium (P1)
* **Tests:** `tests/test_storage.py`.

---

### 13. Web Dashboard UI
* **Module Identifier:** `MOD-013`
* **Path:** `frontend`
* **Purpose:** Interactive user interface for security architects, CISOs, and developers.
* **Responsibility:**
  * Render executive summary risk scorecards and heatmaps.
  * Provide searchable, filterable CBOM table explorer.
  * Provide interactive Mosca timeline slider widget.
  * Display step-by-step PQC remediation guides.
* **Inputs:** API responses from Backend Gateway.
* **Outputs:** Interactive user interface.
* **Dependencies:** Modern Web UI stack (React / Vite).
* **Status:** Planned
* **MVP Priority:** High (P0)
* **Tests:** Component unit tests & end-to-end user journey tests.

---

### 14. Report Export Engine
* **Module Identifier:** `MOD-014`
* **Path:** `backend/export_service`
* **Purpose:** Compiles scan results into downloadable audit and compliance deliverables.
* **Responsibility:**
  * Generate CycloneDX 1.6 JSON CBOM downloads.
  * Generate CSV asset inventories.
  * Generate executive summary PDF audit reports.
* **Inputs:** `CompleteScanResult`.
* **Outputs:** Downloadable file streams.
* **Dependencies:** PDF/CSV generation libraries.
* **Status:** Planned
* **MVP Priority:** Medium (P1)
* **Tests:** `tests/test_export_service.py`.
