# PROJECT_CONTEXT.md — QNetra AI Agent Handoff Document

> **HIGH-DENSITY AGENT ONBOARDING GUIDE**  
> **Purpose:** This document is the fast-entry handoff guide for any AI coding agent or developer joining the QNetra project. Read this file first to understand the system context, architecture, current state, key decisions, and immediate next steps without reading the entire repository.

---

## 1. Project Identity

* **Project Name:** QNetra
* **SIH Problem Statement ID:** 26164
* **Problem Statement Title:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
* **Core Objective:** Build a passive, automated, enterprise-grade cryptographic discovery and risk analysis tool that identifies cryptographic assets across code repositories, container filesystems, and compiled binaries, generates a standardized Cryptographic Bill of Materials (CBOM), assesses quantum computing vulnerabilities (Shor's and Grover's algorithms), models migration urgency via Mosca's Theorem ($X + Y > Z$), and provides actionable Post-Quantum Cryptography (PQC) and hybrid transition roadmaps.
* **Executive Summary:** QNetra discovers where and how cryptography is used in enterprise software, evaluates its vulnerability to quantum adversaries (e.g. Harvest Now, Decrypt Later threats), and provides organizations with a deterministic, compliance-ready path to NIST FIPS 203/204/205 post-quantum standards.

---

## 2. The Core Problem Being Solved

1. **Cryptographic Blind Spots:** Organizations do not know what algorithms, key lengths, cipher modes, certificates, or hardcoded keys exist across their software supply chains.
2. **Quantum Obsolescence:** Shor's algorithm completely breaks public-key cryptography (RSA, ECDSA, ECDH, DSA) once Cryptographically Relevant Quantum Computers (CRQCs) emerge. Grover's algorithm halves symmetric cipher key security (AES-128 becomes 64-bit security).
3. **Harvest Now, Decrypt Later (HNDL):** Adversaries intercept encrypted traffic today to decrypt later. If Data Shelf Life ($X$) + Migration Time ($Y$) > Quantum Horizon ($Z$), data is already compromised today.
4. **PQC Migration Readiness:** Enterprises need a CycloneDX 1.6+ CBOM inventory to systematically replace vulnerable primitives with NIST-standardized algorithms (ML-KEM, ML-DSA, SLH-DSA).

### End-to-End Intelligence Pipeline

```text
Technical Assets (Repos, Containers, Binaries)
        ↓
Cryptographic Discovery Layer                       [✓ IMPLEMENTED - Phase 1]
  (AST Analysis, Regex, Symbols, Package Metadata)
        ↓
Raw Findings (RawFinding v1.1.0 Contract)           [✓ IMPLEMENTED - Phase 1]
        ↓
Normalization & Deduplication                       [✓ IMPLEMENTED - Phase 2]
        ↓
Canonical CryptoAsset Models (v1.2.0)               [✓ IMPLEMENTED - Phase 2]
        ↓
Classification & Parameter Enrichment               [✓ IMPLEMENTED - Phase 2]
        ↓
CBOM Generation (CycloneDX 1.6 JSON/XML)            [✓ IMPLEMENTED - Phase 2]
        ↓
Quantum Risk Engine (Deterministic Scoring)         [✓ IMPLEMENTED - Phase 3]
        ↓
Mosca Migration Urgency Engine (X + Y > Z)          [✓ IMPLEMENTED - Phase 3]
        ↓
PQC & Hybrid Recommendation Engine                  [✓ IMPLEMENTED - Phase 3]
        ↓
FastAPI Backend & Interactive Web UI Dashboard      [○ PLANNED - Phase 4]
```

---

## 3. Current Architecture Snapshot

```text
┌────────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION & ROUTING LAYER (scanners.framework)                     │
│    - ScanTarget (Path, TargetType, ScanOptions)                        │
│    - ScannerRouter (Magic-byte detection + directory heuristics)       │
│    - BaseScanner ABC (Standard lifecycle, error isolation, timing)     │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ dispatches to
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
│ Repository Scanner   │   │ Container Scanner    │   │ Binary Scanner       │
│ (scanners.repository)│   │ (scanners.container) │   │ (scanners.binary)    │
│ - Python AST parser  │   │ - .so shared lib scan│   │ - ELF/PE magic check │
│ - JS/TS import & API │   │ - dpkg/pip/npm pkgs  │   │ - ASCII strings scan │
│ - Java getInstance() │   │ - /etc/ssl certs/keys│   │ - lief symbol tables │
│ - C/C++ OpenSSL EVP  │   │                      │   │ - Signal correlation │
└──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ OUTPUT CONTRACT: ScanResult containing List[RawFinding] (v1.1.0)       │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. CANONICAL NORMALIZATION LAYER (core.normalization — Phase 2 Done)   │
│    Translates RawFinding -> Canonical CryptoAsset Schema (UUIDv5)      │
│    - AlgorithmNormalizer: JCA, EVP, aliases, parameters               │
│    - Deduplicator: Proximity & component clustering                   │
│    - ConfidenceAggregator: Monotonic S_max + bonus formula            │
└─────────────────────────────────────┬──────────────────────────────────┘
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. DOWNSTREAM INTELLIGENCE & CBOM ENGINES (core.* — Phase 2 & 3)        │
│    - CycloneDX 1.6 CBOM Generator (core.cbom_generator)                │
│    - Classification Engine (core.classification)                       │
│    - Quantum Risk Calculator (core.risk_engine)                        │
│    - Mosca Inequality Simulator (core.mosca_engine)                    │
│    - PQC Transition Recommender (core.recommendation_engine)           │
└────────────────────────────────────────────────────────────────────────┘
```

> **CORE ARCHITECTURAL INVARIANT (RULE-004):**  
> Scanners emit `RawFinding` records. Downstream modules (`core.*`, `backend.*`, `frontend`) **MUST NEVER** depend on scanner internals. All downstream processing operates strictly on normalized `CryptoAsset` models.

---

## 4. Current Development Status

```text
CURRENT PHASE:
Phase 3 — Downstream Intelligence Engines (Risk, Mosca, Recommendations) (COMPLETE ✅)

CURRENT SUB-PHASE:
All Phase 3 Milestones Complete. Transitioning to Phase 4: FastAPI Backend & Interactive Web Dashboard.

LAST COMPLETED:
Phase 3 Milestone 3.3 PQC Recommendation Engine (2026-09-04):
  - Implemented core/recommendation_engine/__init__.py (public API exports)
  - Implemented core/recommendation_engine/models.py (PQCRecommendationType, MigrationComplexity, PQCRecommendation, AssetRecommendationDetail, PQCRecommendationReport)
  - Implemented core/recommendation_engine/knowledge.py (NIST FIPS 203/204/205 algorithm defs, parameter selection policy, hybrid constructions, rationale templates)
  - Implemented core/recommendation_engine/mapper.py (pure stateless map_asset_to_recommendation() routing by algorithm family + primitive type)
  - Implemented core/recommendation_engine/engine.py (RecommendationEngine: recommend, recommend_all, generate_report — pure functional, no mutation, no risk_score coupling)
  - Created tests/test_core/test_recommendation_engine.py (104 tests, 93% coverage, 100% engine/models/knowledge/__init__)
  - Full pipeline validated: 289 RawFindings → 147 Assets → 147 Classified → 147 Risk → 147 Mosca → 147 Recommendations
  - Full test suite: 512 passed, 1 skipped, 0 failed
  - ADR DEC-016: Table-driven routing, Risk independence, No-fabrication policy
  - Updated docs/04, docs/05 (Alg-08), docs/07, docs/08 (DEC-016), PROJECT_CONTEXT.md, current_prompt_update.md

PREVIOUSLY COMPLETED:
Phase 3 Milestone 3.1 Risk Engine (2026-09-04):
  - Implemented core/risk_engine/__init__.py, models.py, knowledge.py, scorer.py, engine.py
  - Created tests/test_core/test_risk_engine.py (41 tests, 98% risk engine coverage)
  - Full pipeline verification: 289 RawFindings -> 147 Assets -> 147 Classified -> 147 Risk Assessments (overall 83.8 CRITICAL)
Phase 2 Milestone 2.3 CBOM Generator (2026-09-04):
  - CycloneDX 1.6 JSON/XML serialization, validator, mapper, models (116 tests, 92% coverage)
Phase 2 Classification Subsystem & Normalization Hardening (2026-09-03):
  - ClassificationEngine with orthogonal dimensions & no-fabrication policy (54 tests)
Phase 2 Normalization & CryptoAsset Generation (2026-09-03):
  - Canonical CryptoAsset domain model, AlgorithmNormalizer, Deduplicator (UUIDv5), ConfidenceAggregator
Phase 1 Discovery Layer Implementation & Validation:
  - BaseScanner, ScannerRouter, registries, Repository/Container/Binary scanners, 77 tests (289 real findings)

CURRENTLY IMPLEMENTING:
Phase 3 Milestone 3.3: NIST PQC & Hybrid Recommendation Engine (core.recommendation_engine).

NEXT LOGICAL STEP:
Phase 3 Milestone 3.3: NIST FIPS 203/204/205 PQC Recommendation Engine.
  - Algorithmic replacement mapping (RSA → ML-KEM, ECDSA → ML-DSA, etc.)
  - Hybrid transition scheme recommendations.
  - Per-asset PQCRecommendation dataclass.
  - Repository-level PQCRecommendationReport.
```

---

## 5. What Is Already Implemented

### ✓ IMPLEMENTED & TESTED (Phase 1 & Phase 2 Milestone 2.1)
* **Framework Core (`scanners/framework`):** `BaseScanner` ABC, `ScannerRouter` with magic-byte dispatch, `ScanTarget`, `ScanResult`, `ScanOptions`, `ScanStatistics`, `RawFinding` (v1.1.0 with float confidence and `to_v1_dict()`).
* **Cryptographic Knowledge Registries (`scanners/registry`):**
  * `crypto_algorithms.py`: 30+ algorithms with quantum threat classification and key boundaries.
  * `crypto_libraries.py`: Multi-ecosystem package, import, and shared library alias mappings.
  * `crypto_api_map.py`: API signatures with argument extraction rules (key size, mode, curve).
  * `crypto_patterns.py`: Compiled regex patterns with comment vs. code confidence weights.
  * `crypto_symbols.py`: Binary symbol database for OpenSSL, libsodium, mbedTLS, and Windows CNG.
* **Shared Utilities (`scanners/utils`):** Recursive directory traversal, file size limits, language detection, and streaming binary string extraction.
* **Repository Scanner (`scanners/repository`):**
  * Python AST analyzer: Function call parsing, literal argument extraction (RSA key size, AES mode), import tracking.
  * JavaScript/TypeScript analyzer: `require()` / ES6 `import` detection, Node.js crypto API parsing.
  * Java analyzer: JCA/JCE `getInstance()` factory pattern recognition.
  * C/C++ analyzer: OpenSSL/mbedTLS/libsodium include and EVP API call parsing.
  * Multi-signal confidence engine: Deterministic, explainable scoring (0.0 to 1.0).
* **Container Scanner (`scanners/container`):** Shared library inspection (`/usr/lib`, `/lib64`), package manager parsing (`dpkg`, `pip`, `npm`), and TLS config/cert inspection (`/etc/ssl`, `/etc/pki`).
* **Binary Scanner (`scanners/binary`):** Magic-byte format detection (ELF, PE, Mach-O), printable ASCII string extraction, static symbol table parsing via `lief`, and multi-signal finding correlation.
* **Core Normalization & Classification Engines (`core/`, `core/normalization/`, `core/classification/`):**
  * `CryptoAsset` (v1.2.0), `PrimitiveType`, `SupportingFindingEvidence` models with `to_api_dict()` JSON serialization.
  * `AlgorithmNormalizer`: canonical naming, JCA strings, EVP functions, curve aliases, and parameter extraction.
  * `Deduplicator`: deterministic proximity clustering ($\pm 2$ lines) and binary/container component clustering.
  * Deterministic RFC 4122 UUIDv5 `asset_id` generation under `asset.qnetra.io` namespace.
  * `ConfidenceAggregator`: monotonic corroboration formula with detailed rationale generation.
  * `Normalizer`: public pipeline entrypoint and quantitative statistics calculator.
  * `ClassificationEngine`: deterministic classical (SECURE/WEAK/BROKEN/UNKNOWN) and quantum (SAFE/DEGRADED/CRITICAL/UNKNOWN) classification with Shor/Grover/BHT models and no-fabrication policy.
  * **CycloneDX 1.6 CBOM Generator (`core/cbom_generator/`):**
  * `CBOMSerializer`: CryptoAsset[] → CycloneDX 1.6 JSON (to_json, to_json_dict) and XML (to_xml) with deterministic mode.
  * `CBOMValidator`: Structural validator (required fields, assetType/primitive enums, bom-ref uniqueness, serialNumber, nistQuantumSecurityLevel bounds).
  * `mapper.py`: PrimitiveType → CDX primitive routing, no-fabrication display name, qnetra: namespaced evidence properties.
  * `models.py`: CDXBom, CDXComponent, CDXAlgorithmProperties, CDXEvidence, CDXProperty dataclasses.
* **Quantum Risk Engine (`core/risk_engine/`):**
  * `RiskEngine`: Pure single/batch assessment (`assess`, `assess_all`), in-place enrichment (`assess_and_enrich`, `assess_and_enrich_all`), and aggregate `RiskAssessmentReport` generation.
  * `RiskScorer`: Deterministic Alg-06 calculator with strict 0–100 bounds, double-counting prevention, and no-fabrication parameter handling.
  * `models.py`: `RiskSeverity`, `RiskFactor`, `RiskAssessment`, `AssetRiskDetail`, `RiskAssessmentReport`.
  * `knowledge.py`: Algorithmic base scores, parameter modifiers, severity thresholds, explainability templates.
* **Mosca Migration Engine (`core/mosca_engine/`):**
  * `MoscaEngine`: Pure single/batch assessment (`assess`, `assess_all`), aggregate `MoscaAssessmentReport` generation (no asset mutation).
  * `calculator.py`: `validate_duration`, `evaluate_inequality` (equality = False boundary), `calculate_exposure_gap`, `calculate_deadline_years_from_now`, `classify_hndl_exposure`, `classify_urgency`.
  * `models.py`: `MoscaUrgency` (6 tiers), `HNDLExposure` (6 tiers), `MoscaInput`, `MoscaAssessment`, `AssetMoscaDetail`, `MoscaAssessmentReport`.
  * `knowledge.py`: Quantum-arrival scenarios, migration baselines, HNDL thresholds, urgency constants, assumption templates, `MoscaConfig`.
  * No-fabrication: protected lifetime (X) has no silent default; urgency is UNKNOWN without it.
  * No `datetime.now()`: all deadlines use explicit `assessment_date` from `MoscaInput`.
  * Risk independence: Mosca urgency is orthogonal to Risk Score (DEC-015).
* **PQC Recommendation Engine (`core/recommendation_engine/`):**
  * `RecommendationEngine`: Pure single/batch recommendation (`recommend`, `recommend_all`), aggregate `PQCRecommendationReport` generation with `classical_upgrade_count` (no asset mutation).
  * `mapper.py`: Pure stateless `map_asset_to_recommendation()` routing by algorithm family and primitive type; strictly distinguishes PQC migrations from classical strengthening (`CLASSICAL_UPGRADE`).
  * `models.py`: `PQCRecommendationType` (6 outcomes including `CLASSICAL_UPGRADE`), `MigrationComplexity` (3 tiers), `PQCRecommendation`, `AssetRecommendationDetail`, `PQCRecommendationReport`.
  * `knowledge.py`: NIST FIPS 203/204/205 algorithm constants, parameter selection policy, hybrid construction definitions, rationale string templates.
  * Risk Score independence: recommendation routing NEVER uses `risk_score` or Mosca urgency (DEC-016).
  * No-fabrication: unknown algorithms return UNKNOWN with `recommended_algorithm=None`.
  * Only finalized NIST PQC: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205).
  * Parameter policy: ML-KEM-768 default (Cat.3); ML-KEM-1024 for RSA≥3072/ECC≥384.
  * Explicit hybrids: `X25519+ML-KEM-768` and `Ed25519+ML-DSA-65` only.
* **Test Suite (`tests/`):** 526 passed tests (118 recommendation engine tests), 93% recommendation engine coverage, 97% Mosca engine coverage, 98% risk engine coverage, 92% CBOM coverage.

### ○ PLANNED (Upcoming Phases)
* **Phase 4:** `backend.api` (FastAPI REST service), `frontend` (Interactive dashboard and charts), `backend.export_service` (PDF/CSV/CBOM export).

---

## 6. Current Repository Structure

```text
QNetra/
│
├── PROJECT_CONTEXT.md             ← (THIS FILE) High-density AI agent handoff document
├── current_prompt_update.md       ← Real-time per-prompt implementation summary (RULE-012)
├── current_status.md              ← Comprehensive live status, health metrics & module inventory
├── README.md                      ← Project front door, overview, and status badges
├── AGENTS.md                      ← Persistent operating instructions for AI agents
├── PROJECT_RULES.md               ← Active engineering constraints and governance rules
├── requirements.txt               ← Core Python dependencies (pydantic, lief)
├── core/                          ← Phase 2 Domain models and Normalization Engine
│   ├── __init__.py                ← Exports CryptoAsset, PrimitiveType, SupportingFindingEvidence
│   ├── models.py                  ← Canonical CryptoAsset, PrimitiveType, and SupportingEvidence schemas
│   └── normalization/             ← Normalization Subsystem
│       ├── __init__.py            ← Exports Normalizer, NormalizationStatistics
│       ├── normalizer.py          ← Normalizer orchestrator & stats calculator
│       ├── algorithm_normalizer.py← Algorithm canonicalizer & parameter extractor
│       ├── deduplicator.py        ← Proximity & component deduplicator + UUIDv5 generator
│       └── confidence_aggregator.py← Monotonic multi-signal confidence aggregator
├── AGENTS.md                      ← Persistent operating instructions for AI agents
├── PROJECT_RULES.md               ← Active engineering constraints and governance rules
├── requirements.txt               ← Core Python dependencies (pydantic, lief)
├── requirements-dev.txt           ← Development dependencies (pytest, pytest-cov)
│
├── docs/                          ← Living Single Source of Truth documentation
│   ├── 01_PROJECT_SCOPE.md        ← Scope, requirements, and boundary definitions
│   ├── 02_SYSTEM_ARCHITECTURE.md  ← Layered architecture, component diagrams, design history
│   ├── 03_DATA_FLOW.md            ← 12-stage pipeline and transformation specifications
│   ├── 04_MODULES.md             ← Module catalog, responsibilities, and statuses
│   ├── 05_ALGORITHMS.md           ← Algorithmic specifications (AST, Confidence, Risk, Mosca)
│   ├── 06_API_AND_DATA_CONTRACTS.md ← Canonical data schemas (RawFinding v1.1.0, CryptoAsset, CBOM)
│   ├── 07_PROGRESS.md             ← Real-time task tracker and milestones
│   ├── 08_DECISIONS_AND_LOG.md    ← Architecture Decision Records (DEC-001 to DEC-008)
│   └── 09_KNOWLEDGE_BASE.md       ← Domain knowledge (PQC standards, Mosca theorem, HNDL)
│
├── scanners/                      ← [IMPLEMENTED] Cryptographic Discovery Layer
│   ├── framework/                 ← BaseScanner, ScannerRouter, ScanTarget, ScanResult, RawFinding
│   ├── registry/                  ← Curated registries (algorithms, libraries, APIs, patterns, symbols)
│   ├── utils/                     ← File traversal, language detection, string extraction
│   ├── repository/                ← Source code scanner (Python AST, JS, Java, C/C++ analyzers)
│   ├── container/                 ← Extracted container filesystem & package inspector
│   └── binary/                    ← Static ELF/PE binary scanner (lief symbols + string analysis)
│
├── core/                          ← [PHASE 2 & 3] Normalization, CBOM, Risk, Mosca, Recommendation
├── backend/                       ← [PHASE 4] FastAPI REST endpoints & export services
├── frontend/                      ← [PHASE 4] Interactive web UI dashboard
├── tests/                         ← [77 TESTS] Automated unit and integration test suite
├── scripts/                       ← Utility & demonstration scripts
│   ├── demo_scan.py               ← Phase 1 scanner orchestration & raw_findings.md generator
│   └── generate_binary_fixture.py ← Synthetic ELF binary fixture builder
├── samples/                       ← Test codebases (Python, JS, Java, C crypto testbeds)
│   ├── repository_samples/        ← Per-language crypto source code fixtures
│   ├── container_sample/          ← Synthetic container filesystem fixture
│   └── binary_samples/            ← Synthetic ELF binary fixture
└── raw_findings.md                ← REAL scanner output (289 findings, generated by demo_scan.py)
```

---

## 7. Current Data Contracts Summary

| Model | Purpose | Key Fields | Producing Module |
| :--- | :--- | :--- | :--- |
| `ScanTarget` | Input target envelope | `target_id`, `path`, `target_type`, `options`, `metadata` | Ingestion / Caller |
| `ScanResult` | Scanner execution output | `scan_id`, `target`, `scanner_name`, `status`, `findings`, `statistics`, `errors` | `scanners.framework` |
| `RawFinding` (v1.1.0) | Raw discovery evidence | `finding_id`, `scanner_name`, `discovery_method`, `raw_symbol`, `suspected_algorithm`, `artifact_category`, `key_size_hint`, `mode_hint`, `location`, `confidence_score`, `confidence_rationale` | `scanners.*` |
| `CryptoAsset` (v1.2.0) | Canonical normalized & classified asset | `asset_id`, `algorithm`, `primitive_type`, `key_length_bits`, `curve`, `mode`, `padding`, `classical_security_status`, `quantum_vulnerable`, `quantum_threat_type`, `quantum_security_status`, `effective_classical_security_bits`, `effective_quantum_security_bits`, `classification_notes` | `core.normalization`, `core.classification` |

*Detailed Schema Definitions:* [`docs/06_API_AND_DATA_CONTRACTS.md`](docs/06_API_AND_DATA_CONTRACTS.md)

---

## 8. Scanner Architecture & Discovery Matrix

| Scanner | Target Type | Supported Inputs | Discovery Methods Implemented |
| :--- | :--- | :--- | :--- |
| **RepositoryScanner** | `REPOSITORY` | Python (`.py`), JS/TS (`.js`, `.ts`), Java (`.java`), C/C++ (`.c`, `.cpp`, `.h`) | **AST Analysis** (Python `ast`), **API Matching** (JS, Java `getInstance`, C OpenSSL EVP), **Import Tracking**, **Regex Patterns** |
| **ContainerScanner** | `CONTAINER_FS` | Extracted container filesystem directory | **Shared Library Inspection** (`/usr/lib/*.so`), **Package Metadata** (dpkg `status`, pip `site-packages`, npm `node_modules`), **TLS Config/Certs** (`/etc/ssl`) |
| **BinaryScanner** | `BINARY` | Compiled ELF and PE binaries | **Format Detection** (magic bytes), **ASCII String Extraction**, **Dynamic Symbol Table Parsing** (via `lief`), **Multi-Signal Correlation** |

---

## 9. Key Technical Decisions (ADR Summary)

* **DEC-001:** Living Single Source of Truth documentation in `/docs` governed by `AGENTS.md` and `PROJECT_RULES.md`.
* **DEC-002:** Canonical Normalization Layer separates heterogeneous scanners from downstream analytics.
* **DEC-003:** Adoption of Michele Mosca’s Inequality ($X + Y > Z$) to quantify HNDL timeline urgency.
* **DEC-004:** Strict alignment with official CycloneDX 1.6 CBOM and finalized NIST PQC standards (FIPS 203, 204, 205).
* **DEC-005:** Discovery Framework centered on `BaseScanner` lifecycle and `ScannerRouter` target dispatching.
* **DEC-006:** Promotion of Container and Binary Scanners to Phase 1 Discovery Subsystem.
* **DEC-007:** Integration of `lief` for static binary symbol inspection with pure-Python string fallback.
* **DEC-008:** Evolution of `RawFinding` to v1.1.0 with quantitative multi-signal confidence and parameter hints.
* **DEC-009:** API Contract and Frontend Product Specification Frozen Before Phase 4.
* **DEC-010:** Deterministic Normalization Architecture, Multi-Signal Aggregation, and RFC 4122 UUIDv5 Identity Strategy.
* **DEC-013:** CycloneDX 1.6 CBOM Generation Architecture.
* **DEC-014:** Deterministic Cryptographic Risk Engine Architecture & Factor Model.
* **DEC-015:** Mosca Engine Architecture — No-Fabrication X, Explicit Date, Risk Independence.
* **DEC-016:** Recommendation Engine Architecture — Table-Driven Routing, Risk Independence, No-Fabrication.

*Full Decision Records:* [`docs/08_DECISIONS_AND_LOG.md`](docs/08_DECISIONS_AND_LOG.md)

---

## 10. Important Constraints & Rules

1. **Passive & Read-Only:** Scanners must never execute target code, binaries, or containers (RULE-008). Static analysis only.
2. **Strict Decoupling:** Downstream modules must not access scanner internals or expect scanner-specific fields (RULE-004).
3. **Deterministic & Explainable:** Risk and confidence scores must use transparent formulas — no black-box ML (RULE-002).
4. **Schema Governance:** Any change to shared models requires an ADR and updates across all affected docs (RULE-006).
5. **Continuous Documentation Sync:** Code and documentation must never drift. Every completed task must update progress and affected docs (AGENTS.md).
6. **No Phantom Claims:** Never represent planned features as implemented.

---

## 11. Known Limitations & Current Gaps

* **JavaScript AST:** Phase 1 uses regex and API pattern matching for JS/TS to avoid external parsing dependencies. Full AST parsing is deferred.
* **Container Image Extraction:** `ContainerScanner` requires the container filesystem to be pre-extracted to a local directory (does not interact with Docker daemon directly).
* **Mach-O Deep Symbol Parsing:** Mach-O binaries are detected and analyzed via string extraction; full symbol inspection via `lief` is focused on ELF and PE in Phase 1.
* **Normalization Engine Unimplemented:** `core.normalization` is the immediate next step (Phase 2).

---

## 12. Immediate Next Development Steps

```text
RECOMMENDED CONTINUATION POINT (PHASE 4):

1. [COMPLETED] Implement `core/normalization/`
2. [COMPLETED] Implement `core/classification/`
3. [COMPLETED] Implement `core/cbom_generator/`
4. [COMPLETED] Implement `core/risk_engine/`
5. [COMPLETED] Implement `core/mosca_engine/`
6. [COMPLETED] Implement `core/recommendation_engine/`

7. [NEXT] Phase 4: Implement `backend/api/` (FastAPI REST gateway)
   - POST /api/scan  (trigger scan pipeline)
   - GET  /api/cbom  (retrieve generated CBOM)
   - GET  /api/risk  (retrieve risk assessment report)
   - GET  /api/mosca (retrieve Mosca assessment report)
   - GET  /api/recommendations (retrieve PQC recommendation report)
   - GET  /api/export (download PDF/CSV/CBOM)

8. [NEXT] Phase 4: Implement `frontend/` (Interactive Web Dashboard)
   - Executive summary risk scorecards
   - Searchable/filterable CBOM table explorer
   - Interactive Mosca timeline slider widget
   - PQC migration guide renderer
```

---

## 13. Agent Handoff Protocol

```text
IF YOU ARE A NEW AI AGENT JOINING QNETRA:

1. Read this file (PROJECT_CONTEXT.md) to grasp the current state and architecture.
2. Read PROJECT_RULES.md to internalize active engineering constraints.
3. Read AGENTS.md for operational workflows and documentation responsibilities.
4. Phase 3 is COMPLETE. Check Section 12 above for the Phase 4 continuation point.
5. Inspect only the modules relevant to your specific assigned task.
6. Consult detailed docs in /docs only when needed for specific schema/formula details.
7. Run the test suite (`python -m pytest tests/`) before and after making changes.
8. Update current_prompt_update.md (RULE-012 mandatory on every prompt), current_status.md, PROJECT_CONTEXT.md, and affected docs in /docs upon completing your task.
```
