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
Quantum Risk Engine (Deterministic Scoring)         [○ PLANNED - Phase 3]
        ↓
Mosca Migration Urgency Engine (X + Y > Z)          [○ PLANNED - Phase 3]
        ↓
PQC & Hybrid Recommendation Engine                  [○ PLANNED - Phase 3]
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
Phase 2 — Core Normalization, Classification, & CBOM Generation (IN PROGRESS)

CURRENT SUB-PHASE:
Milestones 2.1, 2.2 & 2.3 Complete — Normalization, Classification, & CycloneDX 1.6 CBOM Generator
Next: Phase 3 — Quantum Risk Engine, Mosca Engine, PQC Recommendation Engine

LAST COMPLETED:
Phase 2 Milestone 2.3 CBOM Generator (2026-09-04):
  - Implemented core/cbom_generator/__init__.py (public API: CBOMSerializer, CBOMValidator)
  - Implemented core/cbom_generator/models.py (CDXBom, CDXComponent, CDXCryptoProperties, CDXAlgorithmProperties, CDXEvidence, CDXProperty)
  - Implemented core/cbom_generator/mapper.py (CryptoAsset → CDXComponent; PrimitiveType → CDX primitive routing; no-fabrication policy)
  - Implemented core/cbom_generator/serializer.py (CBOMSerializer.to_json(), to_xml(), to_json_dict(), build_bom())
  - Implemented core/cbom_generator/validator.py (structural validator: required fields, enum values, bom-ref uniqueness, nistQuantumSecurityLevel)
  - Created tests/test_core/test_cbom_generator.py (116 tests, 92% CBOM coverage)
  - Full test suite: 272 passed, 0 failed
  - Updated docs/04_MODULES.md, docs/07_PROGRESS.md, docs/08_DECISIONS_AND_LOG.md, PROJECT_CONTEXT.md
  - Fixed AES key-size raw symbol injection bug in algorithm_normalizer.py + added 3 regression tests
  - Extended CryptoAsset schema to v1.2.0 with 5 classification fields + updated to_api_dict() (DEC-011)
  - Implemented core/classification/models.py (ClassicalSecurityStatus, QuantumSecurityStatus, ClassificationResult)
  - Implemented core/classification/knowledge.py (NIST SP 800-57 tables, ECC curve profiles, Grover formula, BHT hash profiles)
  - Implemented core/classification/classifier.py (ClassificationEngine with orthogonal dimensions & no-fabrication policy)
  - Created 54-test classification suite; 153/154 total tests passing, 85% core coverage
  - Validated full pipeline: 289 RawFindings -> 147 CryptoAssets -> all classified (65 vuln, 38 safe, 44 unknown)
  - Updated docs/04, docs/05, docs/06, docs/07, docs/08 (DEC-011, DEC-012), docs/10, current_status, PROJECT_CONTEXT

PREVIOUSLY COMPLETED:
Phase 2 Normalization & CryptoAsset Generation (2026-09-03):
  - Canonical CryptoAsset domain model, AlgorithmNormalizer, Deduplicator (UUIDv5), ConfidenceAggregator
Phase 1 Discovery Layer Implementation & Validation:
  - BaseScanner, ScannerRouter, registries, Repository/Container/Binary scanners, 77 tests (289 real findings)

CURRENTLY IMPLEMENTING:
Phase 3 Milestone 3.1: Quantum Risk Engine (core.risk_engine).

NEXT LOGICAL STEP:
Phase 3 Milestone 3.1: Deterministic Quantum Risk Scoring Engine (core.risk_engine).
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
* **Test Suite (`tests/`):** 272 passed tests, 92% CBOM coverage, 85%+ core coverage overall.

### ○ PLANNED (Upcoming Phases)
* **Phase 3:** `core.risk_engine` (Deterministic risk scoring), `core.mosca_engine` ($X+Y > Z$ simulation), `core.recommendation_engine` (NIST FIPS 203/204/205 mapping).
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
* **DEC-011:** Additive CryptoAsset Schema Extension for Classification Fields (v1.2.0).
* **DEC-012:** Classification Engine Architecture: Independent Dimensions & No-Fabrication Policy.

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
RECOMMENDED CONTINUATION POINT (PHASE 2):

1. [COMPLETED] Implement `core/normalization/`:
   - Input: List[RawFinding] -> Output: List[CryptoAsset]
   - Tests: 22 unit & regression tests under `tests/test_core/test_normalization.py`.

2. [COMPLETED] Implement `core/classification/`:
   - Tasks: Orthogonal classical & quantum threat classification, effective security bit calculation, no-fabrication policy.
   - Tests: 54 unit tests under `tests/test_core/test_classification.py`.

3. [NEXT] Implement `core/cbom_generator/`:
   - Tasks: Serialize CryptoAsset list into CycloneDX 1.6+ JSON & XML CBOM formats.
   - Validation: CycloneDX 1.6 JSON Schema compliance tests.

4. Advance to Phase 3 Intelligence Engines (`core/risk_engine`, `core/mosca_engine`).
```

---

## 13. Agent Handoff Protocol

```text
IF YOU ARE A NEW AI AGENT JOINING QNETRA:

1. Read this file (PROJECT_CONTEXT.md) to grasp the current state and architecture.
2. Read PROJECT_RULES.md to internalize active engineering constraints.
3. Read AGENTS.md for operational workflows and documentation responsibilities.
4. Check Section 4 & 12 above for the exact continuation point (Phase 2 Normalization).
5. Inspect only the modules relevant to your specific assigned task.
6. Consult detailed docs in /docs only when needed for specific schema/formula details.
7. Run the test suite (`python -m pytest tests/`) before and after making changes.
8. Update current_prompt_update.md (RULE-012 mandatory on every prompt), current_status.md, PROJECT_CONTEXT.md, and affected docs in /docs upon completing your task.
```
