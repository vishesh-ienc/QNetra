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
Normalization & Deduplication                       [○ PLANNED - Phase 2]
        ↓
Canonical CryptoAsset Models                        [○ PLANNED - Phase 2]
        ↓
CBOM Generation (CycloneDX 1.6 JSON/XML)            [○ PLANNED - Phase 2]
        ↓
Classification & Parameter Enrichment               [○ PLANNED - Phase 2]
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
│ 2. CANONICAL NORMALIZATION LAYER (core.normalization — Phase 2)        │
│    Translates RawFinding -> Canonical CryptoAsset Schema                │
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
Phase 1 — Cryptographic Discovery Layer (COMPLETED)

CURRENT SUB-PHASE:
Transitioning to Phase 2 — Core Normalization, Classification, & CBOM Generation

LAST COMPLETED:
Phase 1 Discovery Layer Implementation:
  - Discovery Framework Core (BaseScanner, ScannerRouter, models.py)
  - Curated Knowledge Registries (Algorithms, Libraries, API Maps, Patterns, Symbols)
  - 3 Discovery Scanners (RepositoryScanner, ContainerScanner, BinaryScanner)
  - 77 Automated Tests across 5 test suites (80% code coverage)
  - Full documentation synchronization across docs/01 through docs/08

CURRENTLY IMPLEMENTING:
Phase 2 Foundation: Normalization Engine (core.normalization) & CBOM Generator

NEXT LOGICAL STEP:
Implement core/normalization/ to convert RawFinding v1.1.0 into canonical CryptoAsset records.
```

---

## 5. What Is Already Implemented

### ✓ IMPLEMENTED & TESTED (Phase 1)
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
* **Test Suite (`tests/`):** 77 passed tests, 80% total code coverage.

### ○ PLANNED (Upcoming Phases)
* **Phase 2:** `core.normalization` (RawFinding -> CryptoAsset), `core.classification`, `core.cbom_generator` (CycloneDX 1.6 JSON/XML).
* **Phase 3:** `core.risk_engine` (Deterministic risk scoring), `core.mosca_engine` ($X+Y > Z$ simulation), `core.recommendation_engine` (NIST FIPS 203/204/205 mapping).
* **Phase 4:** `backend.api` (FastAPI REST service), `frontend` (Interactive dashboard and charts), `backend.export_service` (PDF/CSV/CBOM export).

---

## 6. Current Repository Structure

```text
QNetra/
│
├── PROJECT_CONTEXT.md             ← (THIS FILE) High-density AI agent handoff document
├── README.md                      ← Project front door, overview, and status badges
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
└── samples/                       ← Test codebases (Python, JS, Java, C crypto testbeds)
```

---

## 7. Current Data Contracts Summary

| Model | Purpose | Key Fields | Producing Module |
| :--- | :--- | :--- | :--- |
| `ScanTarget` | Input target envelope | `target_id`, `path`, `target_type`, `options`, `metadata` | Ingestion / Caller |
| `ScanResult` | Scanner execution output | `scan_id`, `target`, `scanner_name`, `status`, `findings`, `statistics`, `errors` | `scanners.framework` |
| `RawFinding` (v1.1.0) | Raw discovery evidence | `finding_id`, `scanner_name`, `discovery_method`, `raw_symbol`, `suspected_algorithm`, `artifact_category`, `key_size_hint`, `mode_hint`, `location`, `confidence_score`, `confidence_rationale` | `scanners.*` |
| `CryptoAsset` *(Phase 2)* | Canonical normalized asset | `asset_id`, `algorithm`, `primitive_type`, `key_length_bits`, `curve`, `mode`, `padding`, `quantum_vulnerable`, `quantum_threat_type` | `core.normalization` |

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

1. Implement `core/normalization/normalizer.py`:
   - Input: List[RawFinding]
   - Output: List[CryptoAsset]
   - Tasks: Algorithm name canonicalization, primitive type classification, duplicate merging.

2. Implement `core/classification/classifier.py`:
   - Tasks: Quantum threat vector assignment (Shor vs Grover), quantum security bit calculation.

3. Implement `core/cbom_generator/cyclonedx.py`:
   - Tasks: Serialize CryptoAsset list into CycloneDX 1.6+ JSON & XML CBOM formats.

4. Add Phase 2 Test Suite (`tests/test_core/`):
   - Normalization accuracy tests, CBOM schema validation against CycloneDX 1.6 schema.
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
8. Update PROJECT_CONTEXT.md and affected docs in /docs upon completing your task.
```
