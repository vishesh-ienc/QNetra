# QNetra — Project Status & Implementation Summary

> **Current As Of:** September 3, 2026
> **Status:** 🟢 **Active / Phase 1 Complete — Phase 2 Normalization Milestone Complete — API & Frontend Specs Frozen**
> **Tracking Protocol:** This document is the comprehensive single-file status report for **QNetra**, maintained and updated on every meaningful progress milestone, architectural decision, and codebase update.

---

## 1. Project Mission & Identity

* **Project Name:** QNetra
* **SIH Problem Statement ID:** 26164
* **Problem Statement Title:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)
* **Core Objective:** Build a passive, automated, enterprise-grade cryptographic discovery and risk analysis tool that identifies cryptographic assets across code repositories, container filesystems, and compiled binaries, generates a standardized Cryptographic Bill of Materials (CBOM), assesses quantum computing vulnerabilities (Shor's and Grover's algorithms), models migration urgency via Mosca's Theorem ($X + Y > Z$), and provides actionable Post-Quantum Cryptography (PQC) and hybrid transition roadmaps.
* **Core Architectural Principle:** **Living Single Source of Truth** with strict layer separation: Scanners emit raw evidence (`RawFinding` v1.1.0) into a Canonical Normalization Layer (`CryptoAsset`), decoupling low-level discovery from downstream CBOM generation, risk scoring, and UI presentation.

---

## 2. Executive Status Snapshot

| Dimension | Current Status | Notes / Highlights |
| :--- | :--- | :--- |
| **Current Phase** | **Phase 2 In Progress** (Milestones 2.1 & 2.2 Complete) | Normalization & Classification subsystems complete & validated on 289 real findings |
| **Test Suite Health** | 🟢 **153 / 154 Tests Passing (1 skipped, 100% active pass rate)** | Run via `pytest` (0 regressions, ~0.8s execution) |
| **Codebase Coverage** | 🟢 **85% Core Coverage** (882 statements in `core/`) | High coverage across classification (models, knowledge, classifier) & normalization |
| **Pipeline Validation** | 🟢 **147 Canonical Assets Classified** | 289 raw findings merged into 147 canonical assets; 65 Shor/Grover vulnerable, 38 safe, 44 unknown |
| **Active Blockers** | 🟢 **None** | No blocking architectural or operational defects |
| **Documentation Sync** | 🟢 **100% Synchronized** | `docs/01` to `docs/10`, `AGENTS.md`, `PROJECT_RULES.md`, `PROJECT_CONTEXT.md`, `current_status.md` |
| **Next Target Milestone** | **Phase 2.3: CBOM Generation** | `core/cbom_generator/` CycloneDX 1.6+ JSON & XML CBOM serializers |
| **API Contract** | 🟢 **Frozen & Aligned (v1.2.0)** — `docs/10_API_CONTRACT.md` | 20 sections, Section 8 aligned with Phase 2.2 classification fields |
| **Frontend Spec** | 🟢 **Frozen** — `docs/11_FRONTEND_PRODUCT_SPEC.md` | 12 sections, E2E user flow, component guidance, visual direction |

---

## 3. End-to-End Intelligence Pipeline Status

```text
[ Technical Target Assets: Source Repositories, Container Images, Compiled Binaries ]
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 1. Cryptographic Discovery Layer (scanners/*)                       [COMPLETED] │
│    - ScannerRouter (Target dispatch via magic bytes & heuristics)               │
│    - RepositoryScanner (Python AST, JS/TS regex/APIs, Java JCA, C/C++ EVP)      │
│    - ContainerScanner (Shared libs, dpkg/pip/npm packages, /etc/ssl certs)     │
│    - BinaryScanner (ELF/PE format detection, lief symbols, ASCII string regex)  │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │ Emits RawFinding (v1.1.0)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 2. Canonical Normalization & Aggregation Layer (core.normalization) [COMPLETED] │
│    - Algorithm canonicalization (JCA, OpenSSL EVP, curve & cipher mode mapping) │
│    - Multi-signal finding deduplication (proximity ±2 lines, component scope)   │
│    - RFC 4122 UUIDv5 deterministic ID generation (asset.qnetra.io namespace)   │
│    - Monotonic, bounded confidence aggregation with explainable rationale       │
│    - Emits canonical CryptoAsset records conforming to docs/10_API_CONTRACT     │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │ Emits Canonical CryptoAsset
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 3. Classification Subsystem (core.classification)                 [COMPLETED]   │
│    - Classical security status (SECURE / WEAK / BROKEN / UNKNOWN)               │
│    - Quantum threat vector tagging (Shor, Grover, BHT, PQC, Classically Broken) │
│    - Effective classical & post-quantum security bit estimation (no-fabrication)│
│    - Enriches canonical CryptoAsset instances in-place                          │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │ Emits Enriched Canonical CryptoAsset
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 4. CBOM Generation Layer (core.cbom_generator)                      [PLANNED]   │
│    - CycloneDX 1.6+ JSON & XML CBOM Serializer                                  │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 5. Downstream Intelligence Engines (core.risk / mosca / recommendations)[PLANNED]│
│    - Deterministic Quantum Risk Engine (0-100 scoring & justifications)         │
│    - Mosca Inequality Simulator (X + Y > Z urgency & HNDL window)               │
│    - NIST FIPS 203/204/205 PQC & Hybrid Migration Recommender                   │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 6. API Gateway & Interactive UI Dashboard (backend / frontend)        [PLANNED] │
│    - FastAPI REST endpoints, job orchestrator, PDF/CSV/CBOM exports             │
│    - Interactive Web UI: CBOM Explorer, Mosca Timeline Slider, Risk Heatmap    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Detailed Module Implementation Inventory

### Phase 1: Cryptographic Discovery Layer (✅ Completed & Verified)

| Subsystem / Module | File Path | Status | Key Implemented Capabilities |
| :--- | :--- | :--- | :--- |
| **Framework Core** | [`scanners/framework/models.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/framework/models.py) | ✅ Complete | Data models for `ScanTarget`, `ScanResult`, `ScanOptions`, `ScanStatistics`, and `RawFinding` v1.1.0 (with float confidence, confidence rationale, parameter hints, and backward-compatible `to_v1_dict()`). |
| **Base Scanner Interface** | [`scanners/framework/base_scanner.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/framework/base_scanner.py) | ✅ Complete | Abstract `BaseScanner` implementing template method pattern: timing, target validation, exception containment, and structured `ScanResult` emission. |
| **Scanner Router** | [`scanners/framework/router.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/framework/router.py) | ✅ Complete | Intelligent dispatcher detecting target types from filesystem characteristics and binary magic bytes (ELF `\x7fELF`, PE `MZ`, Mach-O `\xfe\xed\xfa\xce`/`\xcf`, Archive `!<arch>`). |
| **Algorithm Registry** | [`scanners/registry/crypto_algorithms.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/registry/crypto_algorithms.py) | ✅ Complete | Curated registry of 30+ classical and post-quantum algorithms with quantum threat classifications (Shor, Grover, Classically Broken) and key size boundaries. |
| **Library Registry** | [`scanners/registry/crypto_libraries.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/registry/crypto_libraries.py) | ✅ Complete | Ecosystem mappings for Python (`cryptography`, `pycryptodome`), JS (`crypto`, `node-forge`, `crypto-js`), Java (`BouncyCastle`, `JCA`), and C/C++ (`OpenSSL`, `libsodium`, `mbedTLS`). |
| **API Map Registry** | [`scanners/registry/crypto_api_map.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/registry/crypto_api_map.py) | ✅ Complete | API signatures and parameter extraction rules (e.g. RSA key generation, AES cipher modes, ECC curve selection). |
| **Pattern Registry** | [`scanners/registry/crypto_patterns.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/registry/crypto_patterns.py) | ✅ Complete | Pre-compiled regex patterns for algorithm strings, PEM key formats, protocols (TLS/SSH), and PQC primitives with comment vs. code confidence weights. |
| **Symbol Registry** | [`scanners/registry/crypto_symbols.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/registry/crypto_symbols.py) | ✅ Complete | Dynamic and static binary symbol definitions for OpenSSL (`EVP_*`, `RSA_*`), libsodium (`crypto_box_*`), mbedTLS, and Windows CNG/Bcrypt. |
| **Traversal & File Utils** | [`scanners/utils/file_traversal.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/utils/file_traversal.py)<br>[`scanners/utils/language_detector.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/utils/language_detector.py)<br>[`scanners/utils/string_extractor.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/utils/string_extractor.py) | ✅ Complete | Recursive directory scanning honoring exclusions and size limits; extension/shebang language detector; printable ASCII/UTF-8 string extractor with Shannon entropy scoring. |
| **Repository Scanner** | [`scanners/repository/scanner.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/scanner.py)<br>[`scanners/repository/confidence.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/confidence.py) | ✅ Complete | Orchestrates language analyzers and scores finding confidence (0.0–1.0) with deterministic mathematical weightings. |
| **Python AST Analyzer** | [`scanners/repository/languages/python_analyzer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/languages/python_analyzer.py) | ✅ Complete | Full AST parsing (`ast` module) detecting `import`/`from` aliases, constructor arguments (`RSA.generate(2048)`), cipher modes (`modes.CBC(iv)`), and hash digests (`hashes.SHA256()`). |
| **JS/TS Analyzer** | [`scanners/repository/languages/javascript_analyzer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/languages/javascript_analyzer.py) | ✅ Complete | Static parsing of `require()` / `import` statements, Node.js `crypto` calls (`createCipheriv`, `generateKeyPairSync`), and Web Crypto API. |
| **Java Analyzer** | [`scanners/repository/languages/java_analyzer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/languages/java_analyzer.py) | ✅ Complete | JCA/JCE factory pattern recognition (`Cipher.getInstance("AES/CBC/PKCS5Padding")`, `KeyPairGenerator.getInstance("RSA")`, `KeyAgreement`, `Signature`). |
| **C/C++ Analyzer** | [`scanners/repository/languages/cpp_analyzer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/repository/languages/cpp_analyzer.py) | ✅ Complete | `#include` detection for OpenSSL/mbedTLS/libsodium, and OpenSSL EVP API call parsing (`EVP_aes_256_gcm()`, `EVP_PKEY_keygen()`). |
| **Container Scanner** | [`scanners/container/scanner.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/container/scanner.py)<br>[`scanners/container/filesystem.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/container/filesystem.py)<br>[`scanners/container/package_inspector.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/container/package_inspector.py) | ✅ Complete | Scans extracted container root filesystems for: (1) shared libraries (`/usr/lib/*.so`), (2) package manifests (dpkg `/var/lib/dpkg/status`, pip `site-packages`, npm `node_modules`), and (3) SSL/TLS certs/keys (`/etc/ssl`, `/etc/pki`). |
| **Binary Scanner** | [`scanners/binary/scanner.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/binary/scanner.py)<br>[`scanners/binary/format_detector.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/binary/format_detector.py)<br>[`scanners/binary/string_analyzer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/binary/string_analyzer.py)<br>[`scanners/binary/symbol_inspector.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/binary/symbol_inspector.py)<br>[`scanners/binary/correlation.py`](file:///c:/Users/VISHESH/Desktop/QNetra/scanners/binary/correlation.py) | ✅ Complete | Static binary analysis for ELF/PE executables: magic byte validation, ASCII string and cipher suite extraction, `lief` symbol table inspection with pure-Python fallback, and multi-signal finding correlation. |

### Phase 2: Core Normalization, Classification & Canonical Modeling (✅ Milestones 2.1 & 2.2 Complete)

| Subsystem / Module | File Path | Status | Key Implemented Capabilities |
| :--- | :--- | :--- | :--- |
| **Domain Models** | [`core/models.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/models.py) | ✅ Complete | `CryptoAsset` canonical schema v1.2.0 (with 5 classification fields), `PrimitiveType` enum, `SupportingFindingEvidence` model, and `to_api_dict()` conforming to `docs/10_API_CONTRACT.md`. |
| **Algorithm Normalizer** | [`core/normalization/algorithm_normalizer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/normalization/algorithm_normalizer.py) | ✅ Complete | Canonical algorithm naming, JCA algorithm transformation parsing (`AES/GCM/NoPadding`), OpenSSL EVP symbol parsing (`EVP_aes_256_gcm`), curve alias mapping, mode/padding normalization, parameter extraction, and AES raw-symbol injection fix. |
| **Deduplicator & Aggregator** | [`core/normalization/deduplicator.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/normalization/deduplicator.py) | ✅ Complete | Proximity-based statement clustering ($\pm 2$ lines), whole-file binary/container component clustering, parameter compatibility enforcement, and RFC 4122 UUIDv5 deterministic ID generation using `asset.qnetra.io` namespace. |
| **Confidence Aggregator** | [`core/normalization/confidence_aggregator.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/normalization/confidence_aggregator.py) | ✅ Complete | Deterministic multi-signal confidence aggregation ($S_{\max} + \sum 0.05 \times s_i$), bounded at 1.0, strictly monotonic, with transparent formula rationale breakdown. |
| **Normalizer Orchestrator** | [`core/normalization/normalizer.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/normalization/normalizer.py) | ✅ Complete | Pipeline entrypoint and quantitative metrics calculator (`NormalizationStatistics`). |
| **Classification Models** | [`core/classification/models.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/classification/models.py) | ✅ Complete | `ClassicalSecurityStatus` (SECURE, WEAK, BROKEN, UNKNOWN), `QuantumSecurityStatus` (SAFE, DEGRADED, CRITICAL, UNKNOWN), and `ClassificationResult` dataclass. |
| **Classification Knowledge** | [`core/classification/knowledge.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/classification/knowledge.py) | ✅ Complete | NIST SP 800-57 Table 2 security bit tables, ECC curve profiles, Grover formula ($K/2$), BHT hash profiles (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3), and 128-bit quantum threshold. |
| **Classification Engine** | [`core/classification/classifier.py`](file:///c:/Users/VISHESH/Desktop/QNetra/core/classification/classifier.py) | ✅ Complete | `ClassificationEngine` orchestrating deterministic enrichment across orthogonal classical and quantum dimensions with strict no-fabrication policy. |

---

### Upcoming Development Phases (Roadmap)

| Phase | Target Module | Objective & Key Deliverables | Status |
| :--- | :--- | :--- | :--- |
| **Phase 2** | `core/cbom_generator/` | CycloneDX 1.6+ JSON & XML CBOM serialization conforming to official cryptography extensions. | 🕒 **Immediate Next** |
| **Phase 3** | `core/risk_engine/` | Deterministic, explainable quantum risk scoring algorithm (0–100) factoring in key length, algorithm status, and quantum vulnerability. | 🕒 Planned |
| **Phase 3** | `core/mosca_engine/` | Michele Mosca Inequality ($X + Y > Z$) simulation engine quantifying Harvest Now, Decrypt Later (HNDL) exposure windows. | 🕒 Planned |
| **Phase 3** | `core/recommendation_engine/` | Algorithmic PQC replacement mapping (NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and hybrid migration paths). | 🕒 Planned |
| **Phase 4** | `backend/` | FastAPI REST service (`/api/scan`, `/api/cbom`, `/api/mosca`, `/api/export`), job orchestration, and PDF/CSV report generation. | 🕒 Planned |
| **Phase 4** | `frontend/` | Premium interactive dashboard (CBOM explorer, interactive Mosca timeline slider, quantum risk heatmaps, remediation guides). | 🕒 Planned |

---

## 5. Test Suite Execution & Code Coverage Status

### Test Execution Summary (Validated on Python 3.13)
* **Total Tests:** 154
* **Passed:** 153 (100% active pass rate)
* **Skipped:** 1 (integration test requiring local fixture path)
* **Failed / Errors:** 0
* **Execution Time:** ~0.8 seconds

### Coverage Breakdown by Subsystem

```text
=============================== Coverage Breakdown ===============================
Subsystem / Module                                Statements    Missed    Coverage
----------------------------------------------------------------------------------
core/ (Models, Normalizer, Classifier, Knowledge)        882       135         85%
scanners/framework (BaseScanner, Router, Models)         273        14         95%
scanners/registry (Algorithms, APIs, Libraries, etc.)   186        12         94%
scanners/repository (AST, JS, Java, C++, Confidence)     500        56         89%
scanners/container (Filesystem, Dpkg/Pip/Npm, Scanner)   241        72         70%
scanners/binary (Format, Strings, lief, Correlation)     298       136         54%
scanners/utils (Traversal, Language, Strings)            174        51         71%
----------------------------------------------------------------------------------
TOTAL CODEBASE                                         2,681       483         82%
==================================================================================
```

### Test Directory Map
* [`tests/test_core/test_classification.py`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_core/test_classification.py): Classical security status, quantum threat tagging (Shor, Grover, BHT, PQC), `quantum_vulnerable` semantics, no-fabrication effective bits, classification confidence, determinism, asset enrichment, and pipeline integration (54 passed, 1 skipped).
* [`tests/test_core/test_normalization.py`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_core/test_normalization.py): Canonical `CryptoAsset` modeling, algorithm name canonicalization, parameter extraction, JCA/EVP patterns, spatial & component deduplication, RFC 4122 UUIDv5 idempotency, monotonic confidence aggregation, statistics tests, and AES key-size injection regression tests (22 tests).
* [`tests/test_framework/`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_framework): Data models validation, schema serialization, `to_v1_dict()` compatibility, `ScannerRouter` dispatch tests.
* [`tests/test_repository/`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_repository): Python AST analyzer tests, JavaScript/Node.js crypto tests, Java JCA tests, C/C++ EVP analyzer tests.
* [`tests/test_container/`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_container): Shared library scanner tests, package manager parser tests, SSL certificate tests.
* [`tests/test_binary/`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_binary): ELF/PE magic-byte detection tests, string extraction tests, symbol inspector fallback tests.
* [`tests/test_integration/`](file:///c:/Users/VISHESH/Desktop/QNetra/tests/test_integration): End-to-end scanner pipeline integration on multi-language testbeds (`samples/repository_samples`).

---

## 6. Architecture & Governance Constraints (Active Rules)

All development on QNetra strictly complies with the governance rules defined in [`PROJECT_RULES.md`](file:///c:/Users/VISHESH/Desktop/QNetra/PROJECT_RULES.md) and [`AGENTS.md`](file:///c:/Users/VISHESH/Desktop/QNetra/AGENTS.md):

1. **RULE-001 (Scanner Normalization):** All discovery scanners emit `RawFinding` (v1.1.0), which translates to canonical `CryptoAsset` models.
2. **RULE-002 (Explainable Scoring):** Risk scores and Mosca timeline assessments are 100% deterministic, formulaic, and explainable — no opaque black-box models.
3. **RULE-003 (Continuous Documentation):** Code and documentation are continuously synchronized on every task completion without waiting for explicit prompts.
4. **RULE-004 (Layered Separation):** Scanners, normalization, analytics engines, APIs, and UI maintain strict modular boundaries.
5. **RULE-005 (Standards Compliance):** CBOMs strictly adhere to CycloneDX 1.6+ Cryptography Extension; PQC recommendations strictly follow finalized NIST FIPS 203/204/205 standards.
6. **RULE-008 (Passive & Non-Destructive):** Scanners operate strictly in passive, static read-only mode; target binaries or scripts are never executed.
7. **RULE-012 (Per-Prompt Implementation Tracking):** Maintain and overwrite `current_prompt_update.md` on every single prompt interaction.

---

## 7. Immediate Next Development Actions (Phase 2 CBOM Generator Launch)

1. **Implement CBOM Generator (`core/cbom_generator/`):**
   * Build CycloneDX 1.6+ JSON & XML CBOM serializer translating canonical `CryptoAsset` models into CycloneDX `cryptoAssets` components.
   * Add schema validation test fixtures against official CycloneDX 1.6 JSON Schema (`cyclonedx.schema.json`).
2. **Author CBOM Serializer Unit & Integration Tests (`tests/test_core/`):**
   * CBOM schema compliance validation, CycloneDX 1.6 XML / JSON conformance tests.
3. **Advance to Phase 3 Intelligence Engines:**
   * Prepare data pipeline interfaces for `core.risk_engine` and `core.mosca_engine`.

---

## 8. Status Update Protocol

> [!IMPORTANT]
> **Maintenance Rule for All Contributors & AI Agents:**  
> On every user prompt turn:
> 1. Overwrite/update [`current_prompt_update.md`](file:///c:/Users/VISHESH/Desktop/QNetra/current_prompt_update.md) summarizing the current prompt's implementation (RULE-012).
> 
> When completing any major task, milestone, or architectural change:
> 2. Update this document (`current_status.md`) with the latest test results, module status, and metrics.
> 3. Synchronize [`PROJECT_CONTEXT.md`](file:///c:/Users/VISHESH/Desktop/QNetra/PROJECT_CONTEXT.md) and [`docs/07_PROGRESS.md`](file:///c:/Users/VISHESH/Desktop/QNetra/docs/07_PROGRESS.md).
> 4. If new architectural choices or rules were introduced, log them in [`docs/08_DECISIONS_AND_LOG.md`](file:///c:/Users/VISHESH/Desktop/QNetra/docs/08_DECISIONS_AND_LOG.md) and [`PROJECT_RULES.md`](file:///c:/Users/VISHESH/Desktop/QNetra/PROJECT_RULES.md).
