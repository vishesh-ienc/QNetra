# 08 — Architecture Decisions & Changelog (ADR)

> **DOCUMENT PURPOSE:** Centralized, immutable ledger of all major architectural, design, algorithmic, and engineering decisions made during the lifecycle of **QNetra**.

---

## Decision Record Format Standard

Every Architecture Decision Record (ADR) must follow this template:

```markdown
## DEC-XXX — [Decision Title]

* **Date:** YYYY-MM-DD
* **Status:** [Proposed | Accepted | Superseded | Deprecated]
* **Deciders:** [Team Members / Roles]

### Context
What problem or requirement necessitated this decision? What background context is relevant?

### Decision
What technical or architectural choice was made?

### Reasoning
Why was this choice selected over others? What are the key advantages?

### Alternatives Considered
What other options or frameworks were evaluated, and why were they rejected?

### Consequences
What are the positive and negative trade-offs? What downstream systems are affected?

### Related Modules / Data Contracts
Links to affected modules in `docs/04_MODULES.md` or contracts in `docs/06_API_AND_DATA_CONTRACTS.md`.
```

---

## Architecture Decision Records

### DEC-001 — Living Documentation & Single Source of Truth Governance

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** System Architect & Core Team

#### Context
Complex hackathon projects developed across multi-member teams and AI agents frequently suffer from architectural drift, broken contracts, and lost context when chat transcripts reset.

#### Decision
Adopt a **Living Single Source of Truth** documentation model anchored in `/docs`, governed by [AGENTS.md](AGENTS.md) and [PROJECT_RULES.md](PROJECT_RULES.md). Continuous documentation updates are enforced as a mandatory condition for task completion.

#### Reasoning
Ensures complete reproducibility, traceability, and seamless onboarding for any developer or AI agent without requiring historical chat transcripts.

#### Alternatives Considered
* Ad-hoc documentation after implementation (Rejected: leads to stale docs and integration breaks).
* Relying purely on chat memory (Rejected: context is lost between sessions).

#### Consequences
* Positive: High code quality, clear interfaces, self-documenting project state.
* Trade-off: Requires discipline to evaluate documentation impact on every commit.

#### Related Modules / Data Contracts
* All files in `/docs`, [AGENTS.md](AGENTS.md), [PROJECT_RULES.md](PROJECT_RULES.md).

---

### DEC-002 — Modular Pipeline with Canonical Normalization Layer

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** System Architect & Core Team

#### Context
QNetra must discover cryptographic assets across various programming languages (Python, JS/TS, Java, Go), manifests, and configuration formats. If downstream engines (CBOM generator, Risk Engine, Mosca Engine) depend directly on varied scanner outputs, the system will become tightly coupled and fragile.

#### Decision
Introduce a dedicated **Normalization Layer** that transforms heterogeneous `RawFinding` outputs into a single canonical `CryptoAsset` data contract before any risk scoring or CBOM generation takes place.

#### Reasoning
* Decouples scanner development from analytics and reporting.
* Allows new language parsers to be added simply by implementing a parser that outputs `RawFinding`.
* Simplifies unit testing and validation.

#### Alternatives Considered
* Direct end-to-end scanning directly to CycloneDX format (Rejected: makes custom risk scoring and Mosca analysis complex and repetitive).

#### Consequences
* Positive: High modularity and extensibility.
* Trade-off: Small additional transformation step in memory.

#### Related Modules / Data Contracts
* [docs/04_MODULES.md#5-normalization-layer](docs/04_MODULES.md#5-normalization-layer)
* [docs/06_API_AND_DATA_CONTRACTS.md#22-cryptoasset-canonical-normalized-cryptographic-asset](docs/06_API_AND_DATA_CONTRACTS.md#22-cryptoasset-canonical-normalized-cryptographic-asset)

---

### DEC-003 — Adoption of Mosca’s Inequality ($X+Y > Z$) for Quantum Migration Urgency

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Cryptography Lead & System Architect

#### Context
Organizations struggle to understand the immediate danger of quantum computing when large-scale quantum computers are still years away. A mathematical framework is needed to demonstrate why migration is urgent today.

#### Decision
Implement **Michele Mosca’s Theorem ($X + Y > Z$)** as the core urgency and timeline engine in QNetra to quantify Harvest Now, Decrypt Later (HNDL) exposure windows.

#### Reasoning
* Globally recognized by NIST, ENISA, BSI, and cybersecurity authorities.
* Clearly demonstrates that if Data Shelf Life ($X$) + Migration Time ($Y$) exceeds the Quantum Horizon ($Z$), sensitive data is already compromised.

#### Alternatives Considered
* Simple static CVSS-like vulnerability scoring alone (Rejected: fails to communicate timeline urgency and data longevity risk).

#### Consequences
* Positive: Provides executive-level clarity and mathematical justification for immediate budget and migration planning.
* Trade-off: Requires users to provide realistic estimates for $X$ and $Y$, or rely on curated industry defaults.

#### Related Modules / Data Contracts
* [docs/04_MODULES.md#9-mosca-assessment-engine](docs/04_MODULES.md#9-mosca-assessment-engine)
* [docs/05_ALGORITHMS.md#alg-05-michele-mosca-migration-inequality--urgency-evaluation](docs/05_ALGORITHMS.md#alg-05-michele-mosca-migration-inequality--urgency-evaluation)

---

### DEC-004 — Alignment with CycloneDX 1.6+ CBOM and NIST FIPS 203/204/205 Standards

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Standards & Security Lead

#### Context
Enterprises require standardized, machine-readable artifacts for software supply chain security and post-quantum readiness.

#### Decision
1. Standardize all CBOM generation on the official **CycloneDX 1.6 Cryptography Extension** specification.
2. Standardize all PQC recommendations on official NIST standards finalized in August 2024:
   * **FIPS 203 (ML-KEM)** — Key Encapsulation Mechanism
   * **FIPS 204 (ML-DSA)** — Module-Lattice-Based Digital Signature Algorithm
   * **FIPS 205 (SLH-DSA)** — Stateless Hash-Based Digital Signature Algorithm
   * **FIPS 206 (FN-DSA / Falcon)** — Fast-Fourier Lattice-Based Digital Signature

#### Reasoning
Guarantees industry-wide interoperability with enterprise vulnerability scanners, CISA guidelines, and software bill of materials (SBOM) workflows.

#### Alternatives Considered
* Custom proprietary JSON format only (Rejected: lacks ecosystem interoperability).
* Draft/Pre-standard PQC candidates (Rejected: NIST standardized final FIPS in August 2024).

#### Consequences
* Positive: Enterprise-ready compliance and future-proof outputs.
* Trade-off: Must ensure strict schema validation against official CycloneDX schemas.

#### Related Modules / Data Contracts
* [docs/04_MODULES.md#6-cbom-generator](docs/04_MODULES.md#6-cbom-generator)
* [docs/06_API_AND_DATA_CONTRACTS.md#3-cyclonedx-16-cbom-schema-alignment](docs/06_API_AND_DATA_CONTRACTS.md#3-cyclonedx-16-cbom-schema-alignment)

---

### DEC-005 — Discovery Layer Subsystem Architecture & ScannerRouter Pattern

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Core Engineering & Security Architecture

#### Context
QNetra must scan repositories, extracted containers, and binary files. Each target requires different discovery mechanics, but downstream consumers need a unified discovery contract (`ScanResult` containing `List[RawFinding]`).

#### Decision
Implement a shared Discovery Framework (`scanners.framework`) centered on an abstract `BaseScanner` lifecycle and a `ScannerRouter` that inspects targets using magic byte inspection and directory heuristics to dispatch to `RepositoryScanner`, `ContainerScanner`, or `BinaryScanner`.

#### Reasoning
* Decouples target dispatching from specific scanner internals (RULE-004).
* Allows any new scanner (e.g. cloud config scanner) to be registered dynamically without modifying router logic.
* Standardizes execution lifecycle: validation, execution, error isolation, statistics tracking, and timing.

#### Alternatives Considered
* Monolithic scanner with large if/else blocks (Rejected: poor extensibility and violates SRP).

#### Consequences
* Positive: Clean abstraction, predictable lifecycle, pluggable scanner registration.
* Trade-off: Requires common interface conformance across heterogeneous target types.

#### Related Modules / Data Contracts
* `scanners.framework`, `docs/04_MODULES.md#1-discovery-framework--router`, `docs/06_API_AND_DATA_CONTRACTS.md#22-scantarget--scanresult-discovery-pipeline-contracts`.

---

### DEC-006 — Promotion of Container and Binary Scanners to Phase 1 Discovery Subsystem

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Project Leadership & Hackathon Team

#### Context
Containerized applications and compiled binary libraries represent critical enterprise cryptographic exposure vectors that cannot be detected by source code AST scanners alone. Postponing them to Phase 3 would leave major blind spots in discovery validation.

#### Decision
Promote the initial implementations of `ContainerScanner` and `BinaryScanner` into Phase 1 alongside `RepositoryScanner`.

#### Reasoning
* Validates multi-target architecture early.
* Ensures shared registries (`scanners.registry`) and utility modules (`scanners.utils`) serve all target types from day one.
* Delivers comprehensive multi-asset discovery capability for hackathon evaluation.

#### Consequences
* Positive: Unified discovery surface across code, containers, and binaries.
* Trade-off: Required additional upfront development in Phase 1.

#### Related Modules / Data Contracts
* `scanners.container`, `scanners.binary`, `docs/04_MODULES.md`.

---

### DEC-007 — Integration of `lief` for Static Binary Symbol Inspection with Graceful Fallback

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Core Engineering & Binary Security Lead

#### Context
Binary scanning requires inspecting import/export symbol tables in ELF and PE binaries. Doing this purely via custom binary parsing is fragile, while dynamic execution violates RULE-008.

#### Decision
Adopt `lief` ($\ge 0.14.0$) for static ELF and PE symbol table parsing, while implementing a pure-Python printable string extractor and regex pattern matcher as a baseline fallback when `lief` is not available.

#### Reasoning
* `lief` is the industry standard for cross-platform static binary parsing (no code execution, purely static).
* Pure-Python fallback guarantees that the system always functions even in minimal environments without C extensions.

#### Alternatives Considered
* Dynamic execution via `gdb` / `ptrace` (Rejected: high security risk, violates RULE-008).
* Executing external `nm`/`objdump` binaries (Rejected: platform-dependent, external process dependency).

#### Consequences
* Positive: High-confidence symbol discovery without runtime security risks.
* Trade-off: `lief` is an optional binary dependency with large wheel sizes.

#### Related Modules / Data Contracts
* `scanners.binary.symbol_inspector`, `docs/04_MODULES.md#5-binary-scanner`.

---

### DEC-008 — Evolution of `RawFinding` Schema to v1.1.0 with Quantitative Multi-Signal Confidence

* **Date:** 2026-08-29
* **Status:** Accepted
* **Deciders:** Core Architecture & Discovery Team

#### Context
The draft `RawFinding` schema (`v1.0.0-draft`) used a coarse 3-tier string confidence (`HIGH`/`MEDIUM`/`LOW`) without structured metadata for extracted key sizes, cipher modes, curves, binary symbol names, or container contexts.

#### Decision
Evolve the `RawFinding` data contract to `v1.1.0`:
1. Quantitative `confidence_score` (float $0.0-1.0$) with computed 5-tier `confidence_level` enum and explainable `confidence_rationale`.
2. Explicit metadata fields: `suspected_algorithm`, `artifact_category`, `library_hint`, `key_size_hint`, `mode_hint`, `curve_hint`, `symbol_name`, `binary_format`, `container_context`.
3. Backward-compatible `to_v1_dict()` export for existing consumers.

#### Reasoning
* Enables downstream classification and normalization layers to use structured parameter hints directly.
* Ensures discovery confidence is clearly separated from quantum risk and migration urgency (RULE-002).
* Satisfies schema governance protocol in Section 6 of `docs/06_API_AND_DATA_CONTRACTS.md`.

#### Consequences
* Positive: Rich, structured evidence for normalization and CBOM generation.
* Trade-off: Slightly larger memory footprint per raw finding.

#### Related Modules / Data Contracts
* `scanners.framework.models`, `docs/06_API_AND_DATA_CONTRACTS.md#21-rawfinding-raw-scanner-finding--schema-v110`.

---

## Decision Log Index

| Decision ID | Title | Date | Status |
| :--- | :--- | :--- | :--- |
| **DEC-001** | Living Documentation & Single Source of Truth Governance | 2026-08-29 | Accepted |
| **DEC-002** | Modular Pipeline with Canonical Normalization Layer | 2026-08-29 | Accepted |
| **DEC-003** | Adoption of Mosca’s Inequality ($X+Y > Z$) for Quantum Migration Urgency | 2026-08-29 | Accepted |
| **DEC-004** | Alignment with CycloneDX 1.6+ CBOM and NIST FIPS 203/204/205 Standards | 2026-08-29 | Accepted |
| **DEC-005** | Discovery Layer Subsystem Architecture & ScannerRouter Pattern | 2026-08-29 | Accepted |
| **DEC-006** | Promotion of Container and Binary Scanners to Phase 1 Discovery Subsystem | 2026-08-29 | Accepted |
| **DEC-007** | Integration of `lief` for Static Binary Symbol Inspection with Graceful Fallback | 2026-08-29 | Accepted |
| **DEC-008** | Evolution of `RawFinding` Schema to v1.1.0 with Quantitative Multi-Signal Confidence | 2026-08-29 | Accepted |
