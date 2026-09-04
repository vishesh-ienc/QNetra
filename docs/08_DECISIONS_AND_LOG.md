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

### DEC-009 — API Contract and Frontend Product Specification Frozen Before Phase 4

* **Date:** 2026-09-02
* **Status:** Accepted
* **Deciders:** System Architect & Core Team

#### Context
Phase 4 requires two independently developed artifacts: a FastAPI backend and a frontend
application. Without a frozen, authoritative contract between them, parallel development will
produce incompatible interfaces, duplicated logic, and architectural drift.

#### Decision
Before any Phase 4 implementation begins, freeze:
1. **`docs/10_API_CONTRACT.md`** — The complete, endpoint-by-endpoint API design contract
   covering all 12 user journey stages from artifact upload through migration roadmap export.
2. **`docs/11_FRONTEND_PRODUCT_SPEC.md`** — The complete frontend product specification
   covering all screens, the end-to-end user flow, component guidance, visual direction,
   and the explicit implementation boundary separating frontend from backend and core.

#### Reasoning
* Frozen contracts enable parallel development of backend and frontend without coordination overhead.
* The contract is designed around the user journey (not internal modules), ensuring the API surface
  reflects product intent, not implementation accidents.
* Clearly documenting the implementation boundary (frontend = presentation; core = intelligence)
  prevents the frontend from duplicating risk calculations, Mosca logic, or PQC recommendations.
* Marking Phase 2/3 engine dependencies explicitly (e.g. assets require normalization) prevents
  the frontend team from building against APIs that cannot yet return data.

#### Alternatives Considered
* **Design API ad-hoc during Phase 4:** Rejected — leads to contract churn and incompatible assumptions.
* **Single combined backend+frontend monolith:** Rejected — violates the layered architecture in DEC-002 and DEC-005.

#### Consequences
* **Positive:** Frontend coding agents can start implementation against the stable contract.
  Backend team can implement routes against the same contract simultaneously.
* **Constraint:** Changes to `docs/10_API_CONTRACT.md` must follow the Section 20 governance protocol.
* **Constraint:** The frontend must not implement any logic from `core/` or `scanners/`.

#### Related Modules / Data Contracts
* `docs/10_API_CONTRACT.md`, `docs/11_FRONTEND_PRODUCT_SPEC.md`
* `docs/06_API_AND_DATA_CONTRACTS.md` (internal `RawFinding` and `CryptoAsset` schemas)
* `docs/02_SYSTEM_ARCHITECTURE.md` (layer boundaries)

---

### DEC-010 — Deterministic Normalization Architecture, Multi-Signal Aggregation, and RFC 4122 UUIDv5 Identity Strategy

* **Date:** 2026-09-03
* **Status:** Accepted
* **Deciders:** System Architect & Core Team

#### Context
Phase 1 Discovery emits heterogeneous `RawFinding` records across repositories, container filesystems, and compiled binaries. To support downstream CycloneDX 1.6 CBOM generation and deterministic quantum risk scoring, findings must be canonicalized into `CryptoAsset` models. Furthermore, multiple scanners detecting the same underlying asset (e.g. AST function call + regex match + binary symbol) must be merged into a single canonical asset without losing source evidence or producing non-deterministic asset IDs.

#### Decision
1. **Canonical Schema & Boundary:** `CryptoAsset` is established in `core/models.py`, preserving complete traceability back to all supporting `RawFinding` records via `supporting_finding_ids` and `supporting_findings`.
2. **Deduplication Strategy:** Cluster findings by normalized file path, target type, and location. In source code, findings with compatible algorithms and non-conflicting parameters within $\pm 2$ lines are merged. In binaries and container packages, findings in the same file with compatible algorithms merge into that component's asset.
3. **Deterministic Identity Strategy:** Reject random UUIDs. Generate canonical `CryptoAsset.asset_id` deterministically using RFC 4122 UUIDv5 under the QNetra namespace (`uuid.uuid5(uuid.NAMESPACE_DNS, "asset.qnetra.io")`), hashed from the canonical seed: `path:{file}|line:{anchor}|alg:{alg}|key:{key}|mode:{mode}|curve:{curve}|lib:{lib}`.
4. **Confidence Aggregation Formula:** When aggregating multiple findings, anchor to $S_{\max} = \max(s_1, \dots, s_n)$ and apply a bounded corroboration factor $B = \sum_{i \neq \max} 0.05 \times s_i$, yielding $C_{\text{agg}} = \min(1.0, S_{\max} + B)$ with an explainable text breakdown.

#### Reasoning
* Guarantees 100% idempotency across repeated scans.
* Strictly satisfies RULE-002 (explainability over black-box predictions).
* Prevents over-normalization of disjoint call sites while eliminating redundant duplicate findings.

#### Alternatives Considered
* **Random UUIDv4 generation for assets:** Rejected — causes asset ID churn across repeated runs, breaking UI caching and diffing.
* **Simple average for confidence aggregation:** Rejected — statistically unsound because adding a second corroborating finding would lower confidence below a high-confidence AST detection.

#### Consequences
* Positive: High confidence stability, reproducible CBOM BOM-refs, zero loss of raw evidence.
* Constraints: Downstream engines must consume `CryptoAsset` through `core.models`.

#### Related Modules / Data Contracts
* `core/models.py`, `core/normalization/`, `docs/04_MODULES.md#5-normalization-layer`, `docs/06_API_AND_DATA_CONTRACTS.md#22-cryptoasset-canonical-normalized-cryptographic-asset`.

---

### DEC-011 — Additive CryptoAsset Schema Extension for Classification Fields

* **Date:** 2026-09-03
* **Status:** Accepted
* **Deciders:** AI Agent (Phase 2 Milestone 2.2)

#### Context
Phase 2 Milestone 2.2 (Classification Engine) needed to store classification results on `CryptoAsset` objects. The existing schema had two placeholder fields (`quantum_vulnerable`, `quantum_threat_type`) but lacked the full set needed for classical/quantum security analysis.

#### Decision
Add five new `Optional` fields to `CryptoAsset` in `core/models.py`:
  - `classical_security_status: Optional[str]`
  - `quantum_security_status: Optional[str]`
  - `effective_classical_security_bits: Optional[int]`
  - `effective_quantum_security_bits: Optional[int]`
  - `classification_notes: Optional[str]`

All new fields default to `None` (additive, backward-compatible change). Also update `to_api_dict()` to expose these fields. Contract version bump: `v1.2.0`.

#### Reasoning
Additive-only changes are backward-compatible with all existing producers and consumers. Fields are `Optional` so no existing serialization breaks. Existing 96 tests remain green. No downstream consumers exist yet (Backend API is Phase 4).

#### Alternatives Considered
* Separate `ClassificationAnnotation` side object (Rejected: adds unnecessary indirection; CryptoAsset is the canonical unit).
* Use `metadata` dict for classification fields (Rejected: loses type safety, breaks API contract clarity).

#### Consequences
* Positive: Classification engine can enrich assets in-place without complex adapter layers.
* Positive: `to_api_dict()` automatically includes classification for API consumers.
* Trade-off: `CryptoAsset` model grows; acceptable given it is the canonical output object.

#### Related Modules / Data Contracts
* `core/models.py` (CryptoAsset), `core/classification/classifier.py`, `docs/06_API_AND_DATA_CONTRACTS.md`.

---

### DEC-012 — Classification Engine Architecture: Independent Dimensions & No-Fabrication Policy

* **Date:** 2026-09-03
* **Status:** Accepted
* **Deciders:** AI Agent (Phase 2 Milestone 2.2)

#### Context
Designing `ClassificationEngine` required decisions about: (a) how to handle unknown parameters without guessing, (b) whether classical and quantum security are independent dimensions, (c) how to integrate without duplicating the scanner registry's `QuantumThreat` enum.

#### Decision
1. **Orthogonal dimensions:** Classical security status and quantum threat type are classified independently. RSA-2048 can be `classical_security_status=SECURE` AND `quantum_threat_type=SHOR_POLYNOMIAL_BREAK` simultaneously — this is correct and intentional.
2. **No-fabrication policy:** Any parameter (`key_length_bits`, `curve`) that is `None` produces `None` estimates. Never substitute defaults (e.g., never assume AES-128 when key size is missing).
3. **Shor quantum bits = None:** Shor-vulnerable assets receive `effective_quantum_security_bits=None` always — Shor's algorithm fundamentally breaks the mathematical problem, not merely reduces key bits. Assigning any numeric value would be misleading.
4. **BHT for hash functions:** Hash function quantum security is estimated using the Brassard-Høyer-Tapp quantum collision algorithm (output_bits / 3), explicitly documented in notes. Preimage (output_bits / 2) is noted as the weaker bound.
5. **Reuse QuantumThreat:** `quantum_threat_type` field is populated with `QuantumThreat.value` strings from the scanner registry (`SHOR_POLYNOMIAL_BREAK`, `GROVER_BIT_HALVING`, etc.), extending with `"NOT_APPLICABLE"` and `"UNKNOWN"` for cases the registry doesn't cover. No duplicate enum created.

#### Reasoning
Orthogonal classification prevents incorrect correlations (e.g., "it's classically secure so it must be quantum-safe"). No-fabrication ensures downstream risk scoring (Phase 3) receives accurate inputs rather than fabricated defaults that would generate incorrect risk scores. BHT is the authoritative quantum collision bound cited by NIST SP 800-107.

#### Alternatives Considered
* Single "quantum risk level" combining classical and quantum (Rejected: collapses two independent security properties; loses RSA-2048 being "classically secure but quantum broken").
* Default AES to 128-bit when key unknown (Rejected: would generate incorrect Grover analysis for unknown-key AES — violates no-fabrication policy).

#### Consequences
* Positive: Classification is fully deterministic and auditable.
* Positive: `None` values in security bits explicitly signal missing evidence (not low security).
* Trade-off: Some assets have `quantum_vulnerable=None` — acceptable; this accurately reflects evidence gaps.

#### Related Modules / Data Contracts
* `core/classification/classifier.py`, `core/classification/knowledge.py`, `docs/05_ALGORITHMS.md (Alg-05)`.

---

### DEC-013 — CycloneDX 1.6 CBOM Generation Architecture

* **Date:** 2026-09-04
* **Status:** Accepted
* **Deciders:** AI Agent (Phase 2 Milestone 2.3)

#### Context
Milestone 2.3 required designing a CBOM serialization layer. Key design decisions included: (a) how to map QNetra `PrimitiveType` to CycloneDX 1.6 `primitive` enum values, (b) how to handle unknown parameters without fabrication, (c) how to preserve scanner evidence, (d) determinism requirements, and (e) the scope of schema validation.

#### Decision
1. **Layered architecture:** `mapper.py` handles CryptoAsset → CDXComponent translation; `serializer.py` handles BOM assembly and JSON/XML output; `validator.py` handles structural validation. Concerns are strictly separated.
2. **No-fabrication in CBOM:** If `key_length_bits=None`, `parameterSetIdentifier` is omitted. If `curve=None`, the `curve` field is omitted. Unknown parameters do not produce invented defaults in the CBOM output.
3. **qnetra: namespaced properties:** QNetra-specific metadata (asset_id, quantum threat type, classification notes, finding IDs) is preserved in CycloneDX `properties` blocks with `qnetra:` prefix to clearly separate extensions from standard fields.
4. **Evidence occurrences:** Scanner-discovered source locations are mapped to CycloneDX `evidence.occurrences` blocks for full audit traceability.
5. **Primitive routing:** `PrimitiveType.SYMMETRIC_CIPHER` maps to `ae` (when mode is in {GCM, CCM, EAX, ...}), `block-cipher` (non-AE modes or unknown mode), or `stream-cipher` (ChaCha20, RC4 families). `ML-KEM` → `kem`. `ML-DSA`/`SLH-DSA` → `post-quantum`.
6. **Deterministic serialization:** Sorted by `asset_id`, fixed serial number in deterministic mode, no live timestamps. Identical input always produces identical JSON.
7. **Structural validator (not full JSON Schema):** Implemented a targeted structural validator covering required fields, enum bounds, bom-ref uniqueness, and nistQuantumSecurityLevel range. Full JSON Schema validation deferred to CI toolchain.

#### Reasoning
No-fabrication in the CBOM is critical because downstream tools (risk engines, auditors) rely on the CBOM as an authoritative record. Fabricated key lengths would produce incorrect risk scores. The qnetra: property namespace follows CycloneDX extensibility guidelines and allows round-trip traceability.

#### Alternatives Considered
* Embed library name in `cryptoProperties.implementationLibrary` (Rejected: not a standard CDX 1.6 field at this nesting level; moved to qnetra: property).
* Full JSON Schema validation using jsonschema + official schema file (Deferred: requires network or bundled schema; structural validator is sufficient for MVP).
* Single combined serializer+validator class (Rejected: violates separation of concerns; downstream tools may want raw dict for their own validation).

#### Consequences
* Positive: CBOM output is deterministic, auditable, and compliant with CycloneDX 1.6 structure.
* Positive: Evidence traceability maintained — every CBOM component can be traced back to scanner findings.
* Positive: No-fabrication ensures CBOM is an accurate reflection of what was discovered.
* Trade-off: Full JSON Schema validation not wired in by default (toolchain concern, not application concern).

#### Related Modules / Data Contracts
* `core/cbom_generator/` (mapper, models, serializer, validator), `docs/06_API_AND_DATA_CONTRACTS.md` Section 3.

---

### DEC-014 — Deterministic Cryptographic Risk Engine Architecture & Factor Model

* **Date:** 2026-09-04
* **Status:** Accepted
* **Deciders:** AI Agent (Phase 3 Milestone 3.1)

#### Context
Milestone 3.1 required building a dedicated deterministic cryptographic risk engine (`core.risk_engine`) that converts classified `CryptoAsset` instances into an explainable 0–100 numerical risk score and 4-tier severity rating. Key architectural choices included: (a) strictly bounded 0–100 arithmetic without stochastic or ML components, (b) preventing double-counting between classical and quantum vulnerabilities, (c) handling unverified parameters without fabrication, (d) decoupling discovery confidence from mathematical risk severity, (e) isolating side-effects so batch evaluation does not mutate inputs, and (f) repository-level risk score aggregation.

#### Decision
1. **Multi-Factor Explainable Scoring (Alg-06):** Risk scores are computed as the clamped sum of discrete `RiskFactor` objects:
   - Base algorithmic class: Broken (100), Shor-vulnerable (90), Grover symmetric < 256 bits (60), Grover/BHT hash (40), Quantum-resistant classical (20), NIST PQC (0), Unknown primitive (50), Operational non-crypto (0).
   - Parameter modifiers: RSA < 2048 (+10), RSA >= 4096 (-5), AES-128 (+10), AES-256 (-10), AES-192 (-5), ECB mode (+15), PKCS#1 v1.5 (+5).
2. **Double-Counting Prevention:** Factor ownership is strictly segmented. If an algorithm is classically broken (e.g. MD5, DES), the classical factor claims 100.0 points and the quantum threat is marked superseded (0.0 points), preventing invalid 100 + 90 = 190 blowup. Similarly, Shor-vulnerable asymmetric primitives claim 90.0 points from the quantum factor; classical SECURE status adds zero redundant penalties.
3. **Strict No-Fabrication Policy:** When parameters (key length, curve) are missing, no guesses or default values are fabricated. Modifiers remain 0.0, and an explicit explainability factor notes that the parameter is unverified.
4. **Confidence Decoupling:** Discovery confidence (`confidence_score`) is preserved as descriptive metadata on `RiskAssessment` and does NOT multiply or dilute the mathematical risk score. An uncertain RSA-1024 finding is still a 100-risk asset if deployed.
5. **Purity vs. Enrichment Isolation:** `assess()` and `assess_all()` are purely functional and do NOT mutate input `CryptoAsset` objects. Explicit in-place enrichment is isolated to `assess_and_enrich()` and `assess_and_enrich_all()`.
6. **Repository Aggregation:** Repository overall score is calculated as $\min(100.0, 0.7 \times \max(S) + 0.3 \times \text{mean}(S))$, ensuring critical individual vulnerabilities are not diluted away by hundreds of low-risk hashes while still reflecting repository scale.

#### Reasoning
Strict explainability and determinism are non-negotiable for enterprise cybersecurity and compliance audits (RULE-002). Treating confidence as metadata rather than a risk multiplier prevents hazardous false senses of security.

#### Consequences
* Positive: Fully deterministic, auditable, and traceable risk assessments with zero black-box scoring.
* Positive: No regression in existing scanner or normalization subsystems.
* Positive: Direct compatibility with `docs/06_API_AND_DATA_CONTRACTS.md` and `docs/10_API_CONTRACT.md`.
* Trade-off: Repository aggregation formula weights the worst finding heavily (0.7), which intentionally errs on the side of security conservatism.

#### Related Modules / Data Contracts
* `core/risk_engine/` (`engine.py`, `scorer.py`, `models.py`, `knowledge.py`), `docs/05_ALGORITHMS.md` (Alg-06), `docs/06_API_AND_DATA_CONTRACTS.md` (Section 2.3), `docs/10_API_CONTRACT.md` (Section 9).

---

## Decision Log Index

| Decision ID | Title | Date | Status |
| :--- | :--- | :--- | :--- |
| **DEC-001** | Living Documentation & Single Source of Truth Governance | 2026-08-29 | Accepted |
| **DEC-002** | Modular Pipeline with Canonical Normalization Layer | 2026-08-29 | Accepted |
| **DEC-003** | Adoption of Mosca's Inequality ($X+Y > Z$) for Quantum Migration Urgency | 2026-08-29 | Accepted |
| **DEC-004** | Alignment with CycloneDX 1.6+ CBOM and NIST FIPS 203/204/205 Standards | 2026-08-29 | Accepted |
| **DEC-005** | Discovery Layer Subsystem Architecture & ScannerRouter Pattern | 2026-08-29 | Accepted |
| **DEC-006** | Promotion of Container and Binary Scanners to Phase 1 Discovery Subsystem | 2026-08-29 | Accepted |
| **DEC-007** | Integration of `lief` for Static Binary Symbol Inspection with Graceful Fallback | 2026-08-29 | Accepted |
| **DEC-008** | Evolution of `RawFinding` Schema to v1.1.0 with Quantitative Multi-Signal Confidence | 2026-08-29 | Accepted |
| **DEC-009** | API Contract and Frontend Product Specification Frozen Before Phase 4 | 2026-09-02 | Accepted |
| **DEC-010** | Deterministic Normalization Architecture, Multi-Signal Aggregation, and RFC 4122 UUIDv5 Identity Strategy | 2026-09-03 | Accepted |
| **DEC-011** | Additive CryptoAsset Schema Extension for Classification Fields | 2026-09-03 | Accepted |
| **DEC-012** | Classification Engine Architecture: Independent Dimensions & No-Fabrication Policy | 2026-09-03 | Accepted |
| **DEC-013** | CycloneDX 1.6 CBOM Generation Architecture | 2026-09-04 | Accepted |
| **DEC-014** | Deterministic Cryptographic Risk Engine Architecture & Factor Model | 2026-09-04 | Accepted |

