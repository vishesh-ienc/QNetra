# PROJECT_RULES.md — Project Governance & Engineering Rules

> **PURPOSE:** This document is the evolving, enforceable rule and constraint layer for **QNetra**.
> Every contributor and AI agent must read this file before performing work and strictly adhere to all active rules.
> New rules, architectural constraints, and development guidelines must be appended here with traceable metadata.

---

## Rule Format Standard

Every rule in this document follows this structure:

```markdown
### RULE-XXX — [Rule Title]
* **Date Added:** YYYY-MM-DD
* **Category:** [Active Development | Architecture | Data & API | Coding | Documentation | Testing | Scope]
* **Status:** [Active | Proposed | Deprecated | Temporary]
* **Rule:** [Clear, unambiguous statement of the constraint]
* **Reason:** [Architectural, security, or business rationale]
* **Enforcement:** [How this rule is verified or tested]
```

---

## Active Development Rules

### RULE-001 — Scanner Normalization Requirement
* **Date Added:** 2026-08-29
* **Category:** Active Development
* **Status:** Active
* **Rule:** All scanner modules (Source Scanner, Dependency Scanner, Container/Binary Scanner) MUST output findings conformant to the canonical `CryptoAsset` normalized schema defined in [docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md).
* **Reason:** Guarantees decoupling between scanner implementations and downstream analysis engines (CBOM generator, Risk Engine, Mosca Calculator).
* **Enforcement:** Schema validation unit tests run against all scanner outputs.

### RULE-002 — Explainability Over Black-Box Models
* **Date Added:** 2026-08-29
* **Category:** Active Development
* **Status:** Active
* **Rule:** Cryptographic risk quantification and Mosca timeline assessments MUST be deterministic, formulaic, and explainable. Do not use opaque AI/ML black-box predictions for risk scoring without deterministic justification.
* **Reason:** Enterprise security auditors and CISOs require transparent, auditable mathematical logic (e.g. Shor/Grover vulnerability classifications, Mosca’s inequality $X+Y > Z$).
* **Enforcement:** Risk engine test cases asserting exact score breakdowns and formula outputs.

### RULE-003 — Continuous Documentation Synchronization
* **Date Added:** 2026-08-29
* **Category:** Documentation
* **Status:** Active
* **Rule:** No development task is complete until all affected documentation files in `/docs` are synchronized. Contributors and agents must not wait for explicit user prompts to update docs.
* **Reason:** Prevents architectural drift and ensures that any AI agent or team member can immediately understand the project state.
* **Enforcement:** Code review checklist and agent self-verification step.

---

## Architecture Constraints

### RULE-004 — Layered Separation of Concerns
* **Date Added:** 2026-08-29
* **Category:** Architecture
* **Status:** Active
* **Rule:** The repository architecture must maintain strict layer separation:
  1. Ingestion / Scanning Layer
  2. Normalization Layer
  3. Core Analytics Engines (CBOM, Risk, Mosca, PQC Recommendation)
  4. API / Backend Services
  5. Presentation / UI Layer
  Direct cross-layer bypasses (e.g. UI directly calling a raw scanner without going through the normalized API) are prohibited.
* **Reason:** Allows modular upgrades (e.g. adding new language scanners without touching the risk engine).
* **Enforcement:** Architectural module review and import dependency checks.

### RULE-005 — Standards Compliance for CBOM and PQC
* **Date Added:** 2026-08-29
* **Category:** Architecture
* **Status:** Active
* **Rule:** CBOM exports must comply with the CycloneDX 1.6+ Cryptography Extension specification. Post-Quantum Cryptography recommendations must adhere to NIST PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
* **Reason:** Ensures industry interoperability and compliance with enterprise security tooling and government mandates.
* **Enforcement:** CycloneDX CBOM validation tests against official JSON schema.

---

## Data & API Constraints

### RULE-006 — Explicit Shared Contract Modifications
* **Date Added:** 2026-08-29
* **Category:** Data & API
* **Status:** Active
* **Rule:** No agent or developer may silently alter existing schemas or API response formats in [docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md). Any schema modification requires:
  1. Updating the schema documentation in `docs/06_API_AND_DATA_CONTRACTS.md`.
  2. Updating all producer and consumer modules.
  3. Logging an Architecture Decision Record in `docs/08_DECISIONS_AND_LOG.md` if breaking.
* **Reason:** Prevents breaking integrations between backend, frontend, and scanner modules.
* **Enforcement:** Automated schema contracts and serialization tests.

---

## Coding Constraints

### RULE-007 — Dependency & Library Governance
* **Date Added:** 2026-08-29
* **Category:** Coding
* **Status:** Active
* **Rule:** Do not add heavy external libraries, unmaintained packages, or complex native binaries without explicit architectural justification. Prefer standard library capabilities and well-maintained AST parsing tools.
* **Reason:** Keeps the scanner lightweight, portable across Windows/Linux/macOS, and reduces security vulnerabilities in QNetra itself.
* **Enforcement:** Package manifest lockfiles and dependency audits.

### RULE-008 — Passive & Non-Destructive Scanning
* **Date Added:** 2026-08-29
* **Category:** Coding
* **Status:** Active
* **Rule:** Scanners must operate purely in passive, read-only inspection mode. QNetra must NEVER execute untrusted code found in target repositories, modify target source files without explicit user consent, or send target source code to external unapproved third parties.
* **Reason:** Safety, privacy, and compliance requirements for enterprise codebases.
* **Enforcement:** Read-only file handle operations during static analysis.

---

## Documentation Rules

### RULE-009 — Traceable Architecture Decisions
* **Date Added:** 2026-08-29
* **Category:** Documentation
* **Status:** Active
* **Rule:** Any significant architectural decision (such as choosing a database, adopting a new parser, or redefining risk weightings) must be recorded as an ADR (`DEC-XXX`) in [docs/08_DECISIONS_AND_LOG.md](docs/08_DECISIONS_AND_LOG.md).
* **Reason:** Ensures long-term context retention across a multi-person hackathon team and subsequent development phases.
* **Enforcement:** Code review gate.

### RULE-012 — Mandatory Per-Prompt Update File (current_prompt_update.md)
* **Date Added:** 2026-09-03
* **Category:** Documentation
* **Status:** Active
* **Rule:** At the conclusion of every single user prompt and agent turn, the file [`current_prompt_update.md`](current_prompt_update.md) at the repository root MUST be updated/overwritten with a concise, structured summary of the current prompt's implementation. This includes prompt metadata, summary of implementation actions, table of modified/created files, test and verification results, and context handoff for the next prompt.
* **Reason:** Ensures absolute real-time visibility into the exact changes made in each prompt turn without relying on volatile chat logs or manual diff inspections.
* **Enforcement:** Mandatory self-verification check on every agent turn before reporting completion to the user.

---

## Testing Rules

### RULE-010 — Mandatory Test Fixtures for Cryptographic Primitives
* **Date Added:** 2026-08-29
* **Category:** Testing
* **Status:** Active
* **Rule:** Every scanner pattern (e.g. RSA key generation detection, AES mode detection, hardcoded private keys) must have a corresponding test sample in `/samples` and an automated unit test in `/tests`.
* **Reason:** Prevents regression in cryptographic discovery accuracy and eliminates false positives/negatives.
* **Enforcement:** CI test suite execution.

---

## Scope Constraints

### RULE-011 — MVP Prioritization First
* **Date Added:** 2026-08-29
* **Category:** Scope
* **Status:** Active
* **Rule:** Features outside the Core MVP (e.g., live kernel memory dumping, dynamic binary instrumentations, hardware security module extraction) must remain deferred to Post-MVP until core source scanning, CBOM generation, risk scoring, and the Mosca migration dashboard are complete and validated.
* **Reason:** Delivers a complete, polished, functional prototype within hackathon deadlines.
* **Enforcement:** Scope verification in [docs/01_PROJECT_SCOPE.md](docs/01_PROJECT_SCOPE.md) and [docs/07_PROGRESS.md](docs/07_PROGRESS.md).

---

## Temporary Rules

*(No active temporary rules at initialization.)*

---

## Deprecated Rules

*(No deprecated rules at initialization.)*

---

## Rule Change Log

| Date | Rule ID | Action | Summary | Author |
| :--- | :--- | :--- | :--- | :--- |
| 2026-08-29 | RULE-001 to RULE-011 | Created | Initial repository engineering and governance rules established | System Initialization |
| 2026-09-03 | RULE-012 | Created | Mandated maintenance of current_prompt_update.md on every prompt turn | System Governance |
