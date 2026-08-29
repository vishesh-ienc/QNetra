# 02 — System Architecture Specification

> **DOCUMENT PURPOSE:** Defines the structural topology, layered decomposition, subsystem interactions, boundaries, and architectural evolution of **QNetra**.

---

## 1. Architectural Overview

QNetra follows a **modular, layered pipeline architecture** designed for high extensibility, determinism, and performance. Each layer has strict isolation, communicating through well-defined, versioned data contracts defined in [docs/06_API_AND_DATA_CONTRACTS.md](docs/06_API_AND_DATA_CONTRACTS.md).

```mermaid
graph TD
    subgraph Layer 1: Ingestion & Scanning
        T[Target Directory / Repo] --> IS[Input Ingestion & Identifier]
        IS --> SS[Source Code Scanner<br/>AST & Heuristic Engines]
        IS --> DS[Dependency Scanner<br/>Manifest Parsers]
        IS --> BS[Binary/Container Scanner<br/>(Post-MVP)]
    end

    subgraph Layer 2: Normalization & Aggregation
        SS & DS & BS --> NL[Normalization Layer]
        NL --> CA[(Normalized CryptoAsset Repository)]
    end

    subgraph Layer 3: Core Analytics Engines
        CA --> CBOM[CBOM Generator<br/>CycloneDX 1.6+ Engine]
        CA --> RE[Quantum Risk Engine<br/>Shor/Grover Vulnerability Matrix]
        CA & RE --> ME[Mosca Assessment Engine<br/>X + Y > Z Gap Simulator]
        CA & RE & ME --> REC[PQC Recommendation Engine<br/>NIST FIPS 203/204/205 Mapping]
    end

    subgraph Layer 4: Service & Integration Layer
        CBOM & RE & ME & REC --> API[FastAPI / REST Gateway]
        API --> EX[Export Engine<br/>JSON / PDF / CSV]
    end

    subgraph Layer 5: Presentation Layer
        API <--> UI[Web Dashboard<br/>React + Tailwind / Vanilla CSS]
        API <--> CLI[QNetra CLI Tool]
    end
```

---

## 2. Major Architectural Layers

### Layer 1: Ingestion & Scanning Layer (`/scanners`)
* **Responsibility:** Ingests target repositories, discovers files, and parses source code and package manifests.
* **Key Components:**
  * **Input Manager:** Recursively traverses directories while respecting `.gitignore` and exclusion lists.
  * **Source Scanner:** Employs AST parsers and regex signature engines for language-specific cryptographic API identification (Python `cryptography`/`pycryptodome`, JS `crypto`/`node-forge`, Java `javax.crypto`/`BouncyCastle`, Go `crypto/*`).
  * **Dependency Scanner:** Parses package manifests (`package.json`, `pom.xml`, `requirements.txt`, `go.mod`) to extract direct and transitive crypto dependencies.
* **Output:** Emits raw findings (`RawFinding`) to the Normalization Layer.

### Layer 2: Normalization & Aggregation Layer (`/core/normalization`)
* **Responsibility:** Translates heterogeneous raw scanner findings into the canonical, strongly-typed `CryptoAsset` schema.
* **Key Components:**
  * **Primitive Normalizer:** Resolves algorithm aliases (e.g. `AES_256_CBC`, `AES/CBC/PKCS5Padding`, `aes256` -> Canonical `AES-256-CBC`).
  * **Deduplication Engine:** Merges duplicate findings originating from multiple scanner passes on the same source location.
  * **Context Enricher:** Tags assets with file paths, line numbers, variable contexts, and usage categories (Key Exchange, Encryption, Signature, Hash).

### Layer 3: Core Analytics Engines (`/core`)
* **Responsibility:** Performs cryptographic evaluation, standard-compliant formatting, and quantum threat modeling.
* **Key Components:**
  * **CBOM Generator (`/core/cbom`):** Synthesizes normalized assets into an official **CycloneDX 1.6+ Cryptography Extension** BOM.
  * **Quantum Risk Engine (`/core/risk`):** Assigns deterministic vulnerability scores (0–100) and severity ratings (Critical, High, Medium, Low) based on quantum threat vectors (Shor's algorithm for PKC, Grover's algorithm for symmetric).
  * **Mosca Assessment Engine (`/core/mosca`):** Executes Michele Mosca’s inequality ($X + Y > Z$) using enterprise inputs (Data Shelf Life $X$, Migration Time $Y$, and Quantum Threat Horizon $Z$) to calculate critical exposure years.
  * **PQC & Hybrid Recommendation Engine (`/core/recommendations`):** Maps identified vulnerable primitives to standardized NIST PQC replacements (ML-KEM, ML-DSA, SLH-DSA) and hybrid schemes.

### Layer 4: Service & Integration Layer (`/backend`)
* **Responsibility:** Exposes RESTful API endpoints for target orchestration, scan execution, and data retrieval.
* **Key Components:**
  * **Scan Controller:** Coordinates scanning jobs and asynchronous analysis.
  * **Export Service:** Formats analysis payloads into CycloneDX JSON, structured CSVs, and executive PDF reports.
  * **Storage Interface:** In-memory store for interactive sessions with optional SQLite persistence for historical audits.

### Layer 5: Presentation Layer (`/frontend` & CLI)
* **Responsibility:** Delivers high-impact, interactive visualizations for security teams, developers, and executives.
* **Key Components:**
  * **Executive Summary View:** High-level metrics, total assets, quantum risk distribution, and critical vulnerabilities.
  * **CBOM Explorer:** Filterable, searchable table of all cryptographic assets with key lengths, curves, and file origins.
  * **Mosca Timeline Simulator:** Interactive slider widget to simulate variations in $X$, $Y$, and $Z$, visualizing the HNDL risk window.
  * **PQC Migration Roadmap:** Actionable remediation guide detailing replacement algorithms and migration difficulty.

---

## 3. Storage & Persistence Strategy

* **In-Memory Cache (MVP Default):** Scans execute in-memory with immediate JSON serialization to maximize speed, portability, and zero-dependency operation.
* **Persistent Local Store (Under Evaluation):** Lightweight SQLite database for multi-scan historical trend analysis and repository diffing across time.
* **Artefact Store:** File-system based storage for generated CycloneDX CBOM JSON files and exportable reports.

---

## 4. Technology Stack Strategy (Under Evaluation / Proposed)

| Layer | Proposed Technology | Evaluation Rationale | Status |
| :--- | :--- | :--- | :--- |
| **Core Engines** | Python 3.11+ | Rich AST ecosystem, rapid development, native crypto libraries | **Proposed** |
| **Backend API** | FastAPI / Uvicorn | Async performance, native OpenAPI documentation, Pydantic data validation | **Proposed** |
| **Frontend UI** | Modern Web (React / Vite + CSS) | Reactive component state, interactive charts (Chart.js / Recharts), premium dark UI | **Proposed** |
| **CBOM Schema** | CycloneDX 1.6+ JSON Schema | Official OWASP & CISA endorsed standard for Cryptographic BOMs | **Approved (DEC-004)** |
| **PQC Standards** | NIST FIPS 203, 204, 205 | Formally standardized post-quantum algorithms (August 2024) | **Approved (DEC-004)** |

---

## 5. External Integrations & Standards

1. **CycloneDX 1.6+:** Full alignment with the CycloneDX Cryptography specification (`crypto-asset`, `algorithm`, `key-length`, `quantum-security-level`).
2. **NIST PQC Standards:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 (FN-DSA).
3. **NIST SP 800-56C & 800-131A:** Transition guidelines for classical algorithm deprecation and key lengths.
4. **BSI & ENISA Technical Guidelines:** Migration timelines and quantum resilience recommendations.

---

## 6. Architectural Assumptions & Invariants

* **Invariant 1:** Scanner modules MUST remain stateless and independent. Adding a new language scanner requires zero modifications to the Risk or Mosca engines.
* **Invariant 2:** The Normalization Layer is the single source of truth for downstream data ingestion.
* **Invariant 3:** All risk scores and Mosca calculations MUST be deterministically reproducible from the same input payload.

---

## 7. Architecture Change History

| Date | Change Summary | Decision Reference | Approved By |
| :--- | :--- | :--- | :--- |
| 2026-08-29 | Initial layered modular architecture defined | [DEC-001](docs/08_DECISIONS_AND_LOG.md#dec-001--living-documentation--single-source-of-truth-governance), [DEC-002](docs/08_DECISIONS_AND_LOG.md#dec-002--modular-pipeline-with-canonical-normalization-layer) | Team Architecture Lead |
