# 06 — API & Data Contracts Specification

> **DOCUMENT PURPOSE:** The canonical source of truth for all shared data schemas, intermediate models, CBOM formats, and API interfaces in **QNetra**.
> **CRITICAL RULE:** No agent or developer may silently alter these contracts without following the modification governance protocol in Section 6.

---

## 1. Schema Versioning & Status

* **Contract Version:** `v1.2.0` (Discovery, Normalization, & Classification Layer)
* **Status:** Active Specification
* **CBOM Standard:** CycloneDX 1.6 Cryptography Extension
* **Serialization Format:** JSON (Pydantic v2 validation)

---

## 2. Core Internal Data Contracts

### 2.1. `RawFinding` (Raw Scanner Finding — Schema v1.1.0)
* **Purpose:** Emitted by scanner modules to record discovered cryptographic invocations and evidence before normalization.
* **Producer:** `scanners.repository`, `scanners.container`, `scanners.binary`
* **Consumer:** `core.normalization`

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `finding_id` | `string` (UUID) | Yes | Unique identifier for raw finding (auto-generated) |
| `scanner_name` | `string` | Yes | Identifier of scanner (e.g. `RepositoryScanner/PythonAnalyzer`, `BinaryScanner`) |
| `discovery_method` | `enum` | Yes | `ast`, `regex`, `import_analysis`, `api_call`, `symbol_inspection`, `string_analysis`, `library_detection`, `package_inspection` |
| `raw_symbol` | `string` | Yes | Unprocessed API call, import, or token (e.g. `RSA.generate(2048)`) |
| `suspected_algorithm` | `string` | No | Initial algorithm identified prior to normalization (e.g. `RSA`, `AES`) |
| `artifact_category` | `enum` | Yes | `ASYMMETRIC_PKC`, `SYMMETRIC_CIPHER`, `HASH_FUNCTION`, `MAC`, `KDF`, `DIGITAL_SIGNATURE`, `KEY_EXCHANGE`, `PROTOCOL`, `CERTIFICATE`, `KEY_MATERIAL`, `LIBRARY`, `RANDOM`, `UNKNOWN` |
| `library_hint` | `string` | No | Suspected library name (e.g. `pycryptodome`, `OpenSSL`, `javax.crypto`) |
| `key_size_hint` | `integer` | No | Extracted key size in bits if present (e.g. `2048`, `256`) |
| `mode_hint` | `string` | No | Extracted cipher mode if present (e.g. `GCM`, `CBC`) |
| `curve_hint` | `string` | No | Extracted elliptic curve if present (e.g. `secp256r1`) |
| `raw_parameters` | `object` | No | Extracted parameter dictionary |
| `location` | `FileLocation` | Yes | `file_path` (relative), `start_line`, `end_line`, `snippet`, `byte_offset` |
| `confidence_score` | `float` (0.0–1.0) | Yes | Quantitative multi-signal confidence score |
| `confidence_level` | `enum` | Yes (computed) | `VERY_HIGH` ($\ge 0.85$), `HIGH` ($0.70-0.84$), `MEDIUM` ($0.45-0.69$), `LOW` ($0.25-0.44$), `VERY_LOW` ($< 0.25$) |
| `confidence_rationale` | `string` | Yes | Human-readable explanation of score calculation |
| `binary_format` | `enum` | No | `ELF`, `PE`, `MACHO`, `ARCHIVE`, `UNKNOWN` (binary scans) |
| `symbol_name` | `string` | No | Symbol name from binary import/export table |
| `container_context` | `object` | No | `image_reference`, `layer_id`, `filesystem_path` |

```json
{
  "finding_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "scanner_name": "RepositoryScanner/PythonAnalyzer",
  "discovery_method": "ast",
  "raw_symbol": "RSA.generate(2048, e=65537)",
  "suspected_algorithm": "RSA",
  "artifact_category": "ASYMMETRIC_PKC",
  "library_hint": "pycryptodome",
  "key_size_hint": 2048,
  "mode_hint": null,
  "curve_hint": null,
  "raw_parameters": {
    "key_size": 2048
  },
  "location": {
    "file_path": "src/security/crypto_manager.py",
    "start_line": 42,
    "end_line": 44,
    "snippet": "key = RSA.generate(2048, e=65537)",
    "byte_offset": null
  },
  "confidence_score": 0.95,
  "confidence_level": "VERY_HIGH",
  "confidence_rationale": "AST-confirmed cryptographic API call (0.95) | Matched known crypto API registry (+0.02) → Final: 0.95"
}
```

> **Backward Compatibility Note:** `RawFinding.to_v1_dict()` is provided to export in the original `v1.0.0-draft` 3-tier string format (`HIGH`/`MEDIUM`/`LOW`).

---

### 2.2. `ScanTarget` & `ScanResult` (Discovery Pipeline Contracts)

#### `ScanTarget`
* **Purpose:** Represents an invocation target passed into the scanner router.
* **Fields:** `target_id` (UUID), `path` (str), `target_type` (`REPOSITORY`, `CONTAINER_FS`, `BINARY`, `AUTO`), `options` (`ScanOptions`), `metadata` (dict).

#### `ScanResult`
* **Purpose:** The canonical output of any scanner execution.
* **Fields:** `scan_id` (UUID), `target` (`ScanTarget`), `scanner_name` (str), `scanner_version` (str), `status` (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `PARTIAL`), `started_at` (datetime), `completed_at` (datetime), `duration_seconds` (float), `findings` (`List[RawFinding]`), `statistics` (`ScanStatistics`), `errors` (`List[str]`), `warnings` (`List[str]`).

---

### 2.3. `CryptoAsset` (Canonical Normalized Cryptographic Asset — Schema v1.2.0)
* **Purpose:** Canonical schema representing a verified, normalized, and classified cryptographic asset across all layers.
* **Producer:** `core.normalization` (instantiation & deduplication), `core.classification` (security status & parameter enrichment)
* **Consumer:** `core.cbom_generator`, `core.risk_engine`, `core.mosca_engine`, `core.recommendation_engine`, `backend.api`
* **Status:** Implemented (`v1.2.0`)

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `asset_id` | `string` (UUIDv5) | Yes | Deterministic RFC 4122 UUIDv5 generated from canonical identity seed |
| `algorithm` | `string` | Yes | Standardized algorithm name (e.g. `RSA`, `AES-256-GCM`, `SHA-256`, `ECDSA`) |
| `algorithm_family` | `string` | No | Algorithmic family (e.g. `RSA`, `AES`, `SHA`, `ECC`, `CHACHA`, `ML-KEM`) |
| `primitive_type` | `enum` | Yes | `ASYMMETRIC_ENCRYPTION`, `DIGITAL_SIGNATURE`, `KEY_EXCHANGE`, `SYMMETRIC_CIPHER`, `HASH_FUNCTION`, `MAC`, `KDF`, `PROTOCOL`, `LIBRARY`, `CERTIFICATE`, `KEY_MATERIAL`, `RANDOM`, `UNKNOWN` |
| `key_length_bits` | `integer` | No | Key size or modulus length in bits (e.g. `2048`, `256`) |
| `curve` | `string` | No | Standardized elliptic curve name (e.g. `secp256r1`, `Ed25519`, `Curve25519`) |
| `mode` | `string` | No | Cipher mode of operation (e.g. `GCM`, `CBC`, `CTR`) |
| `padding` | `string` | No | Padding scheme (e.g. `PKCS1_OAEP`, `PKCS7`, `NoPadding`) |
| `implementation_library`| `string` | No | Canonical library name (e.g. `pycryptodome`, `OpenSSL`, `BouncyCastle`, `javax.crypto`) |
| `location` | `FileLocation` | Yes | Primary source location (file path, line range, snippet, byte offset) |
| `locations` | `List[FileLocation]` | Yes | All contributing source locations across supporting findings |
| `supporting_finding_ids` | `List[string]` | Yes | List of `RawFinding.finding_id` strings corroborating this asset |
| `supporting_findings` | `List[SupportingEvidence]` | Yes | Preserved evidentiary findings with snippets, methods, and individual scores |
| `confidence_score` | `float` (0.0–1.0) | Yes | Deterministic multi-signal aggregated confidence score |
| `confidence_level` | `enum` | Yes | `VERY_HIGH`, `HIGH`, `MEDIUM`, `LOW`, `VERY_LOW` |
| `confidence_rationale` | `string` | Yes | Explainable mathematical breakdown of score and corroboration bonus |
| `metadata` | `object` | Yes | Symbols, binary format, container context, extracted parameter dictionaries |
| `classical_security_status` | `enum` | No | Phase 2.2 Classification: `SECURE`, `WEAK`, `BROKEN`, `UNKNOWN` |
| `quantum_vulnerable` | `boolean` | No | Phase 2.2 Classification: `true` if vulnerable to Shor or Grover, `false` if safe, `null` if unknown |
| `quantum_threat_type` | `string` | No | Phase 2.2 Classification: `SHOR_POLYNOMIAL_BREAK`, `GROVER_BIT_HALVING`, `QUANTUM_RESISTANT`, `CLASSICALLY_BROKEN`, `NOT_APPLICABLE`, `UNKNOWN` |
| `quantum_security_status` | `enum` | No | Phase 2.2 Classification: `SAFE`, `DEGRADED`, `CRITICAL`, `UNKNOWN` |
| `effective_classical_security_bits` | `integer` | No | Phase 2.2 Classification: NIST SP 800-57 equivalent classical bits (`112`, `128`, `256`) |
| `effective_quantum_security_bits` | `integer` | No | Phase 2.2 Classification: Post-quantum security bits (Grover: $K/2$, BHT: $N/3$, Shor: `null`) |
| `classification_notes` | `string` | No | Phase 2.2 Classification: Deterministic explainable rationale for classical & quantum assessments |
| `risk_score` | `integer` (0-100) | No | Phase 3 Risk Engine placeholder |
| `risk_severity` | `enum` | No | Phase 3 Risk Engine placeholder |
| `recommendation_id` | `string` | No | Phase 3 Recommendation placeholder |

```json
{
  "asset_id": "c1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
  "algorithm": "RSA",
  "algorithm_family": "RSA",
  "primitive_type": "ASYMMETRIC_ENCRYPTION",
  "key_length_bits": 2048,
  "curve": null,
  "mode": null,
  "padding": "PKCS1_OAEP",
  "implementation_library": "pycryptodome",
  "location": {
    "file_path": "src/security/crypto_manager.py",
    "start_line": 42,
    "end_line": 44,
    "byte_offset": null,
    "snippet": "key = RSA.generate(2048, e=65537)"
  },
  "locations": [
    {
      "file_path": "src/security/crypto_manager.py",
      "start_line": 42,
      "end_line": 44,
      "snippet": "key = RSA.generate(2048, e=65537)"
    }
  ],
  "supporting_finding_ids": [
    "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
    "a2b94fae-7dec-11d0-a765-00a0c91e6bf7"
  ],
  "confidence_score": 0.965,
  "confidence_level": "VERY_HIGH",
  "confidence_rationale": "Multi-finding aggregated confidence (2 findings across RepositoryScanner/PythonAnalyzer): base anchor 0.95 (AST) + corroboration bonus (+0.02 via AST, REGEX) -> Final: 0.97",
  "classical_security_status": "SECURE",
  "quantum_vulnerable": true,
  "quantum_threat_type": "SHOR_POLYNOMIAL_BREAK",
  "quantum_security_status": "CRITICAL",
  "effective_classical_security_bits": 112,
  "effective_quantum_security_bits": null,
  "classification_notes": "[HIGH] Classical [SECURE]: RSA-2048 classical security: SECURE (~112 bits equivalent, NIST SP 800-57 Table 2). | Quantum [CRITICAL]: RSA is vulnerable to Shor's algorithm (polynomial-time quantum attack).",
  "risk_score": null,
  "risk_severity": null
}
```

#### Deduplication & Aggregation Specifications
1. **Source Code Statements:** Findings within the same source file matching compatible algorithm representations and non-conflicting parameters within $\pm 2$ lines are merged into a single asset.
2. **Binary Targets:** Findings within the same compiled binary matching the same algorithm and compatible parameters merge into that binary's asset.
3. **Container Context:** Findings within the same container path matching the same library/package merge into a single asset.
4. **Deterministic Identity Strategy:** Asset IDs are generated via RFC 4122 UUIDv5 with seed `path:{file}|line:{line}|alg:{alg}|key:{key}|mode:{mode}|curve:{curve}|lib:{lib}` under DNS namespace `asset.qnetra.io`.
5. **Confidence Aggregation Formula:** $C_{\text{agg}} = \min\left(1.0, S_{\max} + \sum_{i \neq \max} 0.05 \times s_i\right)$, strictly monotonic and explainable.

---

### 2.3. `RiskAssessmentReport` (Quantum Risk Evaluation)
* **Purpose:** Quantifies risk levels, aggregate scores, and vulnerability breakdowns.
* **Producer:** `core.risk_engine`
* **Consumer:** `backend.api`, `frontend`, `core.mosca_engine`
* **Status:** Implemented (`v1.0.0` — Milestone 3.1)

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `overall_risk_score` | `number` (0–100) | Yes | Normalized aggregate repository risk score |
| `overall_severity` | `enum` | Yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `QUANTUM_RESISTANT` |
| `total_assets_discovered` | `integer` | Yes | Count of all cryptographic assets |
| `vulnerable_assets_count` | `integer` | Yes | Count of quantum-vulnerable assets |
| `shor_vulnerable_count` | `integer` | Yes | Asymmetric assets broken by Shor's algorithm |
| `grover_impacted_count` | `integer` | Yes | Symmetric assets impacted by Grover's algorithm |
| `asset_scores` | `array` (`AssetRiskDetail`) | Yes | Individual risk score and reasoning per asset |

```json
{
  "overall_risk_score": 88.5,
  "overall_severity": "CRITICAL",
  "total_assets_discovered": 14,
  "vulnerable_assets_count": 11,
  "shor_vulnerable_count": 8,
  "grover_impacted_count": 3,
  "asset_scores": [
    {
      "asset_id": "c1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
      "score": 90,
      "severity": "CRITICAL",
      "rationale": "RSA-2048 is completely vulnerable to Shor's algorithm polynomial time key recovery."
    }
  ]
}
```

---

### 2.4. `MoscaAssessmentReport` (Mosca Migration Urgency)
* **Purpose:** Computes exposure window and timeline under $X + Y > Z$.
* **Producer:** `core.mosca_engine`
* **Consumer:** `backend.api`, `frontend`

| Field | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `is_vulnerable` | `boolean` | Yes | `true` if $X + Y > Z$ |
| `data_shelf_life_years_x`| `number` | Yes | Configured data confidentiality requirement ($X$) |
| `migration_time_years_y` | `number` | Yes | Configured enterprise migration timeline ($Y$) |
| `quantum_threat_horizon_z`| `number` | Yes | Projected years until CRQC arrival ($Z$) |
| `exposure_gap_years` | `number` | Yes | Calculated $(X+Y) - Z$ vulnerability gap |
| `deadline_year` | `integer` | Yes | Latest year migration must start to avoid HNDL breach |
| `urgency_rating` | `enum` | Yes | `CRITICAL_IMMEDIATE`, `HIGH_PRIORITY`, `CONTROLLED_TRANSITION` |
| `hndl_alert` | `boolean` | Yes | Indicates active Harvest Now Decrypt Later risk |

```json
{
  "is_vulnerable": true,
  "data_shelf_life_years_x": 10.0,
  "migration_time_years_y": 4.0,
  "quantum_threat_horizon_z": 8.0,
  "exposure_gap_years": 6.0,
  "deadline_year": 2024,
  "urgency_rating": "CRITICAL_IMMEDIATE",
  "hndl_alert": true
}
```

---

### 2.5. `PQCRecommendationReport` (Post-Quantum Recommendations)
* **Purpose:** Delivers actionable migration strategies for vulnerable primitives.
* **Producer:** `core.recommendation_engine`
* **Consumer:** `backend.api`, `frontend`

```json
{
  "recommendations": [
    {
      "target_asset_id": "c1a93e3d-3b1a-4c28-98e3-a4c3e21199a0",
      "current_primitive": "RSA-2048",
      "usage_context": "Key Encapsulation / Exchange",
      "primary_pqc_replacement": "ML-KEM-768",
      "pqc_standard": "NIST FIPS 203",
      "recommended_hybrid": "X25519 + ML-KEM-768",
      "migration_complexity": "MEDIUM",
      "guidance_steps": [
        "Abstract key encapsulation logic behind a crypto service interface.",
        "Deploy hybrid X25519/ML-KEM-768 key exchange for backward compatibility.",
        "Upgrade client endpoints to support larger post-quantum ciphertext payloads."
      ]
    }
  ]
}
```

---

## 3. CycloneDX 1.6 CBOM Schema Alignment

QNetra generates CBOMs compliant with the official **CycloneDX 1.6 Cryptography Extension** format:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-08-29T16:00:00Z",
    "tools": [
      {
        "vendor": "QNetra",
        "name": "QNetra ECDAT Engine",
        "version": "1.0.0"
      }
    ]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "crypto-asset-001",
      "name": "RSA-2048 Keypair",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "public-key-encryption",
          "parameterSetIdentifier": "2048",
          "curve": null,
          "executionEnvironment": "software-plain-text"
        },
        "oid": "1.2.840.113549.1.1.1"
      }
    }
  ]
}
```

---

## 4. API Endpoints & Request/Response Contracts

### 4.1. `POST /api/scan` — Initiate Scan
* **Request Payload:**
```json
{
  "target_path": "c:/Users/VISHESH/Desktop/sample-repo",
  "scan_options": {
    "enable_ast": true,
    "enable_manifests": true,
    "enable_heuristics": true,
    "exclude_patterns": ["node_modules", "venv", ".git"]
  },
  "mosca_params": {
    "data_shelf_life_x": 10,
    "migration_time_y": 3,
    "quantum_threat_horizon_z": 8
  }
}
```
* **Response (200 OK):** Complete `ScanResultEnvelope` containing assets, CBOM, risk, Mosca, and recommendation payloads.

---

### 4.2. `POST /api/mosca/simulate` — Interactive Mosca Recalculation
* **Request Payload:**
```json
{
  "data_shelf_life_x": 15,
  "migration_time_y": 5,
  "quantum_threat_horizon_z": 7
}
```
* **Response (200 OK):** `MoscaAssessmentReport`.

---

### 4.3. `GET /api/export/{scan_id}?format={cyclonedx|csv|pdf}` — Download Exports
* **Response:** File stream with appropriate MIME type (`application/json`, `text/csv`, `application/pdf`).

---

## 5. Contract Governance & Modification Protocol

Any proposed modification to schemas in this document must follow this sequence:

1. **Impact Analysis:** Identify all affected producer modules, consumer modules, and test suites.
2. **Document Update:** Propose the updated JSON schema in this document with version increment.
3. **Architecture Decision Record (ADR):** Record reasoning in [docs/08_DECISIONS_AND_LOG.md](docs/08_DECISIONS_AND_LOG.md).
4. **Synchronized Code Updates:** Update all producers and consumers in the same atomic commit.
