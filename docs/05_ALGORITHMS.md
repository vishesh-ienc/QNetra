# 05 — Algorithms, Heuristics & Decision Logic

> **DOCUMENT PURPOSE:** Authoritative technical specification of all discovery methods, risk quantification formulas, Mosca timeline assessments, and Post-Quantum recommendation algorithms implemented in **QNetra**.

---

## 1. Cryptographic Discovery Methods

### Alg-01: Static AST-Based Cryptographic Primitive Extraction
* **Name:** Abstract Syntax Tree (AST) Cryptographic Parser
* **Module:** `scanners.repository.languages.python_analyzer`
* **Purpose:** Inspects source code to accurately detect cryptographic library imports, function calls, and parameter instantiations without executing the code.
* **Inputs:** Source code file contents (Python `ast.parse`).
* **Processing:**
  1. Parse source code into an Abstract Syntax Tree using Python's stdlib `ast` module.
  2. Traverse nodes looking for `Import` / `ImportFrom` references matching known crypto modules (e.g. `cryptography.hazmat`, `Crypto.Cipher`, `hashlib`).
  3. Identify `Call` nodes to key generation, cipher initialization, hashing, or signing functions against `scanners.registry.crypto_api_map`.
  4. Extract literal arguments (e.g., key sizes like `2048`, cipher modes like `AES.MODE_CBC`, curve names like `secp256r1`).
  5. Capture code location (filename, start line, end line, snippet).
* **Outputs:** `List[RawFinding]` containing structured call details and arguments.
* **Assumptions:** Target code is syntactically valid code in supported languages.
* **Limitations:** Dynamic code evaluation (`eval`, dynamic reflection) may obscure parameter values.
* **Why Selected:** Zero runtime overhead, highly accurate with minimal false positives compared to pure regex.

---

### Alg-02: Heuristic Regex Pattern Signature Matcher
* **Name:** Multi-Pattern Cryptographic Signature Engine
* **Module:** `scanners.registry.crypto_patterns`, `scanners.repository.languages.*`
* **Purpose:** Detects hardcoded private keys, certificate blocks, cipher suite strings, and configuration parameters across source code, config files, and comments.
* **Inputs:** Raw file text.
* **Processing:**
  1. Evaluate regex signatures for PEM headers (`-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`).
  2. Match TLS cipher suite strings (e.g., `TLS_RSA_WITH_AES_128_CBC_SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`).
  3. Match algorithm identifiers in config and code files (`AES-256-GCM`, `RSA-2048`, `SHA-256`, `bcrypt`, `PBKDF2`).
  4. Apply comment-aware confidence de-rating: matches inside comments receive lower base scores (0.15–0.35) than matches in executable code (0.60–0.78).
* **Outputs:** `List[RawFinding]` with file locations, confidence rationales, and matched patterns.
* **Assumptions:** Standard cryptographic naming conventions are followed.
* **Limitations:** Higher false-positive potential; mitigated by multi-signal confidence scoring and classification validation.

---

### Alg-03: Multi-Signal Discovery Confidence Scoring
* **Name:** Deterministic Multi-Signal Confidence Calculator
* **Module:** `scanners.repository.confidence`
* **Purpose:** Quantifies how certain QNetra is that a discovered artifact is an active cryptographic component (0.0 to 1.0), distinct from risk score or migration urgency.
* **Inputs:** Primary signal type, corroborating signals (import detected, argument extracted, API registry match).
* **Processing Formula:**

$$\text{Confidence} = \min\left(\text{Base}(\text{Signal}) + \sum \text{Bonus}(\text{Corroboration}), \text{Cap}(\text{Signal})\right)$$

| Signal Type | Base Score | Cap | Description |
| :--- | :--- | :--- | :--- |
| **AST Crypto API Call** | 0.90 | 0.98 | Confirmed function call via AST parsing |
| **Known Binary Symbol Import** | 0.90 | 0.95 | Confirmed function import in ELF/PE symbol table |
| **Library Import Only** | 0.60 | 0.70 | Library imported but no specific call detected |
| **Regex in Executable Code** | 0.62 | 0.75 | Algorithm string/pattern in active code line |
| **Package Manifest Metadata** | 0.70 | 0.85 | Package detected in dpkg/pip/npm metadata |
| **Binary String Match** | 0.35 | 0.55 | Algorithm string extracted from binary data |
| **Regex in Comment** | 0.18 | 0.30 | Pattern matched on a comment line |

* **Corroborating Bonuses:**
  * Corroborating library import detected: $+0.05$
  * Concrete argument/parameter extracted: $+0.03$
  * Known API registry match: $+0.02$
  * Corroborating binary symbol import: $+0.15$ (for binary strings)
* **Outputs:** `confidence_score` (float 0.0–1.0), `confidence_level` enum, and human-readable `confidence_rationale`.

---

### Alg-04: Static Binary Symbol & String Extraction
* **Name:** Multi-Stage Binary Cryptographic Inspector
* **Module:** `scanners.binary.*`
* **Purpose:** Discovers cryptographic capabilities within compiled binaries (ELF, PE) without code execution.
* **Inputs:** Binary file bytes.
* **Processing:**
  1. **Format Detection:** Read magic bytes to identify ELF (`\x7fELF`), PE (`MZ`), Mach-O, or static archives.
  2. **String Analysis:** Stream printable ASCII strings ($\ge 8$ chars); match OpenSSL/BoringSSL/libsodium version strings, TLS cipher suites, and embedded PEM blocks.
  3. **Symbol Table Parsing:** If `lief` is available and format is ELF/PE, inspect dynamic symbol tables (`imported_functions`, PE import directory) against `scanners.registry.crypto_symbols`.
  4. **Multi-Signal Correlation:** Deduplicate string matches with symbol findings; boost string confidence if corroborated by symbol tables; generate library summary findings for binaries with $\ge 3$ crypto symbols.
* **Outputs:** `List[RawFinding]` with binary format, symbol names, byte offsets, and confidence rationales.
* **Safety Invariant:** Purely static analysis — no process execution, no dynamic instrumentation (RULE-008).

---

## 2. Cryptographic Classification & Parameter Logic

### Alg-05: Cryptographic & Quantum Threat Classification Engine
* **Name:** Deterministic Cryptographic Security & Quantum Threat Classifier
* **Module:** `core.classification.classifier`, `core.classification.knowledge`
* **Status:** Implemented (`v1.0.0` — Milestone 2.2)
* **Purpose:** Enriches normalized `CryptoAsset` instances across three orthogonal dimensions: classical security status, quantum threat type, and post-quantum security status.
* **Inputs:** Normalized `CryptoAsset` instance (algorithm, key length, curve, mode, primitive type).
* **Core Principles:**
  1. **Orthogonal Dimensions:** Classical security and quantum threat are evaluated independently (e.g. RSA-2048 is classically `SECURE` but quantumly `CRITICAL`).
  2. **No-Fabrication Policy:** When required parameters are missing (e.g. unknown AES key size, unspecified ECC curve), security bit counts are set to `None` — never assumed or fabricated.
  3. **Non-Numeric Shor Vulnerability:** Public-key primitives vulnerable to Shor's algorithm receive `effective_quantum_security_bits = None` because the underlying hardness assumption is fundamentally broken, not merely reduced.

* **Processing Rules & Formulas:**

#### A. Classical Security Status Assessment
Assessed against NIST SP 800-131A Rev 2 and NIST SP 800-57 Part 1 Rev 5:

$$\text{ClassicalStatus}(A) \in \{\text{SECURE}, \text{WEAK}, \text{BROKEN}, \text{UNKNOWN}\}$$

* **RSA / DSA / DH:**
  * Modulus $\ge 2048$ bits: `SECURE`
  * Modulus $1024 \le K < 2048$ bits: `WEAK` (deprecated post-2015)
  * Modulus $< 1024$ bits: `BROKEN` (factoring attacks feasible)
  * Modulus unknown: `UNKNOWN`
* **ECC (ECDSA, ECDH):**
  * Recognized NIST / Brainpool / Curve25519 curves ($\ge 256$ bits): `SECURE`
  * Curve unknown: `UNKNOWN`
* **Symmetric Ciphers (AES, ChaCha20):**
  * AES (any approved key size: 128, 192, 256): `SECURE`
  * ChaCha20 (256-bit): `SECURE`
  * 3DES: `WEAK` (effective 112 bits, deprecated by NIST SP 800-131A)
  * DES, RC4: `BROKEN`
* **Hash Functions:**
  * SHA-256, SHA-384, SHA-512, SHA-3: `SECURE`
  * SHA-1: `BROKEN` (SHAttered attack 2017)
  * MD5: `BROKEN` (collision attacks practical)

#### B. Classical Security Bits Estimation ($S_{\text{classical}}$)
* **RSA / DH:** Looked up via NIST SP 800-57 Table 2 step-wise interpolation:
  * $15360 \text{ bits} \to 256$, $7680 \text{ bits} \to 192$, $4096 \text{ bits} \to 140$, $3072 \text{ bits} \to 128$, $2048 \text{ bits} \to 112$, $1024 \text{ bits} \to 80$, $< 1024 \text{ bits} \to 56$.
* **ECC:** Direct curve parameter security level (secp256r1, Curve25519 $\to 128$; secp384r1 $\to 192$; secp521r1 $\to 260$).
* **Symmetric:** $S_{\text{classical}} = K_{\text{bits}}$ for AES and ChaCha20.
* **Hash Functions:** Classical collision resistance = $\lfloor \text{output\_bits} / 2 \rfloor$ (birthday attack bound).

#### C. Quantum Threat Tagging & Security Bits ($S_{\text{quantum}}$)
* **Shor's Polynomial-Time Break (`SHOR_POLYNOMIAL_BREAK`):**
  * Affects: RSA, DSA, DH, ECDSA, ECDH, Ed25519.
  * Quantum Status: `CRITICAL`.
  * Quantum Vulnerable: `True`.
  * Security Bits: $S_{\text{quantum}} = \text{None}$ (fundamentally broken via order-finding in $\mathcal{O}((\log N)^3)$).
* **Grover's Quadratic Key Search (`GROVER_BIT_HALVING`):**
  * Affects: Symmetric ciphers (AES, ChaCha20, 3DES).
  * Formula: $S_{\text{quantum}} = \lfloor K_{\text{bits}} / 2 \rfloor$.
  * Threshold: $T_{\text{NIST}} = 128$ effective quantum bits.
  * If $S_{\text{quantum}} \ge 128$: Quantum Status `SAFE`, `quantum_vulnerable = False` (e.g. AES-256, ChaCha20).
  * If $0 < S_{\text{quantum}} < 128$: Quantum Status `DEGRADED`, `quantum_vulnerable = True` (e.g. AES-128 $\to 64$ bits, AES-192 $\to 96$ bits).
  * If $K_{\text{bits}}$ is missing: Quantum Status `UNKNOWN`, `quantum_vulnerable = None`, $S_{\text{quantum}} = \text{None}$.
* **BHT Quantum Collision Finding (Hash Functions):**
  * Formula: $S_{\text{quantum}} = \lfloor \text{output\_bits} / 3 \rfloor$ (Brassard-Høyer-Tapp algorithm bound $\mathcal{O}(2^{N/3})$).
  * SHA-256: $S_{\text{quantum}} = 85$ bits ($< 128 \implies \text{DEGRADED}$, `quantum_vulnerable = True` for collision contexts).
  * SHA-384: $S_{\text{quantum}} = 128$ bits ($= 128 \implies \text{SAFE}$, `QUANTUM_RESISTANT`).
  * SHA-512: $S_{\text{quantum}} = 171$ bits ($> 128 \implies \text{SAFE}$, `QUANTUM_RESISTANT`).
* **Post-Quantum Cryptography (`QUANTUM_RESISTANT`):**
  * ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205): `SAFE`, `quantum_vulnerable = False`.

* **Outputs:** Mutated canonical `CryptoAsset` with populated classification fields:
  `classical_security_status`, `quantum_security_status`, `quantum_vulnerable`, `quantum_threat_type`, `effective_classical_security_bits`, `effective_quantum_security_bits`, and `classification_notes`.

---

## 3. Quantum Risk Assessment Engine

### Alg-06: Deterministic Quantum Vulnerability Risk Scoring
* **Name:** Multi-Factor Cryptographic & Quantum Risk Calculator
* **Module:** `core.risk_engine` (`RiskEngine`, `RiskScorer`, `knowledge`)
* **Status:** Implemented (`v1.0.0` — Milestone 3.1)
* **Purpose:** Computes an explainable, deterministic risk score (0 to 100) and 4-tier severity rating for every asset and the overall repository.
* **Inputs:** Classified `CryptoAsset` instance (algorithm, key length, curve, mode, padding, classical security status, quantum security status, quantum threat type).
* **Core Principles:**
  1. **Strict 0–100 Boundedness:** Scores are mathematically clamped: $0 \le \text{RiskScore} \le 100$.
  2. **Double-Counting Prevention:** Factor ownership is mutually exclusive:
     - If classically broken, classical risk factor claims 100 points; quantum threat analysis is marked superseded (0 points).
     - If Shor-vulnerable, quantum factor claims 90 points; classical status does not add redundant penalties.
  3. **Strict No-Fabrication:** Missing parameters (key size, curve) are never guessed; they receive zero modifiers and are cited in explainability factors.
  4. **Confidence Decoupling:** Discovery confidence is preserved as descriptive metadata; it does NOT artificially deflate risk scores.

* **Processing Formulas & Factor Model:**

```text
Risk Score Calculation:
Score = Clamp(Sum(RiskFactor.score), 0, 100)

1. Base Score (B) by Algorithmic Class:
   - Broken Classical Primitives (MD5, SHA-1, DES, RC4): B = 100
   - Shor-Vulnerable Asymmetric (RSA, ECC, DH, ECDSA): B = 90
   - Grover-Impacted Symmetric < 256 bits (AES-128, 3DES): B = 60
   - Grover/BHT-Impacted Hash Functions (SHA-256): B = 40
   - Quantum-Resistant Classical (AES-256, SHA-384, SHA-512): B = 20
   - NIST-Approved Standardized PQC (ML-KEM, ML-DSA, SLH-DSA): B = 0
   - Unrecognized / Proprietary Primitive: B = 50
   - Non-Cryptographic Artifacts (Library, Random): B = 0

2. Parameter Modifiers (M_param):
   - RSA Key < 2048: M_key = +10 (below NIST SP 800-131A minimum)
   - RSA Key >= 4096: M_key = -5 (maximum classical security margin)
   - AES Key == 128: M_key = +10 (halved to 64 bits post-Grover)
   - AES Key == 256: M_key = -10 (retains 128 bits post-Grover)
   - AES Key == 192: M_key = -5 (retains 96 bits post-Grover)
   - Mode == ECB: M_mode = +15 (unauthenticated, pattern leakage)
   - Padding == PKCS#1 v1.5: M_pad = +5 (Bleichenbacher vulnerability)

3. Repository Overall Risk Score Aggregation:
   Overall Score = Round(Min(100.0, 0.7 * Max(Score) + 0.3 * Mean(Score)), 1)
```

* **Severity Tiers:**
  * **Critical Risk (80–100):** Shor-vulnerable asymmetric algorithms (RSA, ECC, DH), broken primitives (MD5, SHA-1, DES). Immediate migration required.
  * **High Risk (60–79):** Symmetric ciphers with $< 256$-bit keys (AES-128), SHA-224, 3DES, legacy TLS protocols.
  * **Medium Risk (30–59):** SHA-256 (adequate pre-quantum, medium longevity), AES with unknown key size, unverified primitives.
  * **Low / Quantum-Resistant (0–29):** AES-256, SHA-384/512, standardized PQC algorithms (ML-KEM, ML-DSA), operational artifacts.
* **Outputs:** `RiskAssessment` (per-asset), `RiskAssessmentReport` (repository-level), itemized `RiskFactor` breakdown.
* **Assumptions:** NIST SP 800-131A Rev 2, NIST SP 800-57, and NIST FIPS 203/204/205 standards.
* **Limitations:** Focuses on algorithmic, parameter, and protocol strength; does not model side-channel attacks or physical hardware vulnerabilities.
* **Why Selected:** Fully deterministic, auditable, and transparent for compliance audits.

---

## 4. Mosca Migration Assessment Logic

### Alg-07: Michele Mosca Migration Inequality & Urgency Evaluation
* **Name:** Mosca Theorem Quantum Urgency Calculator
* **Purpose:** Evaluates whether an organization is already in a state of quantum vulnerability due to the Harvest Now, Decrypt Later (HNDL) threat model.
* **Mathematical Model:**

$$\text{Mosca's Inequality:} \quad X + Y > Z$$

Where:
* **$X$ (Shelf Life / Security Lifetime):** The number of years the encrypted data must remain confidential (e.g., healthcare records: 20–30 years, financial records: 10 years, session tokens: 0.1 years).
* **$Y$ (Migration Time):** The number of years required to re-architect systems, update protocols, deploy PQC, and certify infrastructure (typically 3–7 years for enterprise systems).
* **$Z$ (Collapse Time / Quantum Horizon):** The estimated number of years until a Cryptographically Relevant Quantum Computer (CRQC) exists (industry consensus: 2030–2035, i.e., 5–10 years).

```mermaid
gantt
    title Mosca Timeline Model: X + Y vs Z
    dateFormat  YYYY
    section Quantum Horizon
    Z: Time to CRQC Arrival        :crit, 2026, 2034
    section Organization Timeline
    Y: Migration Duration          :active, 2026, 2030
    X: Data Shelf Life             :2030, 2042
    section Vulnerability Gap
    HNDL Vulnerability Window      :done, 2034, 2042
```

* **Decision Logic:**

$$\text{Exposure Gap} = (X + Y) - Z$$

* **Condition 1 ($X + Y > Z$):** **CRITICAL HNDL EXPOSURE.**
  Adversaries harvesting encrypted traffic today will be able to decrypt it before the data loses its confidentiality value. Migration must begin immediately.
* **Condition 2 ($X + Y = Z$):** **ZERO MARGIN.**
  Migration must start today; any delay will cause data to be exposed to post-quantum decryption.
* **Condition 3 ($X + Y < Z$):** **CONTROLLED TIMELINE.**
  The organization has a migration buffer of $Z - (X + Y)$ years before data confidentiality is compromised.
* **Outputs:**
  * `is_vulnerable`: Boolean flag
  * `exposure_gap_years`: $\max(0, (X + Y) - Z)$
  * `deadline_year`: $\text{Current Year} + (Z - X)$
  * `urgency_rating`: `CRITICAL_IMMEDIATE` | `HIGH_PLANNED` | `MODERATE`
* **Why Selected:** Recognized globally (NIST, ENISA, BSI, WEF) as the standard framework for post-quantum migration planning.

---

## 5. PQC & Hybrid Recommendation Logic

### Alg-06: NIST PQC & Hybrid Migration Decision Engine
* **Name:** Post-Quantum Replacement & Transition Recommender
* **Purpose:** Maps vulnerable classical cryptographic primitives to approved NIST PQC replacements and transitional hybrid schemes.
* **Mapping Matrix:**

| Classical Primitive | Primary Function | Primary NIST PQC Replacement | Secondary / Alternative PQC | Recommended Hybrid Scheme |
| :--- | :--- | :--- | :--- | :--- |
| **RSA Key Exchange** | Key Encapsulation | **ML-KEM-768** (FIPS 203) | **ML-KEM-1024** (High Sec) | `X25519 + ML-KEM-768` |
| **ECDH / X25519** | Key Agreement | **ML-KEM-768** (FIPS 203) | **ML-KEM-512** (Resource Constrained) | `ECDH (P-256) + ML-KEM-768` |
| **RSA Digital Signature** | Auth / Signatures | **ML-DSA-65** (FIPS 204) | **SLH-DSA-SHA2-128s** (FIPS 205) | `RSA-2048 + ML-DSA-65` |
| **ECDSA (secp256k1/r1)** | Signatures / Web3 | **ML-DSA-44 / 65** (FIPS 204) | **FN-DSA / Falcon** (FIPS 206) | `ECDSA + ML-DSA-65` |
| **AES-128** | Symmetric Encryption| **AES-256-GCM** | **ChaCha20-Poly1305** (256-bit) | N/A (Increase Key Length to 256 bits) |
| **SHA-1 / SHA-224** | Hashing / Digest | **SHA-384 / SHA-512 / SHA3-256** | **SHAKE256** | N/A (Migrate to SHA-2/3 $\ge 256$ bits) |

* **Recommendation Generation Steps:**
  1. Identify vulnerable primitive and operational usage context (e.g. Signature vs Key Exchange).
  2. Select NIST PQC target standard.
  3. Formulate Hybrid recommendation to allow dual verification during transition.
  4. Estimate migration complexity (Low, Medium, High).
  5. Provide code refactoring guidelines and reference imports.
* **Outputs:** `List[PQCRecommendationItem]` with target algorithm, hybrid mode, complexity, and actionable steps.
* **Why Selected:** Guarantees alignment with official US Federal Information Processing Standards (FIPS) finalized in August 2024.
