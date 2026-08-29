# 09 — Post-Quantum Cryptography & Domain Knowledge Base

> **DOCUMENT PURPOSE:** Centralized knowledge repository for cryptographic theory, quantum computing threat models, NIST Post-Quantum standards, and CBOM specifications relevant to **QNetra**.

---

## 1. Quantum Computing Threat Models

### 1.1. Shor's Algorithm
* **Concept:** A quantum algorithm formulated by Peter Shor (1994) for finding the prime factors of an integer and solving the discrete logarithm problem.
* **Explanation:**
  Runs in polynomial time:
  $$\mathcal{O}((\log N)^2 (\log \log N) (\log \log \log N))$$
  Whereas the best known classical algorithm (General Number Field Sieve) runs in sub-exponential time:
  $$\mathcal{O}\left(\exp\left(c \cdot (\log N)^{1/3} (\log \log N)^{2/3}\right)\right)$$
* **Relevance to QNetra:** Shor's algorithm renders all current public-key cryptography insecure:
  * RSA (Integer Factorization)
  * Diffie-Hellman & DSA (Finite Field Discrete Logarithm)
  * ECDH & ECDSA / Ed25519 (Elliptic Curve Discrete Logarithm)
  Any asset identified by QNetra using these primitives is flagged as **Critically Quantum-Vulnerable**.
* **Source:** Shor, P. W. (1994). *Algorithms for quantum computation: discrete logarithms and factoring.*

---

### 1.2. Grover's Algorithm
* **Concept:** A quantum search algorithm providing quadratic speedup for unstructured search problems.
* **Explanation:**
  Reduces brute-force search time from $\mathcal{O}(N)$ to $\mathcal{O}(\sqrt{N})$.
  * 128-bit symmetric key (e.g. AES-128) $\rightarrow$ Effective 64-bit quantum security level (Vulnerable).
  * 256-bit symmetric key (e.g. AES-256) $\rightarrow$ Effective 128-bit quantum security level (Quantum-Resistant).
  * Collision resistance for 256-bit hashes (e.g. SHA-256) $\rightarrow$ Effective 85-bit security via Brassard-Høyer-Tapp (BHT) quantum algorithm.
* **Relevance to QNetra:** QNetra evaluates symmetric key sizes and hash algorithms. Symmetric ciphers $< 256$ bits and hashes $< 384$ bits are flagged for upgrade.
* **Source:** Grover, L. K. (1996). *A fast quantum mechanical algorithm for database search.*

---

### 1.3. Harvest Now, Decrypt Later (HNDL)
* **Concept:** An active adversary strategy where encrypted communications and archived enterprise data are intercepted and stored today, to be decrypted once a Cryptographically Relevant Quantum Computer (CRQC) becomes available.
* **Explanation:** Even if a quantum computer does not exist today, any data whose required confidentiality lifespan ($X$) exceeds the time until quantum computer arrival ($Z$) is already at risk.
* **Relevance to QNetra:** Forms the primary justification for QNetra’s urgency score and Mosca timeline assessment.

---

## 2. Mosca’s Theorem & Migration Framework

### 2.1. Michele Mosca’s Inequality
* **Concept:** Formulated by Dr. Michele Mosca (Institute for Quantum Computing, University of Waterloo) to quantify quantum risk urgency.
* **Mathematical Formula:**

$$\text{Evaluate:} \quad X + Y > Z$$

* **Variables:**
  * **$X$ (Shelf-Life / Security Lifetime):** Number of years the encrypted data must remain strictly confidential.
    * *Financial transactions / Trade secrets:* 5–15 years.
    * *National security / Intelligence:* 25–50 years.
    * *Medical records / PII:* 30–80 years.
  * **$Y$ (Migration Time):** Number of years required to re-architect systems, upgrade protocols, deploy PQC, and certify infrastructure (typically 3–8 years for large enterprise ecosystems).
  * **$Z$ (Collapse Time / Quantum Horizon):** Estimated years until a CRQC is developed (estimated by quantum physicists to be between 2030 and 2035).
* **Condition Analysis:**
  * If $X + Y > Z$: **Vulnerable to HNDL breach.** Migration is already late.
  * If $X + Y \le Z$: **Safe transition window exists.**

```mermaid
graph LR
    A["Data Shelf Life (X)<br/>e.g. 10 yrs"] + B["Migration Time (Y)<br/>e.g. 4 yrs"] --> C["Total Required Runway (X+Y)<br/>14 yrs"]
    D["Time to CRQC (Z)<br/>e.g. 8 yrs"] --> E{"X + Y > Z ?"}
    C --> E
    E -- "YES (14 > 8)" --> F["CRITICAL HNDL EXPOSURE<br/>Gap = +6 years"]
    E -- "NO" --> G["Safe Migration Buffer"]
```

* **Source:** Mosca, M. (2015). *Setting the Scene for the Post-Quantum Cryptography Transition.*

---

## 3. Post-Quantum Cryptography (PQC) Standards

In August 2024, the National Institute of Standards and Technology (NIST) released the official, finalized Federal Information Processing Standards (FIPS) for Post-Quantum Cryptography:

### 3.1. FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
* **Underlying Hardness Problem:** Module Learning with Errors (M-LWE) over module lattices.
* **Primary Use Case:** General-purpose public-key encryption and secure key exchange (TLS, VPNs, SSH, email).
* **Parameter Sets:**
  * **ML-KEM-512:** NIST Security Category 1 (equivalent to AES-128).
  * **ML-KEM-768:** **Primary Recommended Standard** (NIST Category 3, equivalent to AES-192).
  * **ML-KEM-1024:** Maximum Security (NIST Category 5, equivalent to AES-256).
* **Performance Profile:** Fast encryption/decryption; small key and ciphertext sizes compared to other lattice schemes (~1 KB).

---

### 3.2. FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
* **Underlying Hardness Problem:** Module Learning with Errors (M-LWE) and Module Short Integer Solution (M-SIS).
* **Primary Use Case:** General-purpose digital signatures (code signing, PKI certificates, document signing).
* **Parameter Sets:**
  * **ML-DSA-44:** NIST Security Category 2.
  * **ML-DSA-65:** **Primary Recommended Standard** (NIST Category 3).
  * **ML-DSA-87:** Maximum Security (NIST Category 5).
* **Performance Profile:** Strong performance, moderate public key (~1.3 KB) and signature (~2.4 KB) sizes.

---

### 3.3. FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
* **Underlying Hardness Problem:** Security of cryptographic hash functions (SHA-2 / SHAKE).
* **Primary Use Case:** High-assurance digital signatures and backup signature algorithm if lattice problems are compromised.
* **Characteristics:** Stateless (unlike XMSS/LMS, no state management required). Very small public keys, but larger signatures (~8–30 KB) and higher signing computational cost.

---

### 3.4. FIPS 206 — FN-DSA (Fast-Fourier Lattice-Based Digital Signature Algorithm / Falcon)
* **Underlying Hardness Problem:** Short Integer Solution over NTRU lattices.
* **Primary Use Case:** Digital signatures requiring the smallest combined public key and signature sizes (ideal for constrained bandwidth environments like DNSSEC).

---

## 4. Hybrid Classical-PQC Cryptography

* **Concept:** Combining a proven classical algorithm with a post-quantum algorithm in a dual-encapsulation or dual-signature mode.
* **Mechanism:**
  * **Hybrid Key Exchange:** Combine shared secrets derived from classical Diffie-Hellman ($SS_{\text{classical}}$) and ML-KEM ($SS_{\text{PQC}}$) via a Key Derivation Function:
    $$SS_{\text{hybrid}} = \text{KDF}(SS_{\text{classical}} \parallel SS_{\text{PQC}})$$
  * **Hybrid Digital Signature:** Require verification of both a classical signature (e.g. ECDSA) and a PQC signature (e.g. ML-DSA).
* **Why Recommended by QNetra:**
  1. Protects against unknown vulnerabilities in newly standardized PQC mathematics.
  2. Maintains FIPS 140-3 compliance during the transition period.
  3. Ensures backward compatibility with legacy clients.

---

## 5. Cryptographic Bill of Materials (CBOM) & CycloneDX

* **Concept:** A formal, machine-readable inventory of all cryptographic assets, algorithms, certificates, keys, and protocols within a software artifact.
* **CycloneDX 1.6 Cryptography Extension:**
  * Standardized by OWASP and endorsed by CISA.
  * Extends Software Bill of Materials (SBOM) with cryptographic properties:
    * `cryptoProperties.assetType` (`algorithm`, `certificate`, `key`, `protocol`)
    * `cryptoProperties.algorithmProperties.primitive`
    * `cryptoProperties.algorithmProperties.parameterSetIdentifier`
    * `cryptoProperties.algorithmProperties.curve`
    * `cryptoProperties.oid` (Object Identifier)
* **Relevance to QNetra:** QNetra exports full CycloneDX 1.6+ JSON CBOMs, making discovery actionable for enterprise compliance.

---

## 6. Authoritative References & Standards

1. **NIST FIPS 203:** *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)* (August 2024).
2. **NIST FIPS 204:** *Module-Lattice-Based Digital Signature Standard (ML-DSA)* (August 2024).
3. **NIST FIPS 205:** *Stateless Hash-Based Digital Signature Standard (SLH-DSA)* (August 2024).
4. **NIST SP 800-131A Rev. 2:** *Transitioning the Use of Cryptographic Algorithms and Key Lengths*.
5. **CycloneDX 1.6 Specification:** *Cryptographic Bill of Materials (CBOM) Extensions*, OWASP Foundation.
6. **BSI TR-02102-1:** *Cryptographic Mechanisms: Recommendations and Key Lengths*, Federal Office for Information Security, Germany.
7. **Mosca, M. (2015):** *Cybersecurity in an Era with Quantum Computers: Will We Be Ready?*, IEEE Security & Privacy.
