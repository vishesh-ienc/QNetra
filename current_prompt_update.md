# current_prompt_update.md — Per-Prompt Implementation Summary

> **RULE-012 MANDATORY:** This file is overwritten on every prompt turn.  
> **Agent:** AI Coding Agent  
> **Timestamp:** 2026-09-04T17:25:00+05:30  
> **Milestone:** Phase 3.3 Corrective Pass — Recommendation Type Terminology Disambiguation  
> **Status:** ✅ COMPLETE

---

## 1. Objective

Perform a focused, non-disruptive corrective pass on the Phase 3 Milestone 3.3 NIST PQC Recommendation Engine (`core/recommendation_engine/`) to ensure that **classical cryptographic strengthening recommendations are not incorrectly labeled as `DIRECT_PQC`**.

---

## 2. Terminology Issue Found

In the initial Milestone 3.3 implementation, classical algorithm upgrades were routed with `recommendation_type = PQCRecommendationType.DIRECT_PQC`. Examples:
* `SHA-256 → SHA-384` (hash length upgrade to resist Grover/BHT collision degradation)
* `AES-128 → AES-256-GCM` (symmetric key-length upgrade to resist Grover search)
* `DES / 3DES → AES-256-GCM` (classically broken symmetric cipher upgrade)
* `MD5 / SHA-1 → SHA-256` (classically broken hash upgrade)
* `HMAC-MD5 → HMAC-SHA-256` (classically broken MAC upgrade)

These upgrades strengthen classical cryptographic parameters or replace broken classical ciphers with secure classical ciphers. They do **NOT** deploy Post-Quantum Cryptography (PQC) algorithms (such as NIST FIPS 203 ML-KEM or FIPS 204 ML-DSA). Labeling them `DIRECT_PQC` could cause the frontend, security auditors, or enterprise users to mistakenly believe that `SHA-384` or `AES-256-GCM` are post-quantum algorithms.

---

## 3. Changes Made

1. **`core/recommendation_engine/models.py`**:
   * Added `CLASSICAL_UPGRADE = "CLASSICAL_UPGRADE"` to the `PQCRecommendationType` enum.
   * Added `classical_upgrade_count: int = 0` to `PQCRecommendationReport` dataclass.
   * Updated `PQCRecommendationReport.to_dict()` to include `"classical_upgrade_count"`.

2. **`core/recommendation_engine/mapper.py`**:
   * Updated `_map_hash_function()`:
     - Classically broken hashes (`MD5`, `SHA-1` → `SHA-256`): set `recommendation_type = PQCRecommendationType.CLASSICAL_UPGRADE`.
     - Grover-impacted hashes (`SHA-256` → `SHA-384`): set `recommendation_type = PQCRecommendationType.CLASSICAL_UPGRADE`.
   * Updated `_map_symmetric_cipher()`:
     - Classically broken ciphers (`DES`, `3DES`, `RC4` → `AES-256-GCM`): set `recommendation_type = PQCRecommendationType.CLASSICAL_UPGRADE`.
     - Grover key-length upgrades (`AES-128` → `AES-256` / `AES-256-GCM`): set `recommendation_type = PQCRecommendationType.CLASSICAL_UPGRADE`.
   * Updated `map_asset_to_recommendation()` Step 6 (MAC/KDF):
     - Classically broken MACs/KDFs (`HMAC-MD5` → `HMAC-SHA-256`): set `recommendation_type = PQCRecommendationType.CLASSICAL_UPGRADE`.
   * Updated routing docstrings and rationale text to explicitly state "classical upgrade".

3. **`core/recommendation_engine/engine.py`**:
   * Added `classical_upgrade_count` tracking in `RecommendationEngine.generate_report()`.
   * Populated `classical_upgrade_count` in returned `PQCRecommendationReport`.

4. **`tests/test_core/test_recommendation_engine.py`**:
   * Updated existing assertions in `TestImportsAndModelInvariants`, `TestHashFunctions`, `TestSymmetricCiphers`, `TestBatchAndReport`, `TestClassicallyBroken`, `TestMacKdf`, `TestSerialization`, and `TestFullPipelineIntegration`.
   * Added dedicated test class `TestClassicalUpgradeCorrectivePass` with 14 comprehensive tests, including a regression test verifying no classical strengthening mapping returns `DIRECT_PQC`.

---

## 4. Recommendation Types Taxonomy

With `CLASSICAL_UPGRADE` introduced, the semantic taxonomy is:

| Type | Semantic Definition | Examples | PQC Standard |
| :--- | :--- | :--- | :--- |
| `DIRECT_PQC` | Classical primitive directly replaced by a NIST PQC algorithm | `DSA → ML-DSA-65`, `RSA (sig) → ML-DSA-65` | NIST FIPS 204 |
| `CLASSICAL_UPGRADE` | Weak/insufficient classical primitive upgraded to stronger classical primitive | `SHA-256 → SHA-384`, `AES-128 → AES-256-GCM`, `DES → AES-256-GCM`, `MD5 → SHA-256` | `None` |
| `HYBRID` | Classical primitive paired with PQC primitive in dual mode | `ECDH → X25519 + ML-KEM-768`, `ECDSA → Ed25519 + ML-DSA-65`, `RSA (enc) → ML-KEM-768` | NIST FIPS 203 / 204 |
| `ALREADY_PQC` | Asset is already using an approved NIST PQC algorithm | `ML-KEM-768`, `ML-DSA-65`, `SLH-DSA-SHA2-128s` | NIST FIPS 203/204/205 |
| `NO_MIGRATION_REQUIRED` | Asset does not require cryptographic migration | `AES-256`, `SHA-384`, `SHA-512`, `OpenSSL (LIBRARY)`, `PRNG (RANDOM)`, `TLS (PROTOCOL)` | `None` |
| `UNKNOWN` | Reliable recommendation cannot be determined | Proprietary or unrecognized algorithms (no fabrication) | `None` |

---

## 5. Mappings Affected

### Classical Upgrades (Corrected to `CLASSICAL_UPGRADE`)
* `SHA-256 → SHA-384` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `SHA-224 → SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `MD5 → SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `SHA-1 → SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `MD4 → SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `RIPEMD-160 → SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `AES-128 → AES-256` / `AES-256-GCM` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `DES → AES-256-GCM` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `3DES → AES-256-GCM` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `RC4 → AES-256-GCM` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)
* `HMAC-MD5 → HMAC-SHA-256` : `CLASSICAL_UPGRADE` (was `DIRECT_PQC`)

### Genuine PQC Recommendations (Preserved Unchanged)
* `RSA (key transport / enc) → ML-KEM-768/1024` : `HYBRID` (`X25519 + ML-KEM-768`)
* `ECDH / DH / X25519 → ML-KEM-768/1024` : `HYBRID` (`X25519 + ML-KEM-768`)
* `ECDSA / Ed25519 → ML-DSA-65/87` : `HYBRID` (`Ed25519 + ML-DSA-65`)
* `DSA → ML-DSA-65/87` : `DIRECT_PQC` (FIPS 204)
* `RSA (signature) → ML-DSA-65/87` : `DIRECT_PQC` (FIPS 204)
* `ML-KEM-512/768/1024` : `ALREADY_PQC` (FIPS 203)
* `ML-DSA-44/65/87` : `ALREADY_PQC` (FIPS 204)
* `SLH-DSA-*` : `ALREADY_PQC` (FIPS 205)

---

## 6. Tests Added & Updated

### Modified Existing Tests
* `test_pqc_recommendation_type_values`: validates `CLASSICAL_UPGRADE` enum member.
* `test_sha256_gets_sha384_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_sha1_gets_sha256_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_md5_gets_sha256_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_aes128_gets_aes256_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_des_gets_aes256_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_md5_hash_gets_sha256`: asserts `CLASSICAL_UPGRADE`.
* `test_sha1_gets_sha256`: asserts `CLASSICAL_UPGRADE`.
* `test_des_symmetric_gets_aes256`: asserts `CLASSICAL_UPGRADE`.
* `test_hmac_md5_gets_direct_pqc_upgrade`: asserts `CLASSICAL_UPGRADE`.
* `test_report_to_dict_all_fields_present`: verifies `classical_upgrade_count` present in dict.
* `test_generate_report_empty_list`: asserts `classical_upgrade_count == 0`.
* `test_generate_report_counts_types_correctly`: verifies count distribution including `classical_upgrade_count == 1`.
* `test_full_pipeline_289_findings_to_147_recommendations`: includes `classical_upgrade_count` in sum (sum == 147).

### New Test Class: `TestClassicalUpgradeCorrectivePass` (14 new tests)
1. `test_sha256_to_sha384_is_classical_upgrade`
2. `test_aes128_to_aes256_gcm_is_classical_upgrade`
3. `test_des_to_aes256_gcm_is_classical_upgrade`
4. `test_3des_to_aes256_gcm_is_classical_upgrade`
5. `test_md5_to_sha256_is_classical_upgrade`
6. `test_sha1_to_sha256_is_classical_upgrade`
7. `test_genuine_pqc_rsa_encryption_remains_hybrid`
8. `test_genuine_pqc_ecdh_remains_hybrid`
9. `test_genuine_pqc_ecdsa_remains_hybrid`
10. `test_genuine_pqc_dsa_remains_direct_pqc`
11. `test_genuine_pqc_rsa_signature_remains_direct_pqc`
12. `test_genuine_pqc_already_pqc_remains_already_pqc`
13. `test_regression_no_classical_upgrade_mapping_is_labeled_direct_pqc` (regression check across 14 classical asset configurations)
14. `test_classical_upgrade_serialization_in_to_dict` (JSON serialization roundtrip)

---

## 7. Test Results & Coverage

```text
Full Test Suite: 526 passed, 1 skipped in 1.44s
Recommendation Engine: 118 passed in 0.52s
Regressions: 0
```

### Coverage (`core.recommendation_engine`):
| Module | Stmts | Miss | Cover |
| :--- | :--- | :--- | :--- |
| `__init__.py` | 3 | 0 | **100%** |
| `engine.py` | 50 | 0 | **100%** |
| `knowledge.py` | 62 | 0 | **100%** |
| `mapper.py` | 197 | 26 | **87%** |
| `models.py` | 60 | 0 | **100%** |
| **TOTAL** | **372** | **26** | **93%** |

---

## 8. Documentation Updated

| Document | Sections Updated |
| :--- | :--- |
| `docs/04_MODULES.md` | MOD-010: Added `CLASSICAL_UPGRADE` distinction, updated test counts (118 tests), updated status to `v1.1.0`. |
| `docs/05_ALGORITHMS.md` | Alg-08: Updated Step 3, 4, 5 in routing pseudocode to return `CLASSICAL_UPGRADE`, updated Output Contract enum list. |
| `docs/07_PROGRESS.md` | Updated Milestone 3.3 description with `CLASSICAL_UPGRADE` details, updated test metrics (526 passed), added change log entry. |
| `docs/08_DECISIONS_AND_LOG.md` | DEC-016: Updated Decision point 3, Consequences, and added Addendum for Phase 3.3 Corrective Pass. |
| `docs/09_KNOWLEDGE_BASE.md` | Added Section 5: "Post-Quantum Migration vs. Classical Cryptographic Strengthening" with full comparison table; renumbered subsequent sections. |
| `PROJECT_CONTEXT.md` | Updated Recommendation Engine summary with 6 outcome types, `classical_upgrade_count`, and 526 passing tests. |
| `current_status.md` | Updated status line, executive snapshot, and test health metrics. |
| `current_prompt_update.md` | This file (overwritten per RULE-012). |

---

## 9. Architectural Independence & Invariants Confirmation

* **Risk Score Independence:** Recommendation routing function `map_asset_to_recommendation()` continues to determine recommendations solely from `(algorithm, primitive_type, key_length_bits, curve)`. `asset.risk_score` is **never read**.
* **Mosca Urgency Independence:** Mosca urgency and timeline fields are **never read** during recommendation selection.
* **No Mutation:** `recommend()` and `recommend_all()` remain purely functional; the input `CryptoAsset` instances are never modified.
* **No Fabrication:** Unknown algorithms continue to return `UNKNOWN` with `recommended_algorithm=None`. Parameter defaults are recorded as explicit assumptions.
* **Determinism:** Results are strictly reproducible and sorted by `asset_id`.

---

## 10. Remaining Limitations & Next Steps

* **Limitations:**
  - Hybrid recommendations currently cover key exchange (`X25519 + ML-KEM-768`) and signatures (`Ed25519 + ML-DSA-65`). Other specialized hybrids (e.g. SPHINCS+ hybrid) remain out of scope for MVP.
  - Parameter selection uses deterministic policy thresholds (RSA ≥ 3072 / ECC ≥ 384 bits); fine-grained protocol-specific cipher suite configuration is deferred to Phase 4 remediation guide rendering.
* **Next Steps:** Proceed to **Phase 4: Full-Stack Integration** (`backend/api/` FastAPI REST gateway and `frontend/` interactive web dashboard).
