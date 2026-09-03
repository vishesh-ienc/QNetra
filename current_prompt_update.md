# Current Prompt Update — Phase 2 Milestone 2.2

**Date:** 2026-09-03
**Phase:** Phase 2 — Analysis Layer
**Milestone:** 2.2 — Cryptographic & Quantum Threat Classification

---

## Summary of Work Completed This Prompt

### Phase A — Normalization Bug Fix (AES Key Size Injection)

**Bug:** `core/normalization/algorithm_normalizer.py` incorrectly injected AES key size from arbitrary numbers appearing in raw symbol text:
```python
# OLD (WRONG):
elif "128" in raw_sym and "AES" in suspected.upper():
    key_size = 128  # Would fire for ANY raw symbol containing "128"
```
**Fix Applied:**
- Removed the raw-substring AES key injection (lines 175–181)
- Retained the structured RSA/DSA/DH word-boundary extraction (safe, explicit key sizes)
- Improved `_extract_parameters_from_string` to properly handle concatenated AES aliases (`aes256`, `aes128`, `aes192`) that ARE structured algorithm name forms (not arbitrary substrings)

**Regression Tests Added (3):**
1. `test_aes_jca_no_key_size_without_hint` — `AES/GCM/NoPadding` → `key_length_bits=None`
2. `test_aes_new_call_no_explicit_key` — `AES.new(key, AES.MODE_GCM)` → `key_length_bits=None`
3. `test_aes_raw_symbol_with_unrelated_numbers_no_key_injection` — Buffer size / var name 128/256 → `key_length_bits=None`

**Test Status (post-fix):** 22/22 normalization tests pass ✅

---

### Phase B — CryptoAsset Schema Extension (DEC-011)

Added 5 new `Optional` classification fields to `core/models.py` (CryptoAsset):

| Field | Type | Description |
|---|---|---|
| `classical_security_status` | `Optional[str]` | SECURE/WEAK/BROKEN/UNKNOWN |
| `quantum_security_status` | `Optional[str]` | SAFE/DEGRADED/CRITICAL/UNKNOWN |
| `effective_classical_security_bits` | `Optional[int]` | NIST SP 800-57 classical bit estimate |
| `effective_quantum_security_bits` | `Optional[int]` | Shor/Grover/BHT quantum bit estimate |
| `classification_notes` | `Optional[str]` | Human-readable deterministic rationale |

Updated `to_api_dict()` to include all new fields.
All fields default to `None` — backward-compatible. No existing tests broke.

---

### Phase C — Classification Subsystem (core/classification/)

Created three new modules:

#### `core/classification/models.py`
- `ClassicalSecurityStatus` enum: SECURE, WEAK, BROKEN, UNKNOWN
- `QuantumSecurityStatus` enum: SAFE, DEGRADED, CRITICAL, UNKNOWN
- `ClassificationResult` dataclass: structured output from `classify_one()`

#### `core/classification/knowledge.py`
- NIST SP 800-57 Table 2 RSA/DH security bit lookup table
- ECC curve → classical security bits mapping
- Grover symmetric quantum bits formula (key_bits // 2)
- BHT hash quantum profiles for MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3
- `QUANTUM_SECURITY_THRESHOLD_BITS = 128` (NIST threshold)
- `UNCONDITIONALLY_BROKEN`, `UNCONDITIONALLY_WEAK`, `FINALIZED_NIST_PQC` constant sets

#### `core/classification/classifier.py`
ClassificationEngine with:
- `classify(assets)` — mutates CryptoAsset list in-place
- `classify_one(asset)` — pure function returning ClassificationResult
- Routing by `primitive_type`: PQC → Protocol → Hash → Symmetric → MAC → KDF → Public-key → Fallback
- Per-family classifiers: `_classify_aes()`, `_classify_hash()`, `_classify_public_key()`, `_classify_pqc()`, `_classify_hmac()`, `_classify_mac()`, `_classify_kdf()`
- Key invariants enforced: Shor → `effective_quantum_security_bits=None`, no-fabrication on missing params

---

### Phase D — Test Suite

Created `tests/test_core/test_classification.py` (54 tests + 1 integration skip):

| Test Class | Tests | Coverage Focus |
|---|---|---|
| `TestClassicalClassification` | 12 | Classical SECURE/WEAK/BROKEN/UNKNOWN per algorithm |
| `TestQuantumClassification` | 11 | Shor/Grover/BHT/PQC quantum threat classification |
| `TestQuantumVulnerability` | 9 | `quantum_vulnerable` True/False/None semantics |
| `TestEffectiveSecurityBits` | 11 | No-fabrication on missing params, correct bit values |
| `TestClassificationConfidence` | 3 | HIGH/LOW/UNKNOWN confidence rules |
| `TestDeterminism` | 3 | Idempotency and stability |
| `TestAssetEnrichment` | 3 | CryptoAsset field enrichment + Phase 3 fields untouched |
| `TestIntegration` | 1 (skip) | Full pipeline test (requires sample directory) |

**Test Status:** 54/54 passing, 1 skipped ✅

---

### Phase E — Pipeline Validation

End-to-end run with all 3 scanner types:

| Metric | Value |
|---|---|
| RawFindings (total) | **289** |
| CryptoAssets produced | **147** |
| Findings merged | 142 |
| SHOR_POLYNOMIAL_BREAK | 29 |
| GROVER_BIT_HALVING | 64 |
| QUANTUM_RESISTANT | 2 |
| CLASSICALLY_BROKEN | 14 |
| NOT_APPLICABLE | 38 |
| UNKNOWN | 0 |
| quantum_vulnerable=True | 65 |
| quantum_vulnerable=False | 38 |
| quantum_vulnerable=None | 44 |
| risk_score untouched | ✅ True |

---

### Phase F — Documentation Updates

| Document | Change |
|---|---|
| `docs/04_MODULES.md` | Normalization Layer → **Implemented**; Classification Engine → **Implemented** |
| `docs/05_ALGORITHMS.md` | Alg-05 updated with full classification formulas; Alg-06/07 renumbered |
| `docs/06_API_AND_DATA_CONTRACTS.md` | Contract bumped to v1.2.0, added 5 classification fields to CryptoAsset |
| `docs/07_PROGRESS.md` | Milestone 2.2 marked COMPLETE, updated roadmap |
| `docs/08_DECISIONS_AND_LOG.md` | Added DEC-011 (schema extension) and DEC-012 (classification architecture) |
| `docs/10_API_CONTRACT.md` | Aligned Section 8 CryptoAsset schema with v1.2.0 classification fields |
| `PROJECT_CONTEXT.md` | Synchronized pipeline, inventory, schema summary, and roadmap to Milestone 2.2 |
| `current_status.md` | Comprehensive status updated (153 passed, 85% core coverage, 147 classified) |
| `current_prompt_update.md` | This file |

---

## Test Suite Status (Full)

**153 passed, 1 skipped** — all tests green after Milestone 2.2 implementation.

| Module | Coverage |
|---|---|
| `core.classification.models` | 100% |
| `core.classification.__init__` | 100% |
| `core.classification.knowledge` | 95% |
| `core.classification.classifier` | 76% |
| `core.models` | 100% |
| `core.normalization.normalizer` | 100% |
| **core total** | **85%** |

---

## Files Touched This Prompt

**Modified:**
- `core/normalization/algorithm_normalizer.py` — Bug fix (AES injection removal + structured alias extraction)
- `core/models.py` — +5 classification fields, updated `to_api_dict()` (Schema v1.2.0)
- `tests/test_core/test_normalization.py` — +3 regression tests, new `TestNormalizationRegressions` class
- `docs/04_MODULES.md` — Module status updates (Normalization & Classification Implemented)
- `docs/05_ALGORITHMS.md` — Alg-05 detailed specification & formula definitions
- `docs/06_API_AND_DATA_CONTRACTS.md` — Contract v1.2.0 with classification fields
- `docs/07_PROGRESS.md` — Milestone 2.2 marked complete
- `docs/08_DECISIONS_AND_LOG.md` — DEC-011, DEC-012 added
- `docs/10_API_CONTRACT.md` — Aligned Section 8 with v1.2.0 schema
- `PROJECT_CONTEXT.md` — Agent handoff doc synchronized to Milestone 2.2
- `current_status.md` — Comprehensive project health & test metrics updated
- `task.md` — Task list updated with all items checked

**Created:**
- `core/classification/__init__.py` — Package public API
- `core/classification/models.py` — Classification domain models
- `core/classification/knowledge.py` — NIST SP 800-57 tables, BHT profiles, Grover formulas
- `core/classification/classifier.py` — ClassificationEngine implementation
- `tests/test_core/test_classification.py` — 54-test classification suite

---

## Next Steps (Phase 2 Milestone 2.3+)

1. **Milestone 2.3** — CycloneDX 1.6+ CBOM Serializer (`core.cbom_generator`)
2. **Phase 3** — Quantum Risk Engine (`core.risk_engine`) & Mosca Urgency Engine (`core.mosca_engine`)
3. **Phase 4** — Backend API & Interactive UI Dashboard
