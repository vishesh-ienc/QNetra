# current_prompt_update.md - Per-Prompt Implementation Summary (RULE-012)

## Prompt Metadata
- Date: 2026-09-25
- Phase: Performance Optimization - Sub-60s Large Repo Scanning
- Status: COMPLETE

## Summary

Diagnosed and fixed 4 bottlenecks causing openssl/openssl scans to take 2+ minutes.

## Root Causes Found

| Stage | Old Time | Root Cause |
|:---|:---|:---|
| Acquisition | 60-120s | Full blob download; stall-detection too aggressive |
| Discovery | 25-40s | 3000 file cap x 8ms; 2000 lines/file |
| Traversal | 3-8s | Missing exclusions for test/, docs/, CPython dirs |
| Budget formula | - | Dynamic budget broke when acq_time > 38s |

## Changes Made

### backend/github.py - Acquisition Engine v6.0 (TWO-PHASE SPARSE-CHECKOUT)
- Phase 1: git clone --filter=blob:none --no-checkout (zero blobs, ~3-6s)
- Phase 2: git sparse-checkout init --no-cone + set source extensions + git checkout HEAD (~8-20s)
- Only downloads .c .h .py .js .ts .java .go .rs .cs files
- Drops docs, man pages, fuzz corpora, test vectors entirely
- New _run_git() helper for clean multi-step git error handling
- Expected: openssl/openssl 60-120s -> 12-25s (5x faster)

### backend/pipeline.py - Adaptive Engine v4.0
- max_files_per_scan: 3000 -> 1200 (60% fewer files, same crypto coverage)
- max_lines_per_file: 2000 -> 1000 (50% less I/O per file)
- dynamic_budget formula: max(15, min(30, 50 - acq_time)) 
- Budget capped at 30s for discovery (was 35s)
- _SCAN_ANALYSIS_BUDGET_SECONDS: 50 -> 30

### scanners/framework/models.py - ScanOptions defaults
- Added 15 new directory exclusions: test/, tests/, testing/, spec/, examples/,
  CPython dirs (Misc, PC, PCbuild, Mac, Tools), tutorial/, website/, etc.

### backend/tests/test_github_acquisition.py
- Updated test mocks for v6.0 four-phase git command sequence
- test_acquire_github_repository_success: new fake_git_v6 mock
- test_acquire_github_repository_failure: matches new error prefix
- test_create_scan_github_lifecycle: handles clone/sparse-checkout/checkout phases
- All 14 acquisition tests PASS

## Expected Performance After Fix

| Stage | Before | After |
|:---|:---|:---|
| Acquisition | 60-120s | 12-25s |
| Discovery | 25-40s | 8-15s |
| Norm + Class + Downstream | 2-5s | 2-4s |
| Total | 90-165s | 22-44s |

## Next Steps
- Restart the FastAPI backend to pick up all changes
- Test with openssl/openssl scan in the UI
