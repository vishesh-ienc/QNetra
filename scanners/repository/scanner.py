"""
QNetra Repository Scanner — Main Entry Point (Adaptive Scanning Engine v2.0)

The RepositoryScanner is the primary cryptographic discovery engine for source code
repositories. It orchestrates the full adaptive discovery pipeline:

  1. Traversal: Walk the repository tree, classify files by language.
     - .gitignore-aware filtering eliminates generated/vendored content.
  2. Candidate Ranking: Score files by crypto-relevance (filename signals, no I/O).
  3. Priority Queue: Process highest-value files first.
  4. Bounded Parallel Analysis: Analyze files concurrently via ThreadPoolExecutor.
     - Each worker builds a shared FileContext (one read + pre-filter per file).
     - If a per-scan time budget is configured, the loop stops gracefully when
       the deadline is reached, marking the scan as PARTIAL.
  5. Finding Collection: Aggregate RawFinding objects from completed workers.
  6. Error Isolation: Handle per-file failures without aborting the entire scan.

Architecture notes:
  - Extends BaseScanner (implements _execute_scan).
  - Operates in read-only mode (RULE-008).
  - Does NOT normalize findings (that is core.normalization's responsibility).
  - Produces List[RawFinding] — the Discovery Layer output contract.
  - ThreadPoolExecutor is used for I/O-bound file reading + CPU-bound analysis.
    max_workers is capped to avoid over-subscription on the backend server.
  - When scan_time_budget_seconds > 0, sets a monotonic deadline.
    On deadline: pending futures are cancelled, results so far are kept, scan
    is marked PARTIAL with a user-visible partial_reason.
"""

from __future__ import annotations

import logging
import os
import re
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from scanners.framework.base_scanner import BaseScanner
from scanners.framework.models import (
    ArtifactCategory,
    DiscoveryMethod,
    FileLocation,
    RawFinding,
    ScanResult,
    ScanTarget,
    TargetType,
)
from scanners.repository.languages.base_analyzer import LanguageAnalyzer
from scanners.repository.languages.python_analyzer import PythonAnalyzer
from scanners.repository.languages.javascript_analyzer import JavaScriptAnalyzer
from scanners.repository.languages.java_analyzer import JavaAnalyzer
from scanners.repository.languages.cpp_analyzer import CppAnalyzer
from scanners.repository.traversal import RepositoryTraversal
from scanners.utils.file_traversal import safe_read_text
from scanners.utils.language_detector import Language, is_source_language

logger = logging.getLogger(__name__)

# Maximum parallel workers for the thread pool.
# File analysis is I/O-bound (disk read) + CPU-bound (regex/AST). I/O-heavy
# workloads benefit from more threads than CPU cores since threads spend much
# of their time blocked waiting on disk reads. Empirically, 4× cpu_count gives
# good throughput on SSDs without excessive context-switch overhead.
# Hard cap at 32 to avoid OS scheduler saturation on large servers.
_MAX_WORKERS = min(32, (os.cpu_count() or 4) * 4)

# Quick pre-filter: single-pass scan for any broad crypto keyword before running
# the full multi-phase analyzer. Files with zero matches are returned immediately
# (~0.01ms) instead of running all 35+ patterns + AST (~5-120ms).
# Pattern is intentionally broad to minimise false negatives.
# Extended with argon, keccak, kdf, prf, bcrypt (full list from Section 6 of spec).
_CRYPTO_QUICK_FILTER = re.compile(
    r'(?:'
    r'AES|DES|3DES|RC4|RSA|ECDSA|ECDH|X25519|X448|ChaCha|Poly1305|'
    r'SHA[0-9-]|MD5|MD4|HMAC|HKDF|PBKDF|Scrypt|Argon|BCrypt|Keccak|'
    r'EVP_|SSL_|TLS_|PKCS|X509|OCSP|CRL|'
    r'encrypt|decrypt|cipher|decipher|'
    r'cryptography|crypto|crypt|openssl|mbedtls|libsodium|bouncycastle|'
    r'key_size|key_len|block_size|iv_size|nonce|salt|digest|hash|'
    r'signature|certificate|private.?key|public.?key|keypair|'
    r'blowfish|twofish|camellia|curve25519|ed25519|ed448|'
    r'import\s+(?:hashlib|cryptography|Crypto|ssl|hmac|secrets|nacl|sodium)|'
    r'javax\.crypto|java\.security|org\.bouncycastle'
    r')',
    re.IGNORECASE,
)


@dataclass
class _FileContext:
    """
    Shared context built once per file in the worker thread.

    Building the context (read + decode + pre-filter + line split) happens
    exactly once per file — analyzers receive this struct and never re-open
    or re-decode the file.

    Attributes:
        file_path:        Absolute path to the source file.
        language:         Detected programming language.
        content:          Decoded text content (possibly truncated to max_lines).
        lines:            Content split into lines (for line-indexed findings).
        line_count:       Number of lines in the (possibly truncated) content.
        byte_size:        Number of bytes read from disk.
        has_crypto:       True if the quick pre-filter found any crypto signals.
        truncated:        True if the file was truncated at max_lines_per_file.
        read_error:       Non-None if the file could not be read.
    """
    file_path: Path
    language: Language
    content: str
    lines: list[str]
    line_count: int
    byte_size: int
    has_crypto: bool
    truncated: bool
    read_error: Optional[str] = None


@dataclass
class _FileResult:
    """Result of analyzing a single file — carries findings or error info."""
    file_path: Path
    findings: list[RawFinding]
    read_error: Optional[str]
    analysis_error: Optional[str]
    was_skipped: bool = False      # pre-filtered (no crypto signals) or empty
    bytes_read: int = 0
    lines_analyzed: int = 0


# Filename patterns for crypto-relevance ranking (applied without I/O, pure name matching).
# Files matching higher-tier patterns are analyzed first when the file cap is applied.
_CRYPTO_TIER3 = re.compile(
    r'(?:aes|des|rc4|rsa|ecdsa|ecdh|x25519|chacha|poly|sha\d|md5|hmac|pbkdf|hkdf|'
    r'argon|bcrypt|scrypt|blowfish|twofish|camellia|curve25519|ed25519)',
    re.IGNORECASE,
)
_CRYPTO_TIER2 = re.compile(
    r'(?:crypto|cipher|encrypt|decrypt|sign|verify|hash|digest|key|secret|'
    r'ssl|tls|pkcs|x509|cert|token|auth|oauth|jwt|password|passwd|credential)',
    re.IGNORECASE,
)
_CRYPTO_TIER1 = re.compile(
    r'(?:security|secure|safe|protect|random|nonce|iv|salt|mac|kdf|prf|'
    r'openssl|mbedtls|boringssl|wolfssl|libsodium|nacl)',
    re.IGNORECASE,
)


def _crypto_relevance_score(fp: Path) -> int:
    """Score a file path 0-3 by how likely it contains crypto-relevant code (no I/O)."""
    name = fp.stem.lower()
    if _CRYPTO_TIER3.search(name):
        return 3
    if _CRYPTO_TIER2.search(name):
        return 2
    if _CRYPTO_TIER1.search(name):
        return 1
    return 0


def _rank_by_crypto_relevance(
    work_items: list[tuple[Path, "Language", "LanguageAnalyzer"]],
) -> list[tuple[Path, "Language", "LanguageAnalyzer"]]:
    """
    Sort work items by crypto-relevance score (descending), then by file path (stable).

    This ensures that when max_files_per_scan truncates the list, the dropped files
    are the lowest-priority ones (utility code, test infra, build scripts) rather
    than the files most likely to contain cryptographic usage.
    """
    return sorted(work_items, key=lambda item: (-_crypto_relevance_score(item[0]), str(item[0])))


class RepositoryScanner(BaseScanner):
    """
    Cryptographic Discovery Scanner for Source Code Repositories (Adaptive Engine v2.0).

    Scans a source code directory tree using AST analysis (Python),
    import detection, and regex pattern matching across Python, JavaScript,
    TypeScript, Java, C, and C++ source files.

    Files are analyzed in parallel using a ThreadPoolExecutor to maximize
    throughput on I/O-bound reads and mixed I/O+CPU analysis workloads.

    When scan_time_budget_seconds > 0 in ScanOptions, the scan terminates
    gracefully at the deadline, marks the result as PARTIAL, and reports
    factual coverage information.

    Target type: REPOSITORY
    Output: List[RawFinding] appended to ScanResult.findings
    """

    SCANNER_NAME = "RepositoryScanner"
    SCANNER_VERSION = "2.0.0"

    # Language -> Analyzer mapping (extensible for future languages)
    _ANALYZERS: dict[Language, type[LanguageAnalyzer]] = {
        Language.PYTHON: PythonAnalyzer,
        Language.JAVASCRIPT: JavaScriptAnalyzer,
        Language.TYPESCRIPT: JavaScriptAnalyzer,  # TS uses same analyzer as JS
        Language.JAVA: JavaAnalyzer,
        Language.C: CppAnalyzer,
        Language.CPP: CppAnalyzer,
    }

    def __init__(self) -> None:
        super().__init__()
        # Instantiate analyzers once per scanner instance.
        # Analyzer instances are read-only after construction so sharing across
        # threads is safe — they hold no mutable per-call state.
        self._analyzer_instances: dict[Language, LanguageAnalyzer] = {}
        for lang, analyzer_class in self._ANALYZERS.items():
            # Avoid creating duplicate instances for languages sharing an analyzer class
            instance_exists = any(
                isinstance(inst, analyzer_class)
                for inst in self._analyzer_instances.values()
            )
            if not instance_exists:
                self._analyzer_instances[lang] = analyzer_class()
            else:
                # Reuse existing instance
                self._analyzer_instances[lang] = next(
                    inst for inst in self._analyzer_instances.values()
                    if isinstance(inst, analyzer_class)
                )

    def _validate_target(self, target: ScanTarget) -> Optional[str]:
        """Validate that the target is a readable directory."""
        path = Path(target.path)
        if not path.exists():
            return f"Target path does not exist: {target.path}"
        if not path.is_dir():
            return (
                f"RepositoryScanner requires a directory target. "
                f"Got file: {target.path}. "
                f"Use BinaryScanner for individual files."
            )
        return None

    def _build_file_context(
        self,
        file_path: Path,
        language: Language,
        max_bytes: int,
        max_lines: int,
    ) -> _FileContext:
        """
        Build a FileContext by reading and pre-processing a single file.

        This is the first and ONLY time a file is opened during analysis.
        The resulting context is passed to the language analyzer — no
        further disk I/O is needed.
        """
        content, read_error = safe_read_text(file_path, max_bytes=max_bytes)

        if read_error:
            return _FileContext(
                file_path=file_path, language=language, content="", lines=[],
                line_count=0, byte_size=0, has_crypto=False, truncated=False,
                read_error=read_error,
            )

        if not content or not content.strip():
            return _FileContext(
                file_path=file_path, language=language, content="", lines=[],
                line_count=0, byte_size=len(content or ""), has_crypto=False, truncated=False,
            )

        byte_size = len(content.encode("utf-8", errors="replace"))

        # Truncate very long files to avoid pathological analysis time.
        truncated = False
        if max_lines > 0:
            lines = content.splitlines()
            if len(lines) > max_lines:
                content = "\n".join(lines[:max_lines])
                truncated = True
                lines = lines[:max_lines]
        else:
            lines = content.splitlines()

        # Quick pre-filter: single-pass scan for broad crypto keywords.
        # ~44% of files in large C repos have zero crypto content and can be
        # skipped in ~0.01ms vs ~12ms for full analysis.
        has_crypto = bool(_CRYPTO_QUICK_FILTER.search(content))

        return _FileContext(
            file_path=file_path,
            language=language,
            content=content,
            lines=lines,
            line_count=len(lines),
            byte_size=byte_size,
            has_crypto=has_crypto,
            truncated=truncated,
        )

    def _analyze_file(
        self,
        file_path: Path,
        language: Language,
        analyzer: LanguageAnalyzer,
        root: Path,
        max_bytes: int,
        max_lines: int,
    ) -> _FileResult:
        """
        Analyze a single file. Designed to be called from a thread pool worker.

        Builds a FileContext (one read per file), applies the quick pre-filter,
        then dispatches to the appropriate language analyzer.

        Returns a _FileResult — never raises. All exceptions are captured and
        surfaced via _FileResult.analysis_error so one bad file cannot cancel
        sibling futures.
        """
        try:
            ctx = self._build_file_context(file_path, language, max_bytes, max_lines)

            if ctx.read_error:
                return _FileResult(
                    file_path=file_path, findings=[], read_error=ctx.read_error,
                    analysis_error=None,
                )

            if not ctx.content:
                return _FileResult(
                    file_path=file_path, findings=[], read_error=None,
                    analysis_error=None, was_skipped=True,
                    bytes_read=ctx.byte_size, lines_analyzed=0,
                )

            # Files with no crypto signals are skipped without running analyzers.
            if not ctx.has_crypto:
                return _FileResult(
                    file_path=file_path, findings=[], read_error=None,
                    analysis_error=None, was_skipped=True,
                    bytes_read=ctx.byte_size, lines_analyzed=ctx.line_count,
                )

            findings = analyzer.analyze(file_path, ctx.content)

            # Make path relative to scan root for cleaner reporting
            rel_path = self._make_relative(file_path, root)
            for finding in findings:
                finding.location.file_path = rel_path

            return _FileResult(
                file_path=file_path, findings=findings, read_error=None,
                analysis_error=None,
                bytes_read=ctx.byte_size, lines_analyzed=ctx.line_count,
            )

        except Exception as exc:  # noqa: BLE001 — per-file isolation
            return _FileResult(
                file_path=file_path,
                findings=[],
                read_error=None,
                analysis_error=f"{type(exc).__name__}: {exc}",
            )

    def _execute_scan(self, target: ScanTarget, result: ScanResult) -> None:
        """
        Execute the full adaptive repository scanning pipeline.

        Steps:
          1. Traverse repository and classify files by language.
          2. Rank by crypto-relevance, apply file cap.
          3. Set deadline from scan_time_budget_seconds (if configured).
          4. Submit all files to ThreadPoolExecutor for parallel analysis.
          5. Collect results; stop submitting new work when deadline is reached.
          6. Mark scan PARTIAL if deadline was hit before all files were processed.
          7. Update statistics from aggregated results.
        """
        root = Path(target.path)
        options = target.options
        traversal = RepositoryTraversal(options)

        # --- Stage timing -------------------------------------------------
        t_start = time.monotonic()

        # Step 1: Traverse and classify
        files_by_language = traversal.collect_files(root, result.statistics)
        t_traversal_done = time.monotonic()
        result.statistics.stage_durations["traversal"] = t_traversal_done - t_start

        if not files_by_language:
            result.warnings.append(
                f"No analyzable source files found in: {target.path}. "
                "Check that the path contains source code and exclusion patterns are appropriate."
            )
            return

        # Step 2: Build work list — (file_path, language, analyzer) tuples.
        # Submitting all files to a single pool (not per-language) maximizes parallelism.
        work_items: list[tuple[Path, Language, LanguageAnalyzer]] = []
        skipped_no_analyzer: dict[Language, int] = {}

        for language, file_paths in files_by_language.items():
            analyzer = self._analyzer_instances.get(language)
            if analyzer is None:
                self._logger.debug(
                    "No analyzer for language %s — skipping %d files",
                    language.value, len(file_paths)
                )
                skipped_no_analyzer[language] = len(file_paths)
                result.statistics.files_skipped += len(file_paths)
                continue
            for fp in file_paths:
                work_items.append((fp, language, analyzer))

        # Step 2b: Rank by crypto-relevance then apply file cap.
        # Ensures the most crypto-relevant files are ALWAYS analyzed first,
        # so that a cap only drops low-relevance files (utility code, test infra).
        max_files = options.max_files_per_scan
        if len(work_items) > 0:
            work_items = _rank_by_crypto_relevance(work_items)
            if max_files > 0 and len(work_items) > max_files:
                dropped = len(work_items) - max_files
                result.warnings.append(
                    f"Repository has {len(work_items)} analyzable files — capped at {max_files} "
                    f"({dropped} lower-priority files skipped). Files ranked by crypto-relevance "
                    f"so the most important files are always covered. "
                    f"Set max_files_per_scan=0 in ScanOptions to disable this cap."
                )
                result.statistics.files_skipped += dropped
                work_items = work_items[:max_files]

        total_file_count = len(work_items)
        self._logger.info(
            "Dispatching %d file(s) to %d parallel workers | budget=%ss",
            total_file_count, _MAX_WORKERS,
            options.scan_time_budget_seconds or "unlimited",
        )

        # Step 3: Determine deadline (None = unlimited)
        deadline: Optional[float] = None
        budget_seconds = options.scan_time_budget_seconds
        if budget_seconds and budget_seconds > 0:
            # Budget starts from the beginning of the scan (t_start),
            # not from when we begin submitting futures.
            deadline = t_start + budget_seconds

        # Step 4: Parallel analysis via ThreadPoolExecutor
        total_files_scanned = 0
        total_bytes_read = 0
        total_lines_analyzed = 0
        findings_by_method: dict[str, int] = {}
        findings_by_category: dict[str, int] = {}

        max_bytes = options.max_file_size_bytes if options.max_file_size_bytes > 0 else 5 * 1024 * 1024
        max_lines = options.max_lines_per_file

        # Track futures that were submitted but not yet processed
        submitted_futures: dict[Future[_FileResult], Path] = {}
        pending_paths: list[tuple[Path, Language, LanguageAnalyzer]] = list(work_items)
        deadline_hit = False

        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            # Submit all work items up front (the pool queues internally)
            future_to_path: dict[Future[_FileResult], Path] = {
                pool.submit(self._analyze_file, fp, lang, analyzer, root, max_bytes, max_lines): fp
                for fp, lang, analyzer in work_items
            }

            for future in as_completed(future_to_path):
                # Check deadline before processing each completed future
                if deadline is not None and time.monotonic() > deadline:
                    deadline_hit = True
                    # Cancel all futures that haven't started yet
                    cancelled_count = 0
                    for f, path in future_to_path.items():
                        if not f.done():
                            f.cancel()
                            cancelled_count += 1
                    if cancelled_count > 0:
                        result.statistics.files_skipped += cancelled_count
                        self._logger.info(
                            "Time budget %.1fs exceeded — cancelled %d pending futures",
                            budget_seconds, cancelled_count,
                        )
                    break

                file_path = future_to_path[future]
                try:
                    file_result = future.result()
                except Exception as exc:  # noqa: BLE001 — should never happen (worker catches)
                    error_msg = f"Unexpected worker error for {file_path}: {type(exc).__name__}: {exc}"
                    result.errors.append(error_msg)
                    self._logger.warning(error_msg)
                    result.statistics.files_errored += 1
                    continue

                if file_result.read_error:
                    result.warnings.append(f"Could not read {file_path}: {file_result.read_error}")
                    result.statistics.files_errored += 1
                    continue

                if file_result.analysis_error:
                    error_msg = f"Error analyzing {file_path}: {file_result.analysis_error}"
                    result.errors.append(error_msg)
                    self._logger.warning(error_msg)
                    result.statistics.files_errored += 1
                    continue

                # Accumulate telemetry regardless of whether findings were produced
                total_bytes_read += file_result.bytes_read
                total_lines_analyzed += file_result.lines_analyzed

                if file_result.was_skipped:
                    result.statistics.files_skipped += 1
                    continue

                # Accumulate statistics from this file's findings
                for finding in file_result.findings:
                    method_key = finding.discovery_method.value
                    findings_by_method[method_key] = findings_by_method.get(method_key, 0) + 1
                    cat_key = finding.artifact_category.value
                    findings_by_category[cat_key] = findings_by_category.get(cat_key, 0) + 1

                result.findings.extend(file_result.findings)
                total_files_scanned += 1

                if options.progress_callback and (total_files_scanned % 5 == 0 or total_files_scanned == total_file_count):
                    try:
                        options.progress_callback(total_files_scanned, result.findings)
                    except Exception:
                        pass

        if options.progress_callback:
            try:
                options.progress_callback(total_files_scanned, result.findings)
            except Exception:
                pass

        t_analysis_done = time.monotonic()
        result.statistics.stage_durations["analysis"] = t_analysis_done - t_traversal_done
        result.statistics.stage_durations["total_discovery"] = t_analysis_done - t_start

        # Step 5: Update statistics
        result.statistics.files_scanned = total_files_scanned
        result.statistics.findings_by_method = findings_by_method
        result.statistics.findings_by_category = findings_by_category
        result.statistics.bytes_read = total_bytes_read
        result.statistics.lines_analyzed = total_lines_analyzed

        # Step 6: Mark partial scan if deadline was hit
        if deadline_hit:
            result.statistics.is_partial = True
            result.statistics.partial_reason = (
                f"Large repository — QNetra prioritized cryptographically relevant source files "
                f"to keep the assessment within the {budget_seconds:.0f}s interactive scan budget. "
                f"Analyzed {total_files_scanned} files; additional files were deferred."
            )
            result.warnings.append(result.statistics.partial_reason)

        self._logger.info(
            "Repository scan complete | files_scanned=%d | findings=%d | "
            "bytes_read=%d | lines=%d | workers=%d | partial=%s | "
            "traversal=%.2fs | analysis=%.2fs",
            total_files_scanned,
            len(result.findings),
            total_bytes_read,
            total_lines_analyzed,
            _MAX_WORKERS,
            deadline_hit,
            result.statistics.stage_durations.get("traversal", 0),
            result.statistics.stage_durations.get("analysis", 0),
        )

    def _make_relative(self, file_path: Path, root: Path) -> str:
        """Make a file path relative to the scan root for cleaner finding locations."""
        try:
            return str(file_path.relative_to(root))
        except ValueError:
            return str(file_path)
