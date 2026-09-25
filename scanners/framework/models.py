"""
QNetra Discovery Framework — Core Data Models

Defines the canonical data contracts for the Discovery Layer:
  - ScanTarget: What is being scanned (path, type, options)
  - RawFinding: Evidence-rich cryptographic discovery result (extended from v1.0.0-draft)
  - ScanResult: Complete output of one scanner execution including statistics
  - Supporting enumerations and value types

IMPORTANT: These models extend the RawFinding contract originally specified in
docs/06_API_AND_DATA_CONTRACTS.md v1.0.0-draft. The extension adds fields required
by the Discovery Layer (discovery_method, confidence_score, scanner identification,
binary-specific fields, container context). See ADR DEC-008 for rationale.

All fields are strongly typed via Pydantic v2 for schema validation.
Downstream normalization (core/normalization) consumes these models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TargetType(str, Enum):
    """Classification of what the scanner is inspecting."""
    REPOSITORY = "REPOSITORY"          # Source code directory / git repository
    CONTAINER_FS = "CONTAINER_FS"      # Extracted container filesystem directory
    BINARY = "BINARY"                  # Single compiled binary (ELF / PE / Mach-O)
    AUTO = "AUTO"                      # Auto-detect from target path characteristics


class ScanStatus(str, Enum):
    """Lifecycle status of a scan execution."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"            # All files processed, findings collected
    PARTIAL = "PARTIAL"                # Completed with some errors; findings still valid
    FAILED = "FAILED"                  # Fatal failure; findings unreliable


class DiscoveryMethod(str, Enum):
    """How a cryptographic indicator was detected."""
    AST = "AST"                        # Abstract Syntax Tree parse (Python, JS)
    IMPORT_ANALYSIS = "IMPORT_ANALYSIS"     # Library import / module declaration detected
    API_CALL = "API_CALL"              # Known cryptographic API function call detected
    REGEX = "REGEX"                    # Regular expression pattern match in source text
    STRING_ANALYSIS = "STRING_ANALYSIS"     # String extraction from binary or text
    SYMBOL_INSPECTION = "SYMBOL_INSPECTION" # Binary symbol table (import/export table)
    LIBRARY_DETECTION = "LIBRARY_DETECTION" # Shared library / .so / .dll linkage detected
    PACKAGE_INSPECTION = "PACKAGE_INSPECTION"  # Package manager metadata (dpkg, pip, npm)
    MANIFEST_ANALYSIS = "MANIFEST_ANALYSIS"    # Dependency manifest (requirements.txt, etc.)


class ArtifactCategory(str, Enum):
    """High-level cryptographic category of a discovered finding."""
    ASYMMETRIC_PKC = "ASYMMETRIC_PKC"   # RSA, DSA, ECC (Shor-vulnerable)
    SYMMETRIC_CIPHER = "SYMMETRIC_CIPHER"  # AES, DES, 3DES, ChaCha20
    HASH_FUNCTION = "HASH_FUNCTION"     # SHA-1, SHA-256, MD5
    KDF = "KDF"                         # PBKDF2, HKDF, scrypt, bcrypt
    MAC = "MAC"                         # HMAC, Poly1305, CMAC
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"  # ECDSA, RSA-PSS, Ed25519
    KEY_EXCHANGE = "KEY_EXCHANGE"       # DH, ECDH
    PROTOCOL = "PROTOCOL"              # TLS, SSL version references
    LIBRARY = "LIBRARY"                # Cryptographic library detected (not specific algorithm)
    CERTIFICATE = "CERTIFICATE"        # X.509, PEM certificate material
    KEY_MATERIAL = "KEY_MATERIAL"      # Private/public key data, hardcoded secrets
    RANDOM = "RANDOM"                  # PRNG / CSPRNG usage
    UNKNOWN = "UNKNOWN"                # Could not categorize with available evidence


class ConfidenceLevel(str, Enum):
    """Descriptive confidence tier derived from numeric score (for compatibility)."""
    VERY_HIGH = "VERY_HIGH"    # 0.85 – 1.00
    HIGH = "HIGH"              # 0.70 – 0.84
    MEDIUM = "MEDIUM"          # 0.45 – 0.69
    LOW = "LOW"                # 0.20 – 0.44
    VERY_LOW = "VERY_LOW"      # 0.00 – 0.19


class BinaryFormat(str, Enum):
    """Recognized binary executable formats."""
    ELF = "ELF"            # Linux/Unix ELF
    PE = "PE"              # Windows Portable Executable
    MACHO = "MACHO"        # macOS Mach-O (detection only, not fully parsed in MVP)
    ARCHIVE = "ARCHIVE"    # .a / .lib static library archive
    UNKNOWN = "UNKNOWN"    # Unrecognized format


# ---------------------------------------------------------------------------
# Sub-Models
# ---------------------------------------------------------------------------

class ScanOptions(BaseModel):
    """Configuration options for a scanner execution."""
    exclude_patterns: list[str] = Field(
        default=[
            # VCS and IDE metadata
            ".git", ".svn", ".hg", ".idea", ".vscode",
            # Dependency trees (largest single savings)
            "node_modules", "vendor", ".cargo",
            # Build output
            "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit",
            # Python env / cache
            "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache",
            ".pytest_cache", ".ruff_cache",
            # Java/Gradle/Maven build dirs
            ".gradle", ".mvn",
            # Test data / fixtures / docs (not source code)
            "fixtures", "test_data", "testdata", "docs", "doc",
            # Coverage / lock output
            "coverage", ".nyc_output",
            # Minified / bundled JS
            "*.min.js", "*.bundle.js", "*.min.css",
            # ── Large non-source directories in major OSS repos ──────────────
            # OpenSSL / BoringSSL / libssl
            "fuzz", "fuzz-corpus", "corpus",        # fuzz test corpora (100s of MB)
            "man", "man1", "man3", "man5", "man7",   # man-page directories
            "demos", "demo",                          # demo scripts (low crypto signal)
            "benchmarks", "benchmark", "perf",        # benchmark harnesses
            "generated", "auto-generated", "autogen",  # code-gen output
            "third_party", "third-party", "thirdparty", # bundled external deps
            "external", "extern",                     # external dep snapshots
            "Configurations",                         # OpenSSL build config database
            "ms",                                     # OpenSSL Windows MSVC scripts
            "VMS",                                    # OpenSSL VMS-specific code
            # CPython / Python repos
            "Misc",                                   # CPython misc docs/tools
            "PC",                                     # CPython Windows-only legacy
            "PCbuild",                                # CPython Windows MSVC build
            "Mac",                                    # CPython macOS legacy
            "Tools",                                  # CPython dev tools (non-crypto)
            # General test infrastructure
            "test", "tests", "testing",               # test dirs rarely have real crypto
            "__tests__", "spec", "specs",             # JS/TS test conventions
            "e2e", "integration",                     # integration/e2e test dirs
            # Documentation
            "examples", "example", "sample", "samples", # example code (low priority)
            "tutorial", "tutorials",
            "website", "site", "pages",
        ],
        description="Glob/directory names to exclude from traversal."
    )
    include_extensions: set[str] = Field(
        default={
            # Python
            ".py",
            # JavaScript / TypeScript
            ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            # Java / Kotlin / Scala
            ".java", ".kt", ".scala",
            # C / C++ / Objective-C
            ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".m",
            # C# / .NET
            ".cs",
            # Go
            ".go",
            # Rust
            ".rs",
            # Ruby / PHP
            ".rb", ".php",
            # Shell (for export/cipher config patterns)
            ".sh", ".bash",
            # Config / manifest files with crypto content
            ".yaml", ".yml", ".toml", ".conf", ".cfg", ".ini",
            ".json",  # package.json, tsconfig.json, etc.
            # Cert / key material
            ".pem", ".crt", ".cer", ".key",
        },
        description=(
            "Only traverse files with these extensions. "
            "Empty set means traverse all files (no extension filter). "
            "Dramatically reduces files visited in large repos containing docs, "
            "images, media, and generated assets."
        ),
    )
    max_file_size_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Skip files larger than this threshold to avoid memory issues."
    )
    max_lines_per_file: int = Field(
        default=2000,
        description=(
            "Truncate files to this many lines before analysis. "
            "Real cryptographic API usage is almost always in the first 2000 lines; "
            "files longer than this are typically generated test vectors, data tables, "
            "or auto-generated bindings with no actionable function calls. "
            "Set to 0 to disable."
        ),
    )
    max_files_per_scan: int = Field(
        default=1500,
        description=(
            "Maximum number of files to analyze in a single scan. "
            "Files are ranked by crypto-relevance (filename signals) before the cap "
            "is applied, ensuring the most important files are always covered. "
            "Prevents unbounded scan times on massive repositories (e.g. openssl with "
            "2,172 C files). Set to 0 to disable the cap (use with caution). "
            "The tradeoff: a 1500-file cap covers >99% of projects completely; for "
            "larger repos it covers a representative cryptographic cross-section."
        ),
    )
    max_string_length: int = Field(
        default=200,
        description="Maximum length of extracted code snippets stored in findings."
    )
    enable_ast: bool = Field(default=True, description="Enable AST-based analysis.")
    enable_regex: bool = Field(default=True, description="Enable regex pattern matching.")
    enable_import_analysis: bool = Field(default=True, description="Detect library imports.")
    follow_symlinks: bool = Field(default=False, description="Follow symbolic links during traversal.")
    use_gitignore: bool = Field(
        default=True,
        description="Parse and respect .gitignore rules during traversal to skip generated/vendored content."
    )
    # Time budget: if set, scanning will stop gracefully after this many seconds
    # (producing a partial scan) rather than running unbounded.
    # Set to 0 to disable (no deadline). Default: 55s (leaves 5s for downstream engines).
    scan_time_budget_seconds: float = Field(
        default=55.0,
        description=(
            "Maximum seconds for the discovery/analysis stage. "
            "When exceeded the scan terminates gracefully as PARTIAL with "
            "findings collected so far. Set to 0 to disable."
        ),
    )
    model_config = ConfigDict(arbitrary_types_allowed=True)

    progress_callback: Optional[Any] = Field(
        default=None,
        description="Optional callable(scanned_count: int, findings: list[RawFinding]) called during file analysis for live progress."
    )


class FileLocation(BaseModel):
    """Precise location of a finding within a file or binary."""
    file_path: str = Field(description="Path relative to scan root, or absolute for binaries.")
    start_line: Optional[int] = Field(default=None, description="1-indexed start line (source files).")
    end_line: Optional[int] = Field(default=None, description="1-indexed end line (source files).")
    byte_offset: Optional[int] = Field(default=None, description="Byte offset in binary files.")
    snippet: Optional[str] = Field(default=None, description="Code/data excerpt for audit evidence.")


class ContainerContext(BaseModel):
    """Container-specific metadata attached to findings from container scans."""
    image_reference: Optional[str] = Field(default=None, description="Image name:tag or digest.")
    layer_id: Optional[str] = Field(default=None, description="Container layer ID if applicable.")
    filesystem_path: str = Field(description="Path within the container filesystem.")


class ScanStatistics(BaseModel):
    """Quantitative scan execution statistics."""
    directories_visited: int = 0
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_errored: int = 0
    findings_count: int = 0
    findings_by_method: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    scan_duration_seconds: float = 0.0

    # Extended telemetry (Phase 5 — Adaptive Scanning Engine)
    bytes_read: int = Field(default=0, description="Total bytes read from source files during analysis.")
    lines_analyzed: int = Field(default=0, description="Total lines analyzed across all source files.")

    # Partial scan metadata
    is_partial: bool = Field(
        default=False,
        description="True when the scan was bounded by a time/file budget before all files were analyzed."
    )
    partial_reason: Optional[str] = Field(
        default=None,
        description="Human-readable explanation of why the scan is partial (e.g. 'Time budget exceeded')."
    )

    # Per-stage wall-clock durations (seconds) — internal engineering telemetry
    stage_durations: dict[str, float] = Field(
        default_factory=dict,
        description="Wall-clock seconds per pipeline stage (traversal, analysis, normalization, etc.)."
    )


# ---------------------------------------------------------------------------
# Primary Contracts
# ---------------------------------------------------------------------------

class ScanTarget(BaseModel):
    """
    Represents the asset being submitted for cryptographic discovery scanning.

    A ScanTarget is the entry point to the Discovery Layer. It encapsulates
    what to scan (path), how (options), and what type it is.

    Contract version: v1.1.0 (introduced Phase 1)
    Documented in: docs/06_API_AND_DATA_CONTRACTS.md
    """
    target_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this scan target."
    )
    path: str = Field(description="Absolute or relative path to the scan target.")
    target_type: TargetType = Field(
        default=TargetType.AUTO,
        description="Type of target. AUTO enables router-based auto-detection."
    )
    name: Optional[str] = Field(
        default=None,
        description="Human-readable name for the target (e.g. service or project name)."
    )
    description: Optional[str] = Field(default=None)
    options: ScanOptions = Field(default_factory=ScanOptions)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional additional metadata (e.g. commit hash, environment label)."
    )


class RawFinding(BaseModel):
    """
    Evidence-rich cryptographic discovery record emitted by a scanner.

    Represents a single piece of cryptographic evidence discovered during scanning.
    Every finding answers:
      WHAT was found?       → suspected_algorithm, artifact_category, raw_symbol
      WHERE was it found?   → location (file, line, byte offset, snippet)
      HOW was it detected?  → discovery_method, scanner_name
      WHY believe it's crypto? → confidence_score, confidence_rationale

    This is the v1.1.0 extension of the RawFinding schema from docs/06_API_AND_DATA_CONTRACTS.md.
    Breaking additions from v1.0.0-draft are backwards compatible (all new fields optional
    except those marked required). See ADR DEC-008 for schema change governance record.

    Producer: RepositoryScanner, ContainerScanner, BinaryScanner
    Consumer: core.normalization (next phase)
    """

    # --- Identification ---
    finding_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for this finding instance."
    )
    scanner_name: str = Field(
        description="Name of the scanner that produced this finding (e.g. 'RepositoryScanner')."
    )
    scanner_version: str = Field(
        default="1.0.0",
        description="Version of the scanner module."
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when this finding was recorded."
    )

    # --- Discovery Method ---
    discovery_method: DiscoveryMethod = Field(
        description="The technique used to detect this cryptographic indicator."
    )

    # Retained from v1.0.0-draft for backward compatibility
    scanner_type: Optional[str] = Field(
        default=None,
        description="Deprecated: use discovery_method. Retained for v1.0.0-draft compat."
    )

    # --- Cryptographic Discovery ---
    raw_symbol: str = Field(
        description="The unprocessed token, API call, string, or symbol exactly as found."
    )
    suspected_algorithm: Optional[str] = Field(
        default=None,
        description="Best-effort algorithm identification (e.g. 'RSA', 'AES', 'SHA-256')."
    )
    artifact_category: ArtifactCategory = Field(
        default=ArtifactCategory.UNKNOWN,
        description="High-level cryptographic category of this finding."
    )
    library_hint: Optional[str] = Field(
        default=None,
        description="The library/package associated with this finding (e.g. 'pycryptodome', 'OpenSSL')."
    )
    key_size_hint: Optional[int] = Field(
        default=None,
        description="Extracted key size in bits if determinable from literal arguments (e.g. 2048)."
    )
    mode_hint: Optional[str] = Field(
        default=None,
        description="Cipher mode if extractable (e.g. 'GCM', 'CBC', 'CTR')."
    )
    curve_hint: Optional[str] = Field(
        default=None,
        description="Elliptic curve name if extractable (e.g. 'secp256r1', 'Ed25519')."
    )

    # --- Evidence / Location ---
    location: FileLocation = Field(
        description="Precise location of the finding within the scanned asset."
    )

    # Retained from v1.0.0-draft
    source_file: Optional[str] = Field(
        default=None,
        description="Deprecated: use location.file_path. Retained for v1.0.0-draft compat."
    )
    line_number: Optional[int] = Field(
        default=None,
        description="Deprecated: use location.start_line. Retained for v1.0.0-draft compat."
    )
    raw_parameters: Optional[dict[str, Any]] = Field(
        default=None,
        description="Extracted literal parameters from API calls (e.g. {'key_size': 2048})."
    )
    code_snippet: Optional[str] = Field(
        default=None,
        description="Deprecated: use location.snippet. Retained for v1.0.0-draft compat."
    )

    # --- Binary-Specific Evidence ---
    symbol_name: Optional[str] = Field(
        default=None,
        description="Symbol name from binary import/export table (e.g. 'RSA_public_encrypt')."
    )
    binary_format: Optional[BinaryFormat] = Field(
        default=None,
        description="Format of the binary file (ELF, PE) if this is a binary finding."
    )

    # --- Container-Specific Context ---
    container_context: Optional[ContainerContext] = Field(
        default=None,
        description="Container image metadata. Present only for ContainerScanner findings."
    )

    # --- Confidence ---
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Numeric discovery confidence [0.0, 1.0]. Represents how certain QNetra is "
            "that this cryptographic artifact is genuinely present and being used. "
            "NOT a quantum risk score. NOT a security severity rating."
        )
    )
    confidence_rationale: str = Field(
        description="Human-readable explanation of why this confidence score was assigned."
    )

    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Derive a descriptive confidence tier from the numeric score."""
        if self.confidence_score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        elif self.confidence_score >= 0.70:
            return ConfidenceLevel.HIGH
        elif self.confidence_score >= 0.45:
            return ConfidenceLevel.MEDIUM
        elif self.confidence_score >= 0.20:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def to_v1_dict(self) -> dict[str, Any]:
        """
        Serialize to v1.0.0-draft compatible format for backward compatibility
        with consumers that have not yet upgraded to v1.1.0.
        """
        return {
            "finding_id": self.finding_id,
            "scanner_type": self.discovery_method.value.lower(),
            "source_file": self.location.file_path,
            "line_number": self.location.start_line,
            "end_line_number": self.location.end_line,
            "raw_symbol": self.raw_symbol,
            "raw_parameters": self.raw_parameters,
            "code_snippet": self.location.snippet,
            "confidence": self.confidence_level.value,
        }


class ScanResult(BaseModel):
    """
    Complete output of a single scanner execution against one ScanTarget.

    Encapsulates findings, statistics, errors, and warnings in a single envelope.
    This is NOT a CBOM. It is the raw output of the Discovery Layer before normalization.

    Contract version: v1.1.0 (introduced Phase 1)
    Documented in: docs/06_API_AND_DATA_CONTRACTS.md
    """
    scan_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for this scan execution."
    )
    target: ScanTarget = Field(description="The target that was scanned.")
    scanner_name: str = Field(description="Name of the scanner that executed.")
    scanner_version: str = Field(default="1.0.0")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    findings: list[RawFinding] = Field(default_factory=list)
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal issues encountered during scanning."
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Errors encountered. Presence does not necessarily invalidate findings."
    )
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_successful(self) -> bool:
        return self.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
