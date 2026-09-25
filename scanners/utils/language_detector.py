"""
QNetra Shared Utilities — Language Detection

Detects the programming language of a source file based on file extension,
with optional content-based validation to avoid misclassifying non-source files.

The Repository Scanner uses this to route files to the correct language analyzer.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path


class Language(str, Enum):
    """Supported programming languages for source code analysis."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    GO = "go"                      # Detected but not deeply analyzed in MVP
    RUST = "rust"                  # Detected but not deeply analyzed in MVP
    MANIFEST = "manifest"          # Package manifests (requirements.txt, package.json, etc.)
    UNKNOWN = "unknown"
    BINARY = "binary"              # Compiled / non-text files


# Extension to language mapping
_EXTENSION_MAP: dict[str, Language] = {
    # Python
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".pyx": Language.PYTHON,

    # JavaScript / TypeScript
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,

    # Java
    ".java": Language.JAVA,
    ".kt": Language.JAVA,          # Kotlin — Java ecosystem, similar crypto APIs

    # C / C++
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".hxx": Language.CPP,

    # Go
    ".go": Language.GO,

    # Rust
    ".rs": Language.RUST,

    # Manifests (for source scanner import detection pass)
    ".txt": Language.MANIFEST,     # requirements.txt — checked by filename below
    ".json": Language.MANIFEST,    # package.json, tsconfig, etc.
    ".xml": Language.MANIFEST,     # pom.xml
    ".toml": Language.MANIFEST,    # Cargo.toml, pyproject.toml
    ".gradle": Language.MANIFEST,

    # Known binary extensions
    ".so": Language.BINARY,
    ".dll": Language.BINARY,
    ".exe": Language.BINARY,
    ".o": Language.BINARY,
    ".a": Language.BINARY,
    ".lib": Language.BINARY,
    ".dylib": Language.BINARY,
    ".class": Language.BINARY,
    ".pyc": Language.BINARY,
    ".pyd": Language.BINARY,
    ".jar": Language.BINARY,
    ".war": Language.BINARY,
    ".wasm": Language.BINARY,
}

# Manifest filenames that override extension-based detection
_MANIFEST_FILENAMES: set[str] = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
}

# Binary magic bytes (first 4 bytes) for definitive binary detection
_BINARY_MAGIC: set[bytes] = {
    b"\x7fELF",        # ELF
    b"MZ\x90\x00",    # PE (common)
    b"MZ",             # PE variant
    b"\xcf\xfa\xed",  # Mach-O
    b"\xce\xfa\xed",  # Mach-O BE
    b"PK\x03\x04",    # ZIP (JAR, APK, DOCX, etc.)
    b"\x7fJAR",       # Unlikely but
    b"\xca\xfe\xba\xbe",  # Java class file (also Mach-O fat binary)
    b"!<arch>",       # Static library (.a)
}


# Extensions that unambiguously identify source code — skip binary magic check.
# Magic check is only needed for ambiguous extensions (no extension, .dat, .bin, etc.)
_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    ext for ext, lang in _EXTENSION_MAP.items()
    if lang not in (Language.BINARY, Language.MANIFEST, Language.UNKNOWN)
)


def detect_language(path: Path) -> Language:
    """
    Determine the programming language of a file.

    Detection order:
      1. Manifest filename check (fast set lookup — catches requirements.txt, etc.)
      2. Extension-based detection for unambiguous source extensions (no I/O needed)
      3. Binary magic bytes check ONLY for ambiguous/unknown extensions
      4. Fallback → Language.UNKNOWN

    Note: Steps 1-2 cover >99% of repository files without any filesystem I/O.
    Step 3 is reserved for extensionless files or extensions not in the map.

    Args:
        path: File path to classify.

    Returns:
        Language enum value.
    """
    # Fast path: manifest filename check (before extension — catches "requirements.txt")
    if path.name in _MANIFEST_FILENAMES:
        return Language.MANIFEST

    # Fast path: known source extension — no I/O needed
    suffix = path.suffix.lower()
    if suffix in _SOURCE_EXTENSIONS:
        return _EXTENSION_MAP[suffix]

    # Fast path: known binary extension — no I/O needed
    if suffix in _EXTENSION_MAP and _EXTENSION_MAP[suffix] == Language.BINARY:
        return Language.BINARY

    # Fast path: manifest extension with non-manifest filename (e.g. .txt that isn't requirements.txt)
    if suffix == ".txt":
        return Language.UNKNOWN

    # Slow path: check binary magic bytes only for ambiguous/unknown extensions
    # (extensionless files, .dat, .bin, uncommon extensions not in the map)
    if path.is_file():
        try:
            with open(path, "rb") as fh:
                magic = fh.read(8)
            for magic_prefix in _BINARY_MAGIC:
                if magic.startswith(magic_prefix):
                    return Language.BINARY
        except (OSError, PermissionError):
            pass

    # Extension-based detection for remaining known extensions
    if suffix in _EXTENSION_MAP:
        return _EXTENSION_MAP[suffix]

    return Language.UNKNOWN


def is_source_language(language: Language) -> bool:
    """Return True if this language has a corresponding source code analyzer."""
    return language in (Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT,
                        Language.JAVA, Language.C, Language.CPP)


def is_supported_for_ast(language: Language) -> bool:
    """Return True if AST analysis is available for this language in Phase 1."""
    return language in (Language.PYTHON,)


def normalize_language(language: Language) -> str:
    """Return the canonical string name used in API registry lookups."""
    if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return "javascript"
    if language in (Language.C, Language.CPP):
        return "cpp"
    return language.value
