"""
QNetra Cryptographic Knowledge Registry — Known Cryptographic Libraries

Maps known cryptographic library names (as they appear in package managers,
import statements, and shared library names) to their canonical identifiers,
associated algorithms, and confidence hints.

This registry is used by:
  - RepositoryScanner (import analysis)
  - ContainerScanner (package metadata inspection)
  - BinaryScanner (shared library detection)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LibraryEntry:
    """A recognized cryptographic library."""
    canonical_name: str                        # Canonical display name
    package_aliases: tuple[str, ...]           # Package manager names (pip, npm, maven, etc.)
    import_aliases: tuple[str, ...]            # Import statement names in source code
    shared_lib_names: tuple[str, ...]          # .so / .dll names in binaries
    primary_algorithms: tuple[str, ...]        # Canonical algorithm names from crypto_algorithms.py
    ecosystem: str                             # "python", "javascript", "java", "c", "multi"
    base_confidence: float                     # Confidence for library-level detection alone
    notes: str = ""


LIBRARY_REGISTRY: list[LibraryEntry] = [

    # -----------------------------------------------------------------------
    # Python Libraries
    # -----------------------------------------------------------------------
    LibraryEntry(
        canonical_name="pycryptodome",
        package_aliases=("pycryptodome", "pycryptodomex", "crypto", "pycrypto"),
        import_aliases=("Crypto", "Cryptodome"),
        shared_lib_names=(),
        primary_algorithms=("RSA", "AES", "DES", "3DES", "ECDSA", "SHA-256", "HMAC"),
        ecosystem="python",
        base_confidence=0.75,
        notes="Comprehensive Python crypto library. PyCryptodome is the maintained fork of PyCrypto.",
    ),
    LibraryEntry(
        canonical_name="cryptography",
        package_aliases=("cryptography",),
        import_aliases=("cryptography",),
        shared_lib_names=(),
        primary_algorithms=("RSA", "AES", "ECDSA", "ECDH", "SHA-256", "SHA-512", "HMAC", "HKDF"),
        ecosystem="python",
        base_confidence=0.75,
        notes="The primary PyCA cryptography library. Used by TLS stacks and SSH.",
    ),
    LibraryEntry(
        canonical_name="hashlib",
        package_aliases=(),   # stdlib
        import_aliases=("hashlib",),
        shared_lib_names=(),
        primary_algorithms=("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA-3"),
        ecosystem="python",
        base_confidence=0.70,
        notes="Python standard library hashing module. Wraps OpenSSL.",
    ),
    LibraryEntry(
        canonical_name="ssl",
        package_aliases=(),   # stdlib
        import_aliases=("ssl",),
        shared_lib_names=(),
        primary_algorithms=("TLS", "AES", "RSA"),
        ecosystem="python",
        base_confidence=0.70,
        notes="Python standard TLS/SSL socket wrapper.",
    ),
    LibraryEntry(
        canonical_name="hmac",
        package_aliases=(),   # stdlib
        import_aliases=("hmac",),
        shared_lib_names=(),
        primary_algorithms=("HMAC",),
        ecosystem="python",
        base_confidence=0.70,
    ),
    LibraryEntry(
        canonical_name="bcrypt",
        package_aliases=("bcrypt",),
        import_aliases=("bcrypt",),
        shared_lib_names=(),
        primary_algorithms=("bcrypt",),
        ecosystem="python",
        base_confidence=0.80,
    ),
    LibraryEntry(
        canonical_name="argon2-cffi",
        package_aliases=("argon2-cffi", "argon2"),
        import_aliases=("argon2",),
        shared_lib_names=(),
        primary_algorithms=("Argon2",),
        ecosystem="python",
        base_confidence=0.80,
    ),
    LibraryEntry(
        canonical_name="paramiko",
        package_aliases=("paramiko",),
        import_aliases=("paramiko",),
        shared_lib_names=(),
        primary_algorithms=("RSA", "ECDSA", "AES"),
        ecosystem="python",
        base_confidence=0.70,
        notes="SSH implementation — uses RSA/ECDSA for host keys.",
    ),

    # -----------------------------------------------------------------------
    # JavaScript / Node.js Libraries
    # -----------------------------------------------------------------------
    LibraryEntry(
        canonical_name="node:crypto",
        package_aliases=(),   # built-in
        import_aliases=("crypto", "node:crypto"),
        shared_lib_names=(),
        primary_algorithms=("AES", "RSA", "ECDSA", "SHA-256", "HMAC"),
        ecosystem="javascript",
        base_confidence=0.72,
        notes="Node.js built-in crypto module wrapping OpenSSL.",
    ),
    LibraryEntry(
        canonical_name="crypto-js",
        package_aliases=("crypto-js",),
        import_aliases=("crypto-js", "CryptoJS"),
        shared_lib_names=(),
        primary_algorithms=("AES", "MD5", "SHA-256", "HMAC"),
        ecosystem="javascript",
        base_confidence=0.75,
    ),
    LibraryEntry(
        canonical_name="jsonwebtoken",
        package_aliases=("jsonwebtoken",),
        import_aliases=("jsonwebtoken", "jwt"),
        shared_lib_names=(),
        primary_algorithms=("RSA", "ECDSA", "HMAC"),
        ecosystem="javascript",
        base_confidence=0.72,
        notes="JWT library — typically signs with HS256 (HMAC-SHA256) or RS256 (RSA).",
    ),
    LibraryEntry(
        canonical_name="node-forge",
        package_aliases=("node-forge",),
        import_aliases=("node-forge", "forge"),
        shared_lib_names=(),
        primary_algorithms=("RSA", "AES", "SHA-256", "HMAC"),
        ecosystem="javascript",
        base_confidence=0.75,
    ),
    LibraryEntry(
        canonical_name="bcryptjs",
        package_aliases=("bcryptjs", "bcrypt"),
        import_aliases=("bcryptjs", "bcrypt"),
        shared_lib_names=(),
        primary_algorithms=("bcrypt",),
        ecosystem="javascript",
        base_confidence=0.78,
    ),
    LibraryEntry(
        canonical_name="jose",
        package_aliases=("jose", "node-jose"),
        import_aliases=("jose",),
        shared_lib_names=(),
        primary_algorithms=("RSA", "ECDSA", "AES"),
        ecosystem="javascript",
        base_confidence=0.70,
        notes="JavaScript JOSE (JWS/JWE/JWK) implementation.",
    ),

    # -----------------------------------------------------------------------
    # Java Libraries
    # -----------------------------------------------------------------------
    LibraryEntry(
        canonical_name="javax.crypto",
        package_aliases=(),   # stdlib
        import_aliases=("javax.crypto",),
        shared_lib_names=(),
        primary_algorithms=("AES", "DES", "3DES", "RSA", "HMAC"),
        ecosystem="java",
        base_confidence=0.72,
        notes="Java Cryptography Architecture (JCA) standard library.",
    ),
    LibraryEntry(
        canonical_name="java.security",
        package_aliases=(),   # stdlib
        import_aliases=("java.security",),
        shared_lib_names=(),
        primary_algorithms=("RSA", "DSA", "ECDSA", "SHA-256"),
        ecosystem="java",
        base_confidence=0.72,
    ),
    LibraryEntry(
        canonical_name="BouncyCastle",
        package_aliases=("bcprov-jdk15on", "bcprov-jdk18on", "bouncycastle",
                         "org.bouncycastle"),
        import_aliases=("org.bouncycastle",),
        shared_lib_names=("bcprov-jdk15on.jar", "bcprov-jdk18on.jar"),
        primary_algorithms=("RSA", "AES", "ECDSA", "ECDH", "SHA-256"),
        ecosystem="java",
        base_confidence=0.80,
    ),

    # -----------------------------------------------------------------------
    # C / C++ Libraries
    # -----------------------------------------------------------------------
    LibraryEntry(
        canonical_name="OpenSSL",
        package_aliases=("openssl", "libssl-dev", "openssl-devel"),
        import_aliases=("openssl/", "openssl/evp.h", "openssl/rsa.h",
                        "openssl/aes.h", "openssl/sha.h", "openssl/ssl.h"),
        shared_lib_names=("libssl.so", "libssl.so.1.1", "libssl.so.3",
                          "libcrypto.so", "libcrypto.so.1.1", "libcrypto.so.3",
                          "libssl-1_1-x64.dll", "libcrypto-1_1-x64.dll",
                          "ssleay32.dll", "libeay32.dll"),
        primary_algorithms=("RSA", "AES", "ECDSA", "ECDH", "SHA-256", "SHA-512",
                            "DES", "3DES", "TLS"),
        ecosystem="c",
        base_confidence=0.85,
        notes="The de facto standard TLS/crypto library used by most C/C++ applications.",
    ),
    LibraryEntry(
        canonical_name="libsodium",
        package_aliases=("libsodium", "libsodium-dev"),
        import_aliases=("sodium.h", "sodium/"),
        shared_lib_names=("libsodium.so", "libsodium.so.23", "libsodium.dll",
                          "libsodium-23.dll"),
        primary_algorithms=("ED25519", "ECDH", "ChaCha20", "AES"),
        ecosystem="c",
        base_confidence=0.85,
        notes="High-level, easy-to-use crypto library. Uses modern curve25519/Ed25519.",
    ),
    LibraryEntry(
        canonical_name="mbedTLS",
        package_aliases=("mbedtls", "libmbedtls-dev"),
        import_aliases=("mbedtls/", "mbedtls/aes.h", "mbedtls/rsa.h"),
        shared_lib_names=("libmbedtls.so", "libmbedcrypto.so", "libmbedx509.so",
                          "mbedTLS.dll"),
        primary_algorithms=("RSA", "AES", "ECDSA", "ECDH", "SHA-256", "TLS"),
        ecosystem="c",
        base_confidence=0.83,
        notes="Lightweight TLS/crypto library for embedded systems.",
    ),
]

# Build lookup indices
_PACKAGE_ALIAS_INDEX: dict[str, LibraryEntry] = {}
_IMPORT_ALIAS_INDEX: dict[str, LibraryEntry] = {}
_SHARED_LIB_INDEX: dict[str, LibraryEntry] = {}

for _entry in LIBRARY_REGISTRY:
    for _alias in _entry.package_aliases:
        _PACKAGE_ALIAS_INDEX[_alias.lower()] = _entry
    for _alias in _entry.import_aliases:
        _IMPORT_ALIAS_INDEX[_alias.lower()] = _entry
    for _lib in _entry.shared_lib_names:
        _SHARED_LIB_INDEX[_lib.lower()] = _entry


def find_library_by_package(package_name: str) -> LibraryEntry | None:
    return _PACKAGE_ALIAS_INDEX.get(package_name.lower().strip())


def _matches_import_alias(name: str, alias: str) -> bool:
    """Check if import name matches alias with word/path boundaries."""
    if name == alias:
        return True
    if alias.endswith("/"):
        return name.startswith(alias)
    if name.startswith(alias):
        rest = name[len(alias):]
        if rest.startswith(".") or rest.startswith("/"):
            return True
    return False


def find_library_by_import(import_name: str) -> LibraryEntry | None:
    """Match import statement to a library. Supports boundary-aware prefix matching for submodules."""
    name = import_name.lower().strip()
    if name in _IMPORT_ALIAS_INDEX:
        return _IMPORT_ALIAS_INDEX[name]
    # Try boundary-aware prefix matching, sorted by alias length descending for specificity
    for alias, entry in sorted(_IMPORT_ALIAS_INDEX.items(), key=lambda x: len(x[0]), reverse=True):
        if _matches_import_alias(name, alias):
            return entry
    return None


def find_library_by_shared_lib(lib_name: str) -> LibraryEntry | None:
    """Match a shared library filename to a library entry."""
    name = lib_name.lower().strip()
    if name in _SHARED_LIB_INDEX:
        return _SHARED_LIB_INDEX[name]
    # Partial match for versioned libs (e.g. "libssl.so.1.1.1k")
    for lib, entry in _SHARED_LIB_INDEX.items():
        if name.startswith(lib.split(".so")[0]):
            return entry
    return None
